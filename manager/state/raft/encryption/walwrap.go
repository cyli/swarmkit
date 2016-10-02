package encryption

import (
	"fmt"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
)

// This package wraps the github.com/coreos/etcd/wal package, and encodes
// the bytes of whatever entry is passed to it, and decodes the bytes of
// whatever entry it reads.

// WAL is the interface presented by github.com/coreos/etcd/wal.WAL
type WAL interface {
	ReadAll() ([]byte, raftpb.HardState, []raftpb.Entry, error)
	ReleaseLockTo(index uint64) error
	Close() error
	Save(st raftpb.HardState, ents []raftpb.Entry) error
	SaveSnapshot(e walpb.Snapshot) error
}

// Make sure WAL implements the same interface as wal.WAL
var _ WAL = &WrappedWAL{}
var _ WAL = &wal.WAL{}

// WrappedWAL wraps a github.com/coreos/etcd/wal.WAL, and handles encoding/decoding
type WrappedWAL struct {
	*wal.WAL
	encoder encoder
	decoder decoder
}

// ReadAll wraps the wal.WAL.ReadAll() function, but it decodes the entries if
// a decoder is available
func (w *WrappedWAL) ReadAll() ([]byte, raftpb.HardState, []raftpb.Entry, error) {
	metadata, state, ents, err := w.WAL.ReadAll()
	if err != nil {
		return nil, raftpb.HardState{}, nil, err
	}
	if w.decoder == nil {
		return nil, raftpb.HardState{}, nil, fmt.Errorf("no decoder available")
	}

	for i, ent := range ents {
		entData, err := w.decoder.Decode(ent.Index, ent.Term, ent.Data)
		if err != nil {
			return nil, raftpb.HardState{}, nil, fmt.Errorf("unable to decode WAL: %s", err.Error())
		}
		ents[i].Data = entData
	}

	return metadata, state, ents, nil
}

// Save encodes the entry data (if an encoder is exists) before passing it onto the
// wrapped wal.WAL's Save function.
func (w *WrappedWAL) Save(st raftpb.HardState, ents []raftpb.Entry) error {
	if w.encoder == nil {
		return fmt.Errorf("no encoder available")
	}

	writeEnts := make([]raftpb.Entry, len(ents))
	for i, ent := range ents {
		data, err := w.encoder.Encode(ent.Index, ent.Term, ent.Data)
		if err != nil {
			return fmt.Errorf("unable to encode entry data: %s", err.Error())
		}
		writeEnts[i] = raftpb.Entry{
			Index: ent.Index,
			Term:  ent.Term,
			Type:  ent.Type,
			Data:  data,
		}
	}
	return w.WAL.Save(st, writeEnts)
}

// CreateWAL returns a new WAL object with the given encoders and decoders.
func CreateWAL(dirpath string, metadata []byte, e encoder, d decoder) (WAL, error) {
	w, err := wal.Create(dirpath, metadata)
	if err != nil {
		return nil, err
	}

	return &WrappedWAL{
		WAL:     w,
		encoder: e,
		decoder: d,
	}, nil
}

// OpenWAL returns a new WAL object with the given encoders and decoders.
func OpenWAL(dirpath string, snap walpb.Snapshot, e encoder, d decoder) (WAL, error) {
	w, err := wal.Open(dirpath, snap)
	if err != nil {
		return nil, err
	}

	return &WrappedWAL{
		WAL:     w,
		encoder: e,
		decoder: d,
	}, nil
}
