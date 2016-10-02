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
// which this object wraps
type WrappedWAL struct {
	*wal.WAL
	encoder    encoder
	getDecoder func(string) decoder
}

// ReadAll wraps the wal.WAL.ReadAll() function, but it first checks to see if the
// metadata indicates that the entries are encoded, and if so, decodes them.
func (w *WrappedWAL) ReadAll() ([]byte, raftpb.HardState, []raftpb.Entry, error) {
	metadata, state, ents, err := w.WAL.ReadAll()
	if err != nil {
		return metadata, state, ents, err
	}
	wrappedRecord := WrappedRecord{}
	unmarshalErr := wrappedRecord.Unmarshal(metadata) // nope, this wasn't marshalled as a WrappedRecord
	if unmarshalErr != nil {
		return metadata, state, ents, err
	}

	if wrappedRecord.Encoding == "" {
		return wrappedRecord.Wrapped, state, ents, nil
	}

	d := w.getDecoder(wrappedRecord.Encoding)
	if d == nil {
		return nil, raftpb.HardState{}, nil, fmt.Errorf("no decoder available for %s", wrappedRecord.Encoding)
	}

	for i, ent := range ents {
		entData, err := d.Decode(ent.Index, ent.Term, ent.Data)
		if err != nil {
			return nil, raftpb.HardState{}, nil, fmt.Errorf("unable to decode WAL: %s", err.Error())
		}
		ents[i].Data = entData
	}

	return wrappedRecord.Wrapped, state, ents, nil
}

// Save encodes the entry data (if an encoder is exists) before passing it onto the
// wrapped wal.WAL's Save function.
func (w *WrappedWAL) Save(st raftpb.HardState, ents []raftpb.Entry) error {
	writeEnts := ents
	if w.encoder != nil {
		writeEnts = make([]raftpb.Entry, 0)
		for _, ent := range ents {
			data, err := w.encoder.Encode(ent.Index, ent.Term, ent.Data)
			if err != nil {
				return fmt.Errorf("unable to encode entry data: %s", err.Error())
			}
			writeEnts = append(writeEnts, raftpb.Entry{
				Index: ent.Index,
				Term:  ent.Term,
				Type:  ent.Type,
				Data:  data,
			})
		}
	}
	return w.WAL.Save(st, writeEnts)
}
