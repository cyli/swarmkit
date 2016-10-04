package encryption

import (
	"fmt"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/snap"
)

// This package wraps the github.com/coreos/etcd/snap package, and encodes
// the bytes of whatever snapshot is passed to it, and decodes the bytes of
// whatever snapshot it reads.

// Snapshotter is the interface presented by github.com/coreos/etcd/snap.Snapshotter
type Snapshotter interface {
	SaveSnap(snapshot raftpb.Snapshot) error
	Load() (*raftpb.Snapshot, error)
}

// Make sure WAL implements the same interface as wal.WAL
var _ Snapshotter = &WrappedSnap{}
var _ Snapshotter = &snap.Snapshotter{}

// WrappedSnap wraps a github.com/coreos/etcd/snap.Snapshotter, and handles
// encoding/decoding.
type WrappedSnap struct {
	*snap.Snapshotter
	encoder  encoder
	decoders map[string]decoder
}

// NewSnapshotter returns a new Snapshotter with the given encoders and decoders
func NewSnapshotter(dirpath string, e encoder, decoders []decoder) Snapshotter {
	mappedDecoders := make(map[string]decoder)
	for _, dec := range decoders {
		mappedDecoders[dec.ID()] = dec
	}

	return &WrappedSnap{
		Snapshotter: snap.New(dirpath),
		encoder:     e,
		decoders:    mappedDecoders,
	}
}

// SaveSnap encodes the snapshot data (if an encoder is exists) before passing it onto the
// wrapped snap.Snapshotter's SaveSnap function.
func (s *WrappedSnap) SaveSnap(snapshot raftpb.Snapshot) error {
	toWrite := snapshot
	if s.encoder != nil {
		var err error
		wrapped := WrappedRecord{
			Encoding: s.encoder.ID(),
		}
		wrapped.Data, err = s.encoder.Encode(snapshot.Metadata.Index, snapshot.Metadata.Term, snapshot.Data)
		wrapped.DataLen = int64(len(wrapped.Data))
		if err != nil {
			return fmt.Errorf("unable to encode entry data: %s", err.Error())
		}
		toWrite.Data, err = wrapped.Marshal()
		if err != nil {
			return err
		}
	}
	return s.Snapshotter.SaveSnap(toWrite)
}

// Load decodes the snapshot data (if a decoder is exists) after reading it using the
// wrapped snap.Snapshotter's Load function.
func (s *WrappedSnap) Load() (*raftpb.Snapshot, error) {
	snapshot, err := s.Snapshotter.Load()
	if err != nil {
		return nil, err
	}
	if err := decodeSnaphot(snapshot, s.decoders); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// ReadSnap reads the snapshot named by snapname using the given decoders and returns the snapshot.
func ReadSnap(snapname string, decoders []decoder) (*raftpb.Snapshot, error) {
	snapshot, err := snap.Read(snapname)
	if err != nil {
		return nil, err
	}

	mappedDecoders := make(map[string]decoder)
	for _, dec := range decoders {
		mappedDecoders[dec.ID()] = dec
	}

	if err := decodeSnaphot(snapshot, mappedDecoders); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func decodeSnaphot(snapshot *raftpb.Snapshot, decoders map[string]decoder) error {
	wrappedRecord := WrappedRecord{}
	err := wrappedRecord.Unmarshal(snapshot.Data) // nope, this wasn't marshalled as a WrappedRecord
	if err != nil {
		return nil
	}

	if wrappedRecord.Encoding == "" || wrappedRecord.DataLen != int64(len(wrappedRecord.Data)) {
		snapshot.Data = wrappedRecord.Data
		return nil
	}

	d, ok := decoders[wrappedRecord.Encoding]
	if !ok || d == nil {
		return fmt.Errorf("no decoder available for %s", wrappedRecord.Encoding)
	}

	snapshot.Data, err = d.Decode(snapshot.Metadata.Index, snapshot.Metadata.Term, wrappedRecord.Data)
	if err != nil {
		return fmt.Errorf("unable to decode snapshot: %s", err.Error())
	}

	return nil
}
