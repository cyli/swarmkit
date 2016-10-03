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
	encoder encoder
	decoder decoder
}

// NewSnapshotter returns a new Snapshotter with the given encoders and decoders
func NewSnapshotter(dirpath string, e encoder, d decoder) Snapshotter {
	return &WrappedSnap{
		Snapshotter: snap.New(dirpath),
		encoder:     e,
		decoder:     d,
	}
}

// SaveSnap encodes the snapshot data (if an encoder is exists) before passing it onto the
// wrapped snap.Snapshotter's SaveSnap function.
func (s *WrappedSnap) SaveSnap(snapshot raftpb.Snapshot) error {
	toWrite := snapshot
	if s.encoder == nil {
		return fmt.Errorf("no encoder available")
	}

	var err error
	toWrite.Data, err = s.encoder.Encode(snapshot.Metadata.Index, snapshot.Metadata.Term, snapshot.Data)
	if err != nil {
		return fmt.Errorf("unable to encode entry data: %s", err.Error())
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
	if err := decodeSnaphot(snapshot, s.decoder); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// ReadSnap reads the snapshot named by snapname using the given decoders and returns the snapshot.
func ReadSnap(snapname string, d decoder) (*raftpb.Snapshot, error) {
	snapshot, err := snap.Read(snapname)
	if err != nil {
		return nil, err
	}

	if err := decodeSnaphot(snapshot, d); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func decodeSnaphot(snapshot *raftpb.Snapshot, d decoder) error {
	if d == nil {
		return fmt.Errorf("no decoder available")
	}
	var err error
	snapshot.Data, err = d.Decode(snapshot.Metadata.Index, snapshot.Metadata.Term, snapshot.Data)
	if err != nil {
		return fmt.Errorf("unable to decode snapshot: %s", err.Error())
	}

	return nil
}
