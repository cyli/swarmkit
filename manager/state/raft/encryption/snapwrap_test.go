package encryption

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/snap"
	"github.com/stretchr/testify/require"
)

var fakeSnapshot = raftpb.Snapshot{
	Data: []byte("snapshotdata"),
	Metadata: raftpb.SnapshotMetadata{
		ConfState: raftpb.ConfState{Nodes: []uint64{3}},
		Index:     6,
		Term:      2,
	},
}

func getSnapshotFile(t *testing.T, tempdir string) string {
	var filepaths []string
	err := filepath.Walk(tempdir, func(path string, fi os.FileInfo, err error) error {
		require.NoError(t, err)
		if !fi.IsDir() {
			filepaths = append(filepaths, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, filepaths, 1)
	return filepaths[0]
}

// If there is no decoder for a snapshot, Load and Read fail
func TestSnapshotterLoadAndReadNoDecoder(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	ogSnap := snap.New(tempdir)
	require.NoError(t, ogSnap.SaveSnap(fakeSnapshot))

	wrapped := NewSnapshotter(tempdir, nil, nil)

	_, err = wrapped.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder available")

	_, err = ReadSnap(getSnapshotFile(t, tempdir), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder available")
}

// If decoding a snapshot fails, the error is propagated when Loading and Reading
func TestSnapshotterLoadAndReadDecodingFail(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	coder := &meowCoder{}

	// decoding will fail because the snapshot data doesn't end with a cat
	ogSnap := snap.New(tempdir)
	require.NoError(t, ogSnap.SaveSnap(fakeSnapshot))

	wrapped := NewSnapshotter(tempdir, nil, coder)

	_, err = wrapped.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode snapshot")

	_, err = ReadSnap(getSnapshotFile(t, tempdir), coder)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode snapshot")
}

// If no encoder is passed to Snapshotter, Save errors
func TestSnapshotterSavesSnapshotNoEncoding(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, nil, nil)
	err = wrapped.SaveSnap(fakeSnapshot)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no encoder")
}

// If an encoder is passed to Snapshotter, but encoding the data fails, the
// error is propagated up when Saving
func TestSnapshotterSavesSnapshotEncodingFails(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, &meowCoder{encodeFailures: map[string]struct{}{
		fmt.Sprintf("%d_%d", fakeSnapshot.Metadata.Index, fakeSnapshot.Metadata.Term): {},
	}}, nil)
	err = wrapped.SaveSnap(fakeSnapshot)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to encode")

	// nothing there to read
	ogSnap := snap.New(tempdir)
	_, err = ogSnap.Load()
	require.Error(t, err)
}

// Snapshotter can read what it wrote so long as it has the same decoder, and
// the snap.Snapshotter cannot read the same data
func TestSaveAndLoad(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	coder := &meowCoder{}
	wrapped := NewSnapshotter(tempdir, coder, coder)
	require.NoError(t, wrapped.SaveSnap(fakeSnapshot))
	readSnap, err := wrapped.Load()
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)

	ogSnap := snap.New(tempdir)
	readSnapOG, err := ogSnap.Load()
	require.NotEqual(t, readSnap, readSnapOG)
}

// Snapshotter, with a noop decoder, can read snapshots written by a regular snap.Snapshot
func TestSnapshotterLoadOrReadNoopDecoder(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	ogSnap := snap.New(tempdir)
	require.NoError(t, ogSnap.SaveSnap(fakeSnapshot))

	wrapped := NewSnapshotter(tempdir, nil, Noop)

	readSnap, err := wrapped.Load()
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)

	readSnap, err = ReadSnap(getSnapshotFile(t, tempdir), Noop)
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)
}

// If a noop encoder is passed to Snapshotter, the resulting snapshot can be
// read by the regular snap.Snapshotter
func TestSnapshotterSavesNoopEncoder(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, Noop, nil)
	require.NoError(t, wrapped.SaveSnap(fakeSnapshot))

	ogSnap := snap.New(tempdir)
	readSnap, err := ogSnap.Load()
	require.NoError(t, err)

	require.Equal(t, fakeSnapshot, *readSnap)
}
