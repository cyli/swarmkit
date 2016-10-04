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

// Snapshotter can read snapshots written by a regular snap.Snapshot
func TestSnapshotterLoadOrReadUnencodedSnapshot(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	ogSnap := snap.New(tempdir)
	require.NoError(t, ogSnap.SaveSnap(fakeSnapshot))

	decoders := []decoder{&meowCoder{}}
	wrapped := NewSnapshotter(tempdir, nil, decoders)

	readSnap, err := wrapped.Load()
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)

	readSnap, err = ReadSnap(getSnapshotFile(t, tempdir), decoders)
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)
}

// Snapshotter can read snapshots produced with an empty encoding
func TestSnapshotterLoadEmptyEncodingSnapshot(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	ogSnap := snap.New(tempdir)
	wr := WrappedRecord{
		Data:    fakeSnapshot.Data,
		DataLen: int64(len(fakeSnapshot.Data)),
	}
	wrData, err := wr.Marshal()
	require.NoError(t, err)

	emptyEncodingFakeData := fakeSnapshot
	emptyEncodingFakeData.Data = wrData

	require.NoError(t, ogSnap.SaveSnap(emptyEncodingFakeData))

	decoders := []decoder{&meowCoder{}}
	wrapped := NewSnapshotter(tempdir, nil, decoders)

	readSnap, err := wrapped.Load()
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)

	readSnap, err = ReadSnap(getSnapshotFile(t, tempdir), decoders)
	require.NoError(t, err)
	require.Equal(t, fakeSnapshot, *readSnap)
}

// If there is no decoder for a snapshot, decoding fails
func TestSnapshotterLoadNoDecoder(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	coder := &meowCoder{}

	ogSnap := snap.New(tempdir)
	wr := WrappedRecord{
		Data:     fakeSnapshot.Data,
		DataLen:  int64(len(fakeSnapshot.Data)),
		Encoding: coder.ID(),
	}
	wrData, err := wr.Marshal()
	require.NoError(t, err)

	emptyEncodingFakeData := fakeSnapshot
	emptyEncodingFakeData.Data = wrData

	require.NoError(t, ogSnap.SaveSnap(emptyEncodingFakeData))

	wrapped := NewSnapshotter(tempdir, nil, nil)

	_, err = wrapped.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder available")

	_, err = ReadSnap(getSnapshotFile(t, tempdir), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder available")
}

// If decoding a snapshot fails, the error is propagated
func TestSnapshotterLoadDecodingFail(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	coder := &meowCoder{}

	ogSnap := snap.New(tempdir)
	wr := WrappedRecord{
		Data:     fakeSnapshot.Data,
		DataLen:  int64(len(fakeSnapshot.Data)),
		Encoding: coder.ID(),
	}
	wrData, err := wr.Marshal()
	require.NoError(t, err)

	emptyEncodingFakeData := fakeSnapshot
	emptyEncodingFakeData.Data = wrData

	require.NoError(t, ogSnap.SaveSnap(emptyEncodingFakeData))

	decoders := []decoder{&meowCoder{}}
	wrapped := NewSnapshotter(tempdir, nil, decoders)

	_, err = wrapped.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode snapshot")

	_, err = ReadSnap(getSnapshotFile(t, tempdir), decoders)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode snapshot")
}

// If no encoder is passed to Snapshotter, the resulting snapshot can be
// read by the regular snap.Snapshotter
func TestSnapshotterSavesSnapshotNoEncoding(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, nil, nil)
	require.NoError(t, wrapped.SaveSnap(fakeSnapshot))

	ogSnap := snap.New(tempdir)
	readSnap, err := ogSnap.Load()
	require.NoError(t, err)

	require.Equal(t, fakeSnapshot, *readSnap)
}

// If an encoder is passed to Snapshotter, the resulting snapshot data (but not
// metadata or anything else) is encoded before being passed to the wrapped Snapshotter.
func TestSnapshotterSavesSnapshotWithEncoding(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, &meowCoder{}, nil)
	require.NoError(t, wrapped.SaveSnap(fakeSnapshot))

	ogSnap := snap.New(tempdir)
	readSnap, err := ogSnap.Load()
	require.NoError(t, err)

	require.Equal(t, fakeSnapshot.Metadata, readSnap.Metadata)
	require.NotEqual(t, fakeSnapshot.Data, readSnap.Data)
}

// If an encoder is passed to Snapshotter, but encoding the data fails, the
// error is propagated up
func TestSnapshotterSavesSnapshotEncodingFails(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "snapwrap")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped := NewSnapshotter(tempdir, &meowCoder{encodeFailures: map[string]struct{}{
		fmt.Sprintf("%d_%d", fakeSnapshot.Metadata.Index, fakeSnapshot.Metadata.Term): struct{}{},
	}}, nil)
	err = wrapped.SaveSnap(fakeSnapshot)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to encode")

	// nothing there to read
	ogSnap := snap.New(tempdir)
	_, err = ogSnap.Load()
	require.Error(t, err)
}

// Snapshotter can read what it wrote so long as it has the same decoder
func TestSaveAndLoad(t *testing.T) {
	coder := &meowCoder{}
	for _, e := range []encoder{nil, coder} {
		tempdir, err := ioutil.TempDir("", "waltests")
		require.NoError(t, err)
		defer os.RemoveAll(tempdir)

		wrapped := NewSnapshotter(tempdir, e, []decoder{coder})
		require.NoError(t, wrapped.SaveSnap(fakeSnapshot))
		readSnap, err := wrapped.Load()
		require.NoError(t, err)
		require.Equal(t, fakeSnapshot, *readSnap)
	}
}
