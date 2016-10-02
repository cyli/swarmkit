package encryption

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/stretchr/testify/require"
)

// Generates a bunch of WAL test data
func makeWALData() ([]byte, []raftpb.Entry, walpb.Snapshot) {
	term := uint64(3)
	index := uint64(4)

	var entries []raftpb.Entry
	for i := index + 1; i < index+6; i++ {
		entries = append(entries, raftpb.Entry{
			Term:  term,
			Index: i,
			Data:  []byte(fmt.Sprintf("Entry %d", i)),
		})
	}

	return []byte("metadata"), entries, walpb.Snapshot{Index: index, Term: term}
}

func createWithRegularWAL(t *testing.T, metadata []byte, startSnap walpb.Snapshot, entries []raftpb.Entry) string {
	walDir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)

	ogWAL, err := wal.Create(walDir, metadata)
	require.NoError(t, err)

	require.NoError(t, ogWAL.SaveSnapshot(startSnap))
	require.NoError(t, ogWAL.Save(raftpb.HardState{}, entries))
	require.NoError(t, ogWAL.Close())

	return walDir
}

// When reading WAL, errors if no decoder is provided
func TestReadAllNoDecoder(t *testing.T) {
	metadata, entries, snapshot := makeWALData()
	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped, err := OpenWAL(tempdir, snapshot, nil, nil)
	require.NoError(t, err)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder")
}

// When reading WAL, if a decoder is available but any entry cannot be decoded,
// an error is returned
func TestReadAllEntryIncorrectlyEncoded(t *testing.T) {
	metadata, entries, snapshot := makeWALData()

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	// unable to decode because there is no cat at the end of the data
	wrapped, err := OpenWAL(tempdir, snapshot, nil, &meowCoder{})
	require.NoError(t, err)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode")
}

// If no encoder is provided, the data is saved cannot be saved
func TestSaveNoEncoder(t *testing.T) {
	metadata, entries, snapshot := makeWALData()

	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped, err := CreateWAL(tempdir, metadata, nil, nil)
	require.NoError(t, err)

	require.NoError(t, wrapped.SaveSnapshot(snapshot))
	err = wrapped.Save(raftpb.HardState{}, entries)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no encoder")

	require.NoError(t, wrapped.Close())

	// no entries are written at all
	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	defer ogWAL.Close()

	_, _, ents, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.Empty(t, ents)
}

// If an encoding is provided, and encoding fails, saving will fail
func TestSaveEncodingFails(t *testing.T) {
	metadata, entries, snapshot := makeWALData()

	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	// the first encoding is the metadata, so that should succeed - fail on one
	// of the entries, and not the first one
	coder := &meowCoder{encodeFailures: map[string]struct{}{
		fmt.Sprintf("%d_%d", snapshot.Index+3, snapshot.Term): {},
	}}
	wrapped, err := CreateWAL(tempdir, metadata, coder, nil)
	require.NoError(t, err)

	require.NoError(t, wrapped.SaveSnapshot(snapshot))
	err = wrapped.Save(raftpb.HardState{}, entries)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to encode")
	require.NoError(t, wrapped.Close())

	// no entries are written at all
	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	defer ogWAL.Close()

	_, _, ents, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.Empty(t, ents)
}

// A WAL can read what it wrote so long as it has a corresponding decoder
func TestSaveAndRead(t *testing.T) {
	coder := &meowCoder{}
	metadata, entries, snapshot := makeWALData()

	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped, err := CreateWAL(tempdir, metadata, coder, nil)
	require.NoError(t, err)

	require.NoError(t, wrapped.SaveSnapshot(snapshot))
	require.NoError(t, wrapped.Save(raftpb.HardState{}, entries))
	require.NoError(t, wrapped.Close())

	wrapped, err = OpenWAL(tempdir, snapshot, nil, coder)
	meta, state, ents, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.Equal(t, metadata, meta)
	require.Equal(t, entries, ents)
	require.NoError(t, wrapped.Close())

	// the regular WAL can't read the entries correctly, although it can get
	// the state and metadata just fine
	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	defer ogWAL.Close()

	metaOG, stateOG, entsOG, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.Equal(t, metaOG, meta)
	require.Equal(t, stateOG, state)
	require.NotEqual(t, entsOG, ents)
}

// If the underlying WAL returns an error when opening or creating, the error
// is propagated up.
func TestCreateOpenInvalidDirFails(t *testing.T) {
	_, err := CreateWAL("/not/existing/directory", []byte("metadata"), nil, nil)
	require.Error(t, err)

	_, err = OpenWAL("/not/existing/directory", walpb.Snapshot{}, nil, nil)
	require.Error(t, err)
}
