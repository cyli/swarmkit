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

// WAL can read entries that are not wrapped at all (written by the default wal.WAL)
func TestReadAllNoWrapping(t *testing.T) {
	metadata, entries, snapshot := makeWALData()
	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	meta, state, ents, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.NoError(t, ogWAL.Close())

	wrapped, err := OpenWAL(tempdir, snapshot, nil, []decoder{&meowCoder{}})
	require.NoError(t, err)
	metaW, stateW, entsW, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())

	require.Equal(t, meta, metaW)
	require.Equal(t, state, stateW)
	require.Equal(t, ents, entsW)

	require.Equal(t, metadata, metaW)
	require.Equal(t, entries, entsW)
}

// WAL can read entries are not wrapped, but not encoded
func TestReadAllWrappedNoEncoding(t *testing.T) {
	ogMeta, entries, snapshot := makeWALData()
	r := WrappedRecord{Data: ogMeta, DataLen: int64(len(ogMeta))}
	metadata, err := r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped, err := OpenWAL(tempdir, snapshot, nil, []decoder{&meowCoder{}})
	require.NoError(t, err)
	metaW, _, entsW, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())

	require.Equal(t, ogMeta, metaW)
	require.Equal(t, entries, entsW)
}

// When reading WAL, if no decoders are available for the encoding type, errors
func TestReadAllNoSupportedDecoder(t *testing.T) {
	metadata, entries, snapshot := makeWALData()
	r := WrappedRecord{
		Data:     metadata,
		DataLen:  int64(len(metadata)),
		Encoding: "no-decoder",
	}
	var err error
	metadata, err = r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped, err := OpenWAL(tempdir, snapshot, nil, []decoder{&meowCoder{}})
	require.NoError(t, err)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder")
}

// When reading WAL, if a decoder is available for the encoding type but any
// entry is incorrectly encoded, an error is returned
func TestReadAllEntryIncorrectlyEncoded(t *testing.T) {
	coder := &meowCoder{}
	metadata, entries, snapshot := makeWALData()

	// metadata is correctly encoded, but entries are not meow-encoded
	r := WrappedRecord{
		Data:     metadata,
		DataLen:  int64(len(metadata)),
		Encoding: coder.ID(),
	}
	var err error
	metadata, err = r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped, err := OpenWAL(tempdir, snapshot, nil, []decoder{&meowCoder{}})
	require.NoError(t, err)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode")
}

// If no encoding is provided, the data is saved without encryption at all
// such that it is readable by a regular WAL object.
func TestSaveWithoutEncoding(t *testing.T) {
	metadata, entries, snapshot := makeWALData()

	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	wrapped, err := CreateWAL(tempdir, metadata, nil, nil)
	require.NoError(t, err)

	require.NoError(t, wrapped.SaveSnapshot(snapshot))
	require.NoError(t, wrapped.Save(raftpb.HardState{}, entries))
	require.NoError(t, wrapped.Close())

	wrapped, err = OpenWAL(tempdir, snapshot, nil, nil)
	require.NoError(t, err)
	metaW, stateW, entsW, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())

	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	defer ogWAL.Close()

	meta, state, ents, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.Equal(t, metaW, meta)
	require.Equal(t, stateW, state)
	require.Equal(t, entsW, ents)

	require.Equal(t, metadata, meta)
	require.Equal(t, entries, ents)
}

// If an encoding is provided, the entry data and metadata are encoded and
// a regular WAL will see them as such.
func TestSaveWithEncoding(t *testing.T) {
	metadata, entries, snapshot := makeWALData()

	tempdir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	coder := &meowCoder{}
	wrapped, err := CreateWAL(tempdir, metadata, coder, nil)
	require.NoError(t, err)

	require.NoError(t, wrapped.SaveSnapshot(snapshot))
	require.NoError(t, wrapped.Save(raftpb.HardState{}, entries))
	require.NoError(t, wrapped.Close())

	wrapped, err = OpenWAL(tempdir, snapshot, nil, []decoder{coder})
	require.NoError(t, err)
	metaW, stateW, entsW, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())

	ogWAL, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	defer ogWAL.Close()

	meta, state, ents, err := ogWAL.ReadAll()
	require.NoError(t, err)
	require.NotEqual(t, metaW, meta)
	require.Equal(t, stateW, state)
	require.NotEqual(t, entsW, ents)

	require.Equal(t, metadata, metaW)
	require.Equal(t, entries, entsW)
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
		fmt.Sprintf("%d_%d", snapshot.Index+3, snapshot.Term): struct{}{},
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

// If the underlying WAL returns an error when opening or creating, the error
// is propagated up.
func TestCreateOpenInvalidDirFails(t *testing.T) {
	_, err := CreateWAL("/not/existing/directory", []byte("metadata"), nil, nil)
	require.Error(t, err)

	_, err = OpenWAL("/not/existing/directory", walpb.Snapshot{}, nil, nil)
	require.Error(t, err)
}

// A WAL can read what it wrote so long as it has a corresponding decoder
func TestSaveAndRead(t *testing.T) {
	coder := &meowCoder{}
	metadata, entries, snapshot := makeWALData()

	for _, e := range []encoder{nil, coder} {
		tempdir, err := ioutil.TempDir("", "waltests")
		require.NoError(t, err)
		defer os.RemoveAll(tempdir)

		wrapped, err := CreateWAL(tempdir, metadata, e, nil)
		require.NoError(t, err)

		require.NoError(t, wrapped.SaveSnapshot(snapshot))
		require.NoError(t, wrapped.Save(raftpb.HardState{}, entries))
		require.NoError(t, wrapped.Close())

		wrapped, err = OpenWAL(tempdir, snapshot, nil, []decoder{coder})
		meta, _, ents, err := wrapped.ReadAll()
		defer wrapped.Close()
		require.NoError(t, err)
		require.Equal(t, metadata, meta)
		require.Equal(t, entries, ents)
	}
}
