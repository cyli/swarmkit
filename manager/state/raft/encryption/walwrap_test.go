package encryption

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/stretchr/testify/require"
)

type meowCoder struct{}

func (m meowCoder) Encode(index, term uint64, orig []byte) ([]byte, error) {
	return append(orig, []byte("🐱")...), nil
}

func (m meowCoder) Decode(index, term uint64, orig []byte) ([]byte, error) {
	if !bytes.HasSuffix(orig, []byte("🐱")) {
		return nil, fmt.Errorf("not meowcoded")
	}
	return bytes.TrimSuffix(orig, []byte("🐱")), nil
}

func (m meowCoder) ID() string {
	return "🐱-coder"
}

// Generates a bunch of WAL test data
func makeWALData() ([]byte, []raftpb.Entry, walpb.Snapshot) {
	term := uint64(3)
	index := uint64(4)

	var entries []raftpb.Entry
	for i := index + 1; i < index+6; i++ {
		entries = append(entries, raftpb.Entry{
			Term:  5,
			Index: i,
			Data:  []byte(fmt.Sprintf("Entry %d", i)),
		})
	}

	return []byte("metadata"), entries, walpb.Snapshot{Index: index, Term: term}
}

func createWithRegularWAL(t *testing.T, metadata []byte, startSnap walpb.Snapshot, entries []raftpb.Entry) string {
	walDir, err := ioutil.TempDir("", "waltests")
	require.NoError(t, err)

	w, err := wal.Create(walDir, metadata)
	require.NoError(t, err)

	require.NoError(t, w.SaveSnapshot(startSnap))
	require.NoError(t, w.Save(raftpb.HardState{}, entries))
	require.NoError(t, w.ReleaseLockTo(startSnap.Index+uint64(len(entries)+1)))
	require.NoError(t, w.Close())

	return walDir
}

func getMeowDecodingWAL(t *testing.T, tempdir string, startSnap walpb.Snapshot) WAL {
	w, err := wal.Open(tempdir, startSnap)
	require.NoError(t, err)

	coder := meowCoder{}
	return &WrappedWAL{
		WAL:     w,
		encoder: coder,
		getDecoder: func(d string) decoder {
			if d == coder.ID() {
				return coder
			}
			return nil
		},
	}
}

// WAL can read entries that are not wrapped at all (written by the default wal.WAL)
func TestReadAllNoWrapping(t *testing.T) {
	metadata, entries, snapshot := makeWALData()
	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	w, err := wal.Open(tempdir, snapshot)
	require.NoError(t, err)
	meta, state, ents, err := w.ReadAll()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, metadata, meta)
	require.Equal(t, entries, ents)

	wrapped := getMeowDecodingWAL(t, tempdir, snapshot)
	metaW, stateW, entsW, err := wrapped.ReadAll()
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())

	require.Equal(t, meta, metaW)
	require.Equal(t, state, stateW)
	require.Equal(t, ents, entsW)
}

// WAL can read entries are not wrapped, but not encoded
func TestReadAllWrappedNoEncoding(t *testing.T) {
	ogMeta, entries, snapshot := makeWALData()
	r := WrappedRecord{Wrapped: ogMeta}
	metadata, err := r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped := getMeowDecodingWAL(t, tempdir, snapshot)
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
		Wrapped:  metadata,
		Encoding: "no-decoder",
	}
	var err error
	metadata, err = r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped := getMeowDecodingWAL(t, tempdir, snapshot)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no decoder")
}

// When reading WAL, if a decoder is available for the encoding type but any
// entry is incorrectly encoded, an error is returned
func TestReadAllEntryIncorrectlyEncoded(t *testing.T) {
	coder := meowCoder{}
	metadata, entries, snapshot := makeWALData()

	// metadata is correctly encoded, but entries are not meow-encoded
	r := WrappedRecord{
		Wrapped:  metadata,
		Encoding: coder.ID(),
	}
	var err error
	metadata, err = r.Marshal()
	require.NoError(t, err)

	tempdir := createWithRegularWAL(t, metadata, snapshot, entries)
	defer os.RemoveAll(tempdir)

	wrapped := getMeowDecodingWAL(t, tempdir, snapshot)
	defer wrapped.Close()

	_, _, _, err = wrapped.ReadAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to decode")
}
