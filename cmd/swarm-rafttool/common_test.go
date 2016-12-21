package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/etcd/pkg/fileutil"
	"github.com/coreos/etcd/raft/raftpb"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/ca/testutils"
	v2raftpb "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/raft/raftpb"
	v2snap "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/snap"
	v2wal "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/wal"
	v2walpb "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/wal/walpb"
	"github.com/docker/swarmkit/manager"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/manager/state/raft"
	"github.com/docker/swarmkit/manager/state/raft/storage"
	"github.com/stretchr/testify/require"
)

// writeFakeV2RaftData writes the given snapshot and some generated WAL data to given "snap" and "wal" directories
// using the v2 etcd snap and wal packages - this is just a copy of the test helper in manager/state/raft/storage_test.go,
// because the types are different
func writeFakeV2RaftData(t *testing.T, raftDir string, snapshot *v2raftpb.Snapshot) {
	snapDir := filepath.Join(raftDir, "raft", "snap")
	walDir := filepath.Join(raftDir, "raft", "wal")
	require.NoError(t, os.MkdirAll(snapDir, 0755))

	wsn := v2walpb.Snapshot{}
	if snapshot != nil {
		require.NoError(t, v2snap.New(snapDir).SaveSnap(*snapshot))

		wsn.Index = snapshot.Metadata.Index
		wsn.Term = snapshot.Metadata.Term
	}

	var entries []v2raftpb.Entry
	for i := wsn.Index + 1; i < wsn.Index+6; i++ {
		entries = append(entries, v2raftpb.Entry{
			Term:  wsn.Term + 1,
			Index: i,
			Data:  []byte(fmt.Sprintf("v2Entry %d", i)),
		})
	}

	walWriter, err := v2wal.Create(walDir, []byte("v2metadata"))
	require.NoError(t, err)
	require.NoError(t, walWriter.SaveSnapshot(wsn))
	require.NoError(t, walWriter.Save(v2raftpb.HardState{}, entries))
	require.NoError(t, walWriter.Close())
}

func writeFakeV3RaftData(t *testing.T, stateDir string, snapshot *raftpb.Snapshot, wf storage.WALFactory, sf storage.SnapFactory) {
	snapDir := filepath.Join(stateDir, "raft", "snap-v3-encrypted")
	walDir := filepath.Join(stateDir, "raft", "wal-v3-encrypted")
	require.NoError(t, os.MkdirAll(snapDir, 0755))

	wsn := walpb.Snapshot{}
	if snapshot != nil {
		require.NoError(t, sf.New(snapDir).SaveSnap(*snapshot))

		wsn.Index = snapshot.Metadata.Index
		wsn.Term = snapshot.Metadata.Term
	}

	var entries []raftpb.Entry
	for i := wsn.Index + 1; i < wsn.Index+6; i++ {
		entries = append(entries, raftpb.Entry{
			Term:  wsn.Term + 1,
			Index: i,
			Data:  []byte(fmt.Sprintf("v3Entry %d", i)),
		})
	}

	walWriter, err := wf.Create(walDir, []byte("v3metadata"))
	require.NoError(t, err)
	require.NoError(t, walWriter.SaveSnapshot(wsn))
	require.NoError(t, walWriter.Save(raftpb.HardState{}, entries))
	require.NoError(t, walWriter.Close())
}

func TestDowngradeToV2(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "rafttool")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	kek := []byte("kek")
	dek := []byte("dek")
	unlockKey := encryption.HumanReadableKey(kek)

	// write a key to disk, else we won't be able to decrypt anything
	paths := certPaths(tempdir)
	krw := ca.NewKeyReadWriter(paths.Node, kek,
		manager.RaftDEKData{EncryptionKeys: raft.EncryptionKeys{CurrentDEK: dek}})
	cert, key, err := testutils.CreateRootCertAndKey("not really a root, just need cert and key")
	require.NoError(t, err)
	require.NoError(t, krw.Write(cert, key, nil))

	checkFiles := func(numRaftDirs, numCertFiles int) {
		files, err := ioutil.ReadDir(filepath.Join(tempdir, "raft"))
		require.NoError(t, err)
		require.Len(t, files, numRaftDirs)

		files, err = ioutil.ReadDir(filepath.Join(tempdir, "certificates"))
		require.NoError(t, err)
		require.Len(t, files, numCertFiles)
	}

	// make sure a snap/wal directory already exist
	writeFakeV2RaftData(t, tempdir, &v2raftpb.Snapshot{
		Data: []byte("snapshotdata"),
		Metadata: v2raftpb.SnapshotMetadata{
			Index: 1,
			Term:  1,
		},
	})
	checkFiles(2, 2)
	// if there is no v3 encrypted directory, nothing gets moved or migrated.
	err = downgrade(tempdir, unlockKey)
	require.Equal(t, err, storage.ErrNoWAL)
	checkFiles(2, 2)

	// create the encrypted v3 directory
	e, d := encryption.Defaults(dek)
	v3snapshot := raftpb.Snapshot{
		Data: []byte("latest snapshot"),
		Metadata: raftpb.SnapshotMetadata{
			Index: 100,
			Term:  100,
		},
	}
	writeFakeV3RaftData(t, tempdir, &v3snapshot, storage.NewWALFactory(e, d), storage.NewSnapFactory(e, d))
	checkFiles(4, 2)

	// if we use the wrong unlock key, we can't actually decrypt anything
	err = downgrade(tempdir, "")
	require.IsType(t, ca.ErrInvalidKEK{}, err)
	checkFiles(4, 2)

	// Using the right unlock key, we move aside the existing snap and wal directories and
	// migrate all the data to the old format
	require.NoError(t, downgrade(tempdir, unlockKey))
	checkFiles(6, 3) // 2 temp snap/wal directories, 1 temp key file

	// the key is now unencrypted, with no headers
	dekManager := manager.RaftDEKData{}
	krw = ca.NewKeyReadWriter(paths.Node, nil, dekManager)
	_, _, err = krw.Read()
	require.NoError(t, err)
	require.Nil(t, dekManager.EncryptionKeys.CurrentDEK)

	// The snapshot directory is readable by the v2 etcd snapshotter
	v2snapshot, err := v2snap.New(filepath.Join(tempdir, "raft", "snap")).Load()
	require.NoError(t, err)
	require.NotNil(t, v2snapshot)
	require.Equal(t, v3snapshot.Data, v2snapshot.Data)
	require.Equal(t, v2raftpb.SnapshotMetadata{Index: 100, Term: 100}, v2snapshot.Metadata)

	// The wals are readable by the v2 etcd wal
	walreader, err := v2wal.Open(filepath.Join(tempdir, "raft", "wal"), v2walpb.Snapshot{Index: 100, Term: 100})
	require.NoError(t, err)
	metadata, _, v2entries, err := walreader.ReadAll()
	require.NoError(t, err)
	require.Equal(t, []byte("v3metadata"), metadata)
	require.Len(t, v2entries, 5)
	for _, ent := range v2entries {
		require.True(t, bytes.HasPrefix(ent.Data, []byte("v3Entry")))
		require.True(t, ent.Index > 100)
		require.True(t, ent.Term > 100)
	}
}

func TestDecrypt(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "rafttool")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	kek := []byte("kek")
	dek := []byte("dek")
	unlockKey := encryption.HumanReadableKey(kek)

	// write a key to disk, else we won't be able to decrypt anything
	paths := certPaths(tempdir)
	krw := ca.NewKeyReadWriter(paths.Node, kek,
		manager.RaftDEKData{EncryptionKeys: raft.EncryptionKeys{CurrentDEK: dek}})
	cert, key, err := testutils.CreateRootCertAndKey("not really a root, just need cert and key")
	require.NoError(t, err)
	require.NoError(t, krw.Write(cert, key, nil))

	// create the encrypted v3 directory
	origSnapshot := raftpb.Snapshot{
		Data: []byte("snapshot"),
		Metadata: raftpb.SnapshotMetadata{
			Index: 1,
			Term:  1,
		},
	}
	e, d := encryption.Defaults(dek)
	writeFakeV3RaftData(t, tempdir, &origSnapshot, storage.NewWALFactory(e, d), storage.NewSnapFactory(e, d))

	outdir := filepath.Join(tempdir, "outdir")
	// if we use the wrong unlock key, we can't actually decrypt anything.  The output directory won't get created.
	err = decryptRaftData(tempdir, outdir, "")
	require.IsType(t, ca.ErrInvalidKEK{}, err)
	require.False(t, fileutil.Exist(outdir))

	// Using the right unlock key, we produce data that is unencrypted
	require.NoError(t, decryptRaftData(tempdir, outdir, unlockKey))
	require.True(t, fileutil.Exist(outdir))

	// The snapshot directory is readable by the regular snapshotter
	snapshot, err := storage.OriginalSnap.New(filepath.Join(outdir, "snap-decrypted")).Load()
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	require.Equal(t, origSnapshot, *snapshot)

	// The wals are readable by the regular wal
	walreader, err := storage.OriginalWAL.Open(filepath.Join(outdir, "wal-decrypted"), walpb.Snapshot{Index: 1, Term: 1})
	require.NoError(t, err)
	metadata, _, entries, err := walreader.ReadAll()
	require.NoError(t, err)
	require.Equal(t, []byte("v3metadata"), metadata)
	require.Len(t, entries, 5)
}
