package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"os"

	"io"

	"github.com/coreos/etcd/pkg/fileutil"
	"github.com/coreos/etcd/wal/walpb"
	"github.com/docker/swarmkit/ca"
	v2raftpb "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/raft/raftpb"
	v2snap "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/snap"
	v2wal "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/wal"
	v2walpb "github.com/docker/swarmkit/cmd/swarm-rafttool/v2etcd/wal/walpb"
	"github.com/docker/swarmkit/manager"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/manager/state/raft/storage"
)

func certPaths(swarmdir string) *ca.SecurityConfigPaths {
	return ca.NewConfigPaths(filepath.Join(swarmdir, "certificates"))
}

func getDEKData(krw *ca.KeyReadWriter) (manager.RaftDEKData, error) {
	h, _ := krw.GetCurrentState()
	dekData, ok := h.(manager.RaftDEKData)
	if !ok {
		return manager.RaftDEKData{}, fmt.Errorf("cannot read raft dek headers in TLS key ")
	}

	if dekData.CurrentDEK == nil {
		return manager.RaftDEKData{}, fmt.Errorf("no raft DEKs available")
	}

	return dekData, nil
}

func getKRW(swarmdir, unlockKey string) (*ca.KeyReadWriter, error) {
	var (
		kek []byte
		err error
	)
	if unlockKey != "" {
		kek, err = encryption.ParseHumanReadableKey(unlockKey)
		if err != nil {
			return nil, err
		}
	}
	krw := ca.NewKeyReadWriter(certPaths(swarmdir).Node, kek, manager.RaftDEKData{})
	_, _, err = krw.Read() // loads all the key data into the KRW object
	if err != nil {
		return nil, err
	}
	return krw, nil
}

func moveDirAside(dirname string) error {
	if fileutil.Exist(dirname) {
		tempdir, err := ioutil.TempDir(filepath.Dir(dirname), filepath.Base(dirname))
		if err != nil {
			return err
		}
		return os.Rename(dirname, tempdir)
	}
	return nil
}

func decryptRaftData(swarmdir, outdir, unlockKey string) error {
	krw, err := getKRW(swarmdir, unlockKey)
	if err != nil {
		return err
	}
	deks, err := getDEKData(krw)
	if err != nil {
		return err
	}

	_, d := encryption.Defaults(deks.CurrentDEK)
	if deks.PendingDEK == nil {
		_, d2 := encryption.Defaults(deks.PendingDEK)
		d = storage.MultiDecrypter{d, d2}
	}

	snapDir := filepath.Join(outdir, "snap-decrypted")
	if err := moveDirAside(snapDir); err != nil {
		return err
	}
	if err := storage.MigrateSnapshot(
		filepath.Join(swarmdir, "raft", "snap-v3-encrypted"), snapDir,
		storage.NewSnapFactory(encryption.NoopCrypter, d), storage.OriginalSnap); err != nil {
		return err
	}

	var walsnap walpb.Snapshot
	snap, err := storage.OriginalSnap.New(snapDir).Load()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if snap != nil {
		walsnap.Index = snap.Metadata.Index
		walsnap.Term = snap.Metadata.Term
	}

	walDir := filepath.Join(outdir, "wal-decrypted")
	if err := moveDirAside(walDir); err != nil {
		return err
	}
	return storage.MigrateWALs(context.Background(),
		filepath.Join(swarmdir, "raft", "wal-v3-encrypted"), walDir,
		storage.NewWALFactory(encryption.NoopCrypter, d), storage.OriginalWAL, walsnap)
}

func backUpFile(filename string) error {
	src, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

// we can't actually use the migrate functions, because we cannot create a v2 etcd WALFactory
// or v2 etcd SnapFactory, since the types returned are v2etcd's snapshots and entries, which
// may be different.  So read everything using our logger, and write using v2etcd's wal and
// snapshotter
func downgrade(swarmdir, unlockKey string) error {
	krw, err := getKRW(swarmdir, unlockKey)
	if err != nil {
		return err
	}

	deks, err := getDEKData(krw)
	if err != nil {
		return err
	}

	raftDir := filepath.Join(swarmdir, "raft")

	// It doesn't matter which we use as the main key for the logger, because all we are doing is
	// reading, not writing with the logger.
	logger := storage.EncryptedRaftLogger{
		StateDir:      raftDir,
		EncryptionKey: deks.CurrentDEK,
	}
	var otherKeys [][]byte
	if deks.PendingDEK != nil {
		otherKeys = append(otherKeys, deks.PendingDEK)
	}
	// The BootstrapFromDisk will create this directory if it doesn't exist, so clean it up if it shouldn't
	// have existed.
	v3SnapDir := filepath.Join(swarmdir, "raft", "snap-v3-encrypted")
	if !fileutil.Exist(v3SnapDir) {
		defer os.RemoveAll(v3SnapDir)
	}
	v3snapshot, v3walData, err := logger.BootstrapFromDisk(context.Background(), false, otherKeys...)
	if err != nil {
		return err
	}

	// Back up the encrypted key with raft headers before replacing it with the decrypted version
	if err := backUpFile(certPaths(swarmdir).Node.Key); err != nil {
		return err
	}

	// throw away headers (ViewAndUpdateHeaders) and ensure the key is decrypted
	// (via ViewAndRotateKEK, which can also update headers, but does not deleting
	// headers)
	err = krw.ViewAndUpdateHeaders(func(_ ca.PEMKeyHeaders) (ca.PEMKeyHeaders, error) {
		return manager.RaftDEKData{}, nil
	})
	if err != nil {
		return err
	}
	err = krw.ViewAndRotateKEK(func(_ ca.KEKData, _ ca.PEMKeyHeaders) (ca.KEKData, ca.PEMKeyHeaders, error) {
		return ca.KEKData{}, nil, nil
	})
	if err != nil {
		return err
	}

	snapDir := filepath.Join(raftDir, "snap")
	if err := moveDirAside(snapDir); err != nil {
		return err
	}
	if err := fileutil.CreateDirAll(snapDir); err != nil {
		return err
	}
	wsn := v2walpb.Snapshot{}
	if v3snapshot != nil {
		if err := v2snap.New(snapDir).SaveSnap(v2raftpb.Snapshot{
			Data: v3snapshot.Data,
			Metadata: v2raftpb.SnapshotMetadata{
				Index: v3snapshot.Metadata.Index,
				Term:  v3snapshot.Metadata.Term,
			},
		}); err != nil {
			return err
		}
		wsn.Index = v3snapshot.Metadata.Index
		wsn.Term = v3snapshot.Metadata.Term
	}

	// protobuf types have not changed between v2 and v3, but on v3 the index and term must be 64-bit aligned
	// raftpb entries have changed between v2 and v3
	walDir := filepath.Join(raftDir, "wal")
	if err := moveDirAside(walDir); err != nil {
		return err
	}
	walwriter, err := v2wal.Create(walDir, v3walData.Metadata)
	if err != nil {
		return err
	}
	if err := walwriter.SaveSnapshot(wsn); err != nil {
		return err
	}
	v2state := v2raftpb.HardState(v3walData.HardState)
	var v2entries []v2raftpb.Entry
	for _, ent := range v3walData.Entries {
		v2entries = append(v2entries, v2raftpb.Entry{
			Type:  v2raftpb.EntryType(ent.Type),
			Index: ent.Index,
			Term:  ent.Term,
			Data:  ent.Data,
		})
	}
	if err := walwriter.Save(v2state, v2entries); err != nil {
		return err
	}
	return walwriter.Close()
}
