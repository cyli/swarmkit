package main

import (
	"context"
	"fmt"
	"path/filepath"

	"os"

	"github.com/coreos/etcd/wal/walpb"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/manager"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/manager/state/raft/storage"
)

func getDEKs(swarmdir, unlockKey string) (manager.RaftDEKData, error) {
	paths := ca.NewConfigPaths(filepath.Join(swarmdir, "certificates"))
	var (
		kek []byte
		err error
	)
	if unlockKey != "" {
		kek, err = encryption.ParseHumanReadableKey(unlockKey)
		if err != nil {
			return manager.RaftDEKData{}, err
		}
	}
	krw := ca.NewKeyReadWriter(paths.Node, kek, manager.RaftDEKData{})
	_, _, err = krw.Read()
	if err != nil {
		return manager.RaftDEKData{}, err
	}

	h, _ := krw.GetCurrentState()
	dekData, ok := h.(manager.RaftDEKData)
	if !ok {
		return manager.RaftDEKData{}, fmt.Errorf("cannot read raft dek headers in TLS key ")
	}
	return dekData, nil
}

func decryptRaftData(swarmdir, outdir string, deks manager.RaftDEKData) error {
	if deks.CurrentDEK == nil {
		return fmt.Errorf("no raft DEKs available")
	}

	_, d := encryption.Defaults(deks.CurrentDEK)
	if deks.PendingDEK == nil {
		_, d2 := encryption.Defaults(deks.PendingDEK)
		d = storage.MultiDecrypter{d, d2}
	}

	snapDir := filepath.Join(outdir, "snap-decrypted")
	err := storage.MigrateSnapshot(
		filepath.Join(swarmdir, "raft", "snap-v3-encrypted"), filepath.Join(outdir, "snap-decrypted"),
		storage.NewSnapFactory(encryption.NoopCrypter, d), storage.OriginalSnap)
	if err != nil {
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

	return storage.MigrateWALs(context.Background(),
		filepath.Join(swarmdir, "raft", "wal-v3-encrypted"), filepath.Join(outdir, "wal-decrypted"),
		storage.NewWALFactory(encryption.NoopCrypter, d), storage.OriginalWAL, walsnap)
}
