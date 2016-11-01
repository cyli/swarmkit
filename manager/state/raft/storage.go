package raft

import (
	"fmt"

	"github.com/coreos/etcd/raft"
	"github.com/coreos/etcd/raft/raftpb"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/log"
	"github.com/docker/swarmkit/manager/state/raft/membership"
	"github.com/docker/swarmkit/manager/state/store"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

var errNoWAL = errors.New("no WAL present")

// bootstraps a node's raft store from the raft logs and snapshots on disk
func (n *Node) loadAndStart(ctx context.Context, forceNewCluster bool) error {
	snapshot, waldata, err := n.raftLogger.BootstrapFromDisk(ctx)
	if err != nil {
		return err
	}

	if snapshot != nil {
		// Load the snapshot data into the store
		if err := n.restoreFromSnapshot(snapshot.Data, forceNewCluster); err != nil {
			return err
		}
	}

	// Read logs to fully catch up store
	var raftNode api.RaftMember
	if err := raftNode.Unmarshal(waldata.Metadata); err != nil {
		return errors.Wrap(err, "failed to unmarshal WAL metadata")
	}
	n.Config.ID = raftNode.RaftID

	ents, st := waldata.Entries, waldata.HardState

	// All members that are no longer part of the cluster must be added to
	// the removed list right away, so that we don't try to connect to them
	// before processing the configuration change entries, which could make
	// us get stuck.
	for _, ent := range ents {
		if ent.Index <= st.Commit && ent.Type == raftpb.EntryConfChange {
			var cc raftpb.ConfChange
			if err := cc.Unmarshal(ent.Data); err != nil {
				return errors.Wrap(err, "failed to unmarshal config change")
			}
			if cc.Type == raftpb.ConfChangeRemoveNode {
				n.cluster.RemoveMember(cc.NodeID)
			}
		}
	}

	if forceNewCluster {
		// discard the previously uncommitted entries
		for i, ent := range ents {
			if ent.Index > st.Commit {
				log.G(ctx).Infof("discarding %d uncommitted WAL entries ", len(ents)-i)
				ents = ents[:i]
				break
			}
		}

		// force append the configuration change entries
		toAppEnts := createConfigChangeEnts(getIDs(snapshot, ents), uint64(n.Config.ID), st.Term, st.Commit)

		// All members that are being removed as part of the
		// force-new-cluster process must be added to the
		// removed list right away, so that we don't try to
		// connect to them before processing the configuration
		// change entries, which could make us get stuck.
		for _, ccEnt := range toAppEnts {
			if ccEnt.Type == raftpb.EntryConfChange {
				var cc raftpb.ConfChange
				if err := cc.Unmarshal(ccEnt.Data); err != nil {
					return errors.Wrap(err, "error unmarshalling force-new-cluster config change")
				}
				if cc.Type == raftpb.ConfChangeRemoveNode {
					n.cluster.RemoveMember(cc.NodeID)
				}
			}
		}
		ents = append(ents, toAppEnts...)

		// force commit newly appended entries
		err := n.raftLogger.SaveEntries(st, toAppEnts)
		if err != nil {
			log.G(ctx).WithError(err).Fatalf("failed to save WAL while forcing new cluster")
		}
		if len(toAppEnts) != 0 {
			st.Commit = toAppEnts[len(toAppEnts)-1].Index
		}
	}

	if snapshot != nil {
		if err := n.raftStore.ApplySnapshot(*snapshot); err != nil {
			return err
		}
	}
	if err := n.raftStore.SetHardState(st); err != nil {
		return err
	}
	return n.raftStore.Append(ents)
}

func (n *Node) newRaftLogs(nodeID string) (raft.Peer, error) {
	raftNode := &api.RaftMember{
		RaftID: n.Config.ID,
		NodeID: nodeID,
		Addr:   n.opts.Addr,
	}
	metadata, err := raftNode.Marshal()
	if err != nil {
		return raft.Peer{}, errors.Wrap(err, "error marshalling raft node")
	}
	if err := n.raftLogger.BootstrapNew(metadata); err != nil {
		return raft.Peer{}, err
	}
	n.cluster.AddMember(&membership.Member{RaftMember: raftNode})
	return raft.Peer{ID: n.Config.ID, Context: metadata}, nil
}

func (n *Node) doSnapshot(ctx context.Context, raftConfig api.RaftConfig) {
	snapshot := api.Snapshot{Version: api.Snapshot_V0}
	for _, member := range n.cluster.Members() {
		snapshot.Membership.Members = append(snapshot.Membership.Members,
			&api.RaftMember{
				NodeID: member.NodeID,
				RaftID: member.RaftID,
				Addr:   member.Addr,
			})
	}
	snapshot.Membership.Removed = n.cluster.Removed()

	viewStarted := make(chan struct{})
	n.asyncTasks.Add(1)
	n.snapshotInProgress = make(chan uint64, 1) // buffered in case Shutdown is called during the snapshot
	go func(appliedIndex, snapshotIndex uint64) {
		defer func() {
			n.asyncTasks.Done()
			n.snapshotInProgress <- snapshotIndex
		}()

		var err error
		n.memoryStore.View(func(tx store.ReadTx) {
			close(viewStarted)

			var storeSnapshot *api.StoreSnapshot
			storeSnapshot, err = n.memoryStore.Save(tx)
			snapshot.Store = *storeSnapshot
		})
		if err != nil {
			log.G(ctx).WithError(err).Error("failed to read snapshot from store")
			return
		}

		d, err := snapshot.Marshal()
		if err != nil {
			log.G(ctx).WithError(err).Error("failed to marshal snapshot")
			return
		}
		snap, err := n.raftStore.CreateSnapshot(appliedIndex, &n.confState, d)
		if err == nil {
			if err := n.saveSnapshot(snap, raftConfig.KeepOldSnapshots); err != nil {
				log.G(ctx).WithError(err).Error("failed to save snapshot")
				return
			}
			snapshotIndex = appliedIndex

			if appliedIndex > raftConfig.LogEntriesForSlowFollowers {
				err := n.raftStore.Compact(appliedIndex - raftConfig.LogEntriesForSlowFollowers)
				if err != nil && err != raft.ErrCompacted {
					log.G(ctx).WithError(err).Error("failed to compact snapshot")
				}
			}
		} else if err != raft.ErrSnapOutOfDate {
			log.G(ctx).WithError(err).Error("failed to create snapshot")
		}
	}(n.appliedIndex, n.snapshotIndex)

	// Wait for the goroutine to establish a read transaction, to make
	// sure it sees the state as of this moment.
	<-viewStarted
}

// This sees if there are any keys queued to be rotated if so it saves the snapshot and trims
// the key queue. Otherwise, it just saves the snapshot.
func (n *Node) saveSnapshot(snapshot raftpb.Snapshot, keepOldSnapshots uint64) error {
	_, err := n.keyRotator.MaybeDoRotation(func(key []byte) error {
		return n.raftLogger.SaveSnapshot(snapshot, key)
	})
	if err != nil {
		return err
	}
	return n.raftLogger.GC(snapshot.Metadata.Index, snapshot.Metadata.Term, keepOldSnapshots)
}

func (n *Node) restoreFromSnapshot(data []byte, forceNewCluster bool) error {
	var snapshot api.Snapshot
	if err := snapshot.Unmarshal(data); err != nil {
		return err
	}
	if snapshot.Version != api.Snapshot_V0 {
		return fmt.Errorf("unrecognized snapshot version %d", snapshot.Version)
	}

	if err := n.memoryStore.Restore(&snapshot.Store); err != nil {
		return err
	}

	oldMembers := n.cluster.Members()

	if !forceNewCluster {
		for _, member := range snapshot.Membership.Members {
			if err := n.registerNode(&api.RaftMember{RaftID: member.RaftID, NodeID: member.NodeID, Addr: member.Addr}); err != nil {
				return err
			}
			delete(oldMembers, member.RaftID)
		}
	}

	for _, removedMember := range snapshot.Membership.Removed {
		n.cluster.RemoveMember(removedMember)
		delete(oldMembers, removedMember)
	}

	for member := range oldMembers {
		n.cluster.ClearMember(member)
	}

	return nil
}
