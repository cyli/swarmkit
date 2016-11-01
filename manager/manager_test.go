package manager

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/ca/testutils"
	"github.com/docker/swarmkit/manager/dispatcher"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/manager/state/raft/storage"
	raftutils "github.com/docker/swarmkit/manager/state/raft/testutils"
	"github.com/docker/swarmkit/manager/state/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {
	ctx := context.Background()

	temp, err := ioutil.TempFile("", "test-socket")
	assert.NoError(t, err)
	assert.NoError(t, temp.Close())
	assert.NoError(t, os.Remove(temp.Name()))

	defer os.RemoveAll(temp.Name())

	stateDir, err := ioutil.TempDir("", "test-raft")
	assert.NoError(t, err)
	defer os.RemoveAll(stateDir)

	tc := testutils.NewTestCA(t, func(p ca.CertPaths) *ca.KeyReadWriter {
		return ca.NewKeyReadWriter(p, []byte("kek"), nil)
	})
	defer tc.Stop()

	agentSecurityConfig, err := tc.NewNodeConfig(ca.WorkerRole)
	assert.NoError(t, err)
	agentDiffOrgSecurityConfig, err := tc.NewNodeConfigOrg(ca.WorkerRole, "another-org")
	assert.NoError(t, err)
	managerSecurityConfig, err := tc.NewNodeConfig(ca.ManagerRole)
	assert.NoError(t, err)

	m, err := New(&Config{
		RemoteAPI:        RemoteAddrs{ListenAddr: "127.0.0.1:0"},
		ControlAPI:       temp.Name(),
		StateDir:         stateDir,
		SecurityConfig:   managerSecurityConfig,
		AutoLockManagers: true,
		PEMHeadersManager: NewRaftDEKPEMHeadersManager(
			RaftDEKData{CurrentDEK: []byte("dek")},
			[]byte("kek"),
		),
	})
	assert.NoError(t, err)
	assert.NotNil(t, m)

	tcpAddr := m.Addr()

	done := make(chan error)
	defer close(done)
	go func() {
		done <- m.Run(ctx)
	}()

	opts := []grpc.DialOption{
		grpc.WithTimeout(10 * time.Second),
		grpc.WithTransportCredentials(agentSecurityConfig.ClientTLSCreds),
	}

	conn, err := grpc.Dial(tcpAddr, opts...)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, conn.Close())
	}()

	// We have to send a dummy request to verify if the connection is actually up.
	client := api.NewDispatcherClient(conn)
	_, err = client.Heartbeat(ctx, &api.HeartbeatRequest{})
	assert.Equal(t, dispatcher.ErrNodeNotRegistered.Error(), grpc.ErrorDesc(err))
	_, err = client.Session(ctx, &api.SessionRequest{})
	assert.NoError(t, err)

	// Try to have a client in a different org access this manager
	opts = []grpc.DialOption{
		grpc.WithTimeout(10 * time.Second),
		grpc.WithTransportCredentials(agentDiffOrgSecurityConfig.ClientTLSCreds),
	}

	conn2, err := grpc.Dial(tcpAddr, opts...)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, conn2.Close())
	}()

	client = api.NewDispatcherClient(conn2)
	_, err = client.Heartbeat(context.Background(), &api.HeartbeatRequest{})
	assert.Contains(t, grpc.ErrorDesc(err), "Permission denied: unauthorized peer role: rpc error: code = 7 desc = Permission denied: remote certificate not part of organization")

	// Verify that requests to the various GRPC services running on TCP
	// are rejected if they don't have certs.
	opts = []grpc.DialOption{
		grpc.WithTimeout(10 * time.Second),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
	}

	noCertConn, err := grpc.Dial(tcpAddr, opts...)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, noCertConn.Close())
	}()

	client = api.NewDispatcherClient(noCertConn)
	_, err = client.Heartbeat(context.Background(), &api.HeartbeatRequest{})
	assert.EqualError(t, err, "rpc error: code = 7 desc = Permission denied: unauthorized peer role: rpc error: code = 7 desc = no client certificates in request")

	controlClient := api.NewControlClient(noCertConn)
	_, err = controlClient.ListNodes(context.Background(), &api.ListNodesRequest{})
	assert.EqualError(t, err, "rpc error: code = 7 desc = Permission denied: unauthorized peer role: rpc error: code = 7 desc = no client certificates in request")

	raftClient := api.NewRaftMembershipClient(noCertConn)
	_, err = raftClient.Join(context.Background(), &api.JoinRequest{})
	assert.EqualError(t, err, "rpc error: code = 7 desc = Permission denied: unauthorized peer role: rpc error: code = 7 desc = no client certificates in request")

	opts = []grpc.DialOption{
		grpc.WithTimeout(10 * time.Second),
		grpc.WithTransportCredentials(managerSecurityConfig.ClientTLSCreds),
	}

	controlConn, err := grpc.Dial(tcpAddr, opts...)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, controlConn.Close())
	}()

	// check that the kek is added to the config
	var cluster api.Cluster
	m.raftNode.MemoryStore().View(func(tx store.ReadTx) {
		clusters, err := store.FindClusters(tx, store.All)
		require.NoError(t, err)
		require.Len(t, clusters, 1)
		cluster = *clusters[0]
	})
	require.NotNil(t, cluster)
	require.Len(t, cluster.UnlockKeys, 1)
	require.Equal(t, &api.EncryptionKey{
		Subsystem: ca.ManagerRole,
		Key:       []byte("kek"),
	}, cluster.UnlockKeys[0])

	// Test removal of the agent node
	agentID := agentSecurityConfig.ClientTLSCreds.NodeID()
	assert.NoError(t, m.raftNode.MemoryStore().Update(func(tx store.Tx) error {
		return store.CreateNode(tx,
			&api.Node{
				ID: agentID,
				Certificate: api.Certificate{
					Role: api.NodeRoleWorker,
					CN:   agentID,
				},
			},
		)
	}))
	controlClient = api.NewControlClient(controlConn)
	_, err = controlClient.RemoveNode(context.Background(),
		&api.RemoveNodeRequest{
			NodeID: agentID,
			Force:  true,
		},
	)
	assert.NoError(t, err)

	client = api.NewDispatcherClient(conn)
	_, err = client.Heartbeat(context.Background(), &api.HeartbeatRequest{})
	assert.Contains(t, grpc.ErrorDesc(err), "removed from swarm")

	m.Stop(ctx)

	// After stopping we should MAY receive an error from ListenAndServe if
	// all this happened before WaitForLeader completed, so don't check the
	// error.
	<-done
}

// Tests locking and unlocking the manager and key rotations
func TestManagerLockUnlock(t *testing.T) {
	ctx := context.Background()

	temp, err := ioutil.TempFile("", "test-manager-lock")
	require.NoError(t, err)
	require.NoError(t, temp.Close())
	require.NoError(t, os.Remove(temp.Name()))

	defer os.RemoveAll(temp.Name())

	stateDir, err := ioutil.TempDir("", "test-raft")
	require.NoError(t, err)
	defer os.RemoveAll(stateDir)

	// start without a DEK, so we can test automatically adding one
	pemHeaderManager := &RaftDEKPEMHeadersManager{}

	tc := testutils.NewTestCA(t, func(p ca.CertPaths) *ca.KeyReadWriter {
		return ca.NewKeyReadWriter(p, nil, pemHeaderManager)
	})
	defer tc.Stop()

	managerSecurityConfig, err := tc.NewNodeConfig(ca.ManagerRole)
	require.NoError(t, err)

	_, _, err = managerSecurityConfig.KeyReader().Read()
	require.NoError(t, err)

	m, err := New(&Config{
		RemoteAPI:         RemoteAddrs{ListenAddr: "127.0.0.1:0"},
		ControlAPI:        temp.Name(),
		StateDir:          stateDir,
		SecurityConfig:    managerSecurityConfig,
		PEMHeadersManager: pemHeaderManager,
	})
	require.NoError(t, err)
	require.NotNil(t, m)

	done := make(chan error)
	defer close(done)
	go func() {
		done <- m.Run(ctx)
	}()

	opts := []grpc.DialOption{
		grpc.WithTimeout(10 * time.Second),
		grpc.WithTransportCredentials(managerSecurityConfig.ClientTLSCreds),
	}

	conn, err := grpc.Dial(m.Addr(), opts...)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, conn.Close())
	}()

	// check that there is no kek currently - we are using the API because this
	// lets us wait until the manager is up and listening, as well
	var cluster *api.Cluster
	client := api.NewControlClient(conn)

	require.NoError(t, raftutils.PollFuncWithTimeout(nil, func() error {
		resp, err := client.ListClusters(ctx, &api.ListClustersRequest{})
		if err != nil {
			return err
		}
		if len(resp.Clusters) == 0 {
			return fmt.Errorf("no clusters yet")
		}
		cluster = resp.Clusters[0]
		return nil
	}, 1*time.Second))

	require.Nil(t, cluster.UnlockKeys)

	// tls key is unencrypted, but there is a DEK
	key, err := ioutil.ReadFile(tc.Paths.Node.Key)
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(key)
	require.NotNil(t, keyBlock)
	require.False(t, x509.IsEncryptedPEMBlock(keyBlock))
	require.Len(t, keyBlock.Headers, 1)
	currentDEK, err := decodePEMHeaderValue(keyBlock.Headers[pemHeaderRaftDEK], nil)
	require.NoError(t, err)
	require.NotEmpty(t, currentDEK)

	tlsKeyPrivateBytes := keyBlock.Bytes

	// update the lock key - this may fail due to update out of sequence errors, so try again
	for i := 0; i < 3; i++ {
		getResp, err := client.GetCluster(ctx, &api.GetClusterRequest{ClusterID: cluster.ID})
		require.NoError(t, err)
		cluster = getResp.Cluster

		spec := cluster.Spec.Copy()
		spec.EncryptionConfig.AutoLockManagers = true
		_, err = client.UpdateCluster(ctx, &api.UpdateClusterRequest{
			ClusterID:      cluster.ID,
			ClusterVersion: &cluster.Meta.Version,
			Spec:           spec,
		})
		if grpc.ErrorDesc(err) == "update out of sequence" {
			continue
		}
		if err == nil {
			break
		}
	}
	require.NoError(t, err)

	// this should update the TLS key and start rotating the DEK
	var updatedKey []byte
	require.NoError(t, raftutils.PollFuncWithTimeout(nil, func() error {
		updatedKey, err = ioutil.ReadFile(tc.Paths.Node.Key)
		require.NoError(t, err) // this should never error due to atomic writes

		if bytes.Equal(key, updatedKey) {
			return fmt.Errorf("TLS key should have been re-encrypted at least")
		}

		keyBlock, _ = pem.Decode(updatedKey)
		require.NotNil(t, keyBlock) // this should never error due to atomic writes

		if !x509.IsEncryptedPEMBlock(keyBlock) {
			return fmt.Errorf("Key not encrypted")
		}

		return nil
	}, 1*time.Second))

	caConn := api.NewCAClient(conn)
	unlockKeyResp, err := caConn.GetUnlockKey(ctx, &api.GetUnlockKeyRequest{})
	require.NoError(t, err)

	// Don't know how fast the process was - if the DEK finished rotating and
	// the snapshot is done, then there'd only be one DEK header.  Either way,
	// there will be 2 key encryption headers.
	if len(keyBlock.Headers) > 3 {
		require.Len(t, keyBlock.Headers, 4)
		stillCurrentDEK, err := decodePEMHeaderValue(keyBlock.Headers[pemHeaderRaftDEK], unlockKeyResp.UnlockKey)
		require.NoError(t, err)
		require.Equal(t, currentDEK, stillCurrentDEK)
		pendingDEK, err := decodePEMHeaderValue(keyBlock.Headers[pemHeaderRaftPendingDEK], unlockKeyResp.UnlockKey)
		require.NoError(t, err)
		require.NotEqual(t, currentDEK, pendingDEK)
	}

	require.NoError(t, raftutils.PollFuncWithTimeout(nil, func() error {
		updatedKey, err = ioutil.ReadFile(tc.Paths.Node.Key)
		require.NoError(t, err) // this should never error due to atomic writes

		keyBlock, _ = pem.Decode(updatedKey)
		require.NotNil(t, keyBlock) // this should never error due to atomic writes

		// the new key should be encrypted, and a DEK rotation should have kicked off
		// check that it wasn't just the previous key, encrypted
		derBytes, err := x509.DecryptPEMBlock(keyBlock, unlockKeyResp.UnlockKey)
		require.NoError(t, err) // this should never, because what else would it be re-encrypted with?

		if bytes.Equal(tlsKeyPrivateBytes, derBytes) {
			return fmt.Errorf("TLS key has not been renewed")
		}
		tlsKeyPrivateBytes = derBytes

		if len(keyBlock.Headers) != 3 {
			return fmt.Errorf("DEK not finished rotating")
		}

		return nil
	}, 1*time.Second))

	nowCurrentDEK, err := decodePEMHeaderValue(keyBlock.Headers[pemHeaderRaftDEK], unlockKeyResp.UnlockKey)
	require.NoError(t, err)
	require.NotNil(t, nowCurrentDEK)
	require.NotEqual(t, nowCurrentDEK, currentDEK)

	// verify that the snapshot is readable with the new DEK
	encrypter, decrypter := encryption.Defaults(nowCurrentDEK)
	// we can't use the raftLogger, because the WALs are still locked while the raft node is up.  And once we remove
	// the manager, they'll be deleted.
	snapshot, err := storage.NewSnapFactory(encrypter, decrypter).New(filepath.Join(stateDir, "raft", "snap-v3-encrypted")).Load()
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	// update the lock key to nil
	for i := 0; i < 3; i++ {
		getResp, err := client.GetCluster(ctx, &api.GetClusterRequest{ClusterID: cluster.ID})
		require.NoError(t, err)
		cluster = getResp.Cluster

		spec := cluster.Spec.Copy()
		spec.EncryptionConfig.AutoLockManagers = false
		_, err = client.UpdateCluster(ctx, &api.UpdateClusterRequest{
			ClusterID:      cluster.ID,
			ClusterVersion: &cluster.Meta.Version,
			Spec:           spec,
		})
		if grpc.ErrorDesc(err) == "update out of sequence" {
			continue
		}
		require.NoError(t, err)
	}

	// this should update the TLS key
	var unlockedKey []byte
	require.NoError(t, raftutils.PollFuncWithTimeout(nil, func() error {
		unlockedKey, err = ioutil.ReadFile(tc.Paths.Node.Key)
		if err != nil {
			return err
		}

		if bytes.Equal(unlockedKey, updatedKey) {
			return fmt.Errorf("TLS key should have been rotated")
		}

		return nil
	}, 1*time.Second))

	// the new key should not be encrypted, and the DEK should also be unencrypted
	// but not rotated
	keyBlock, _ = pem.Decode(unlockedKey)
	require.NotNil(t, keyBlock)
	require.False(t, x509.IsEncryptedPEMBlock(keyBlock))
	// check that this is just the previous TLS key, decrypted
	require.Equal(t, tlsKeyPrivateBytes, keyBlock.Bytes)

	unencryptedDEK, err := decodePEMHeaderValue(keyBlock.Headers[pemHeaderRaftDEK], nil)
	require.NoError(t, err)
	require.NotNil(t, unencryptedDEK)
	require.Equal(t, nowCurrentDEK, unencryptedDEK)

	m.Stop(ctx)

	// After stopping we should MAY receive an error from ListenAndServe if
	// all this happened before WaitForLeader completed, so don't check the
	// error.
	<-done
}
