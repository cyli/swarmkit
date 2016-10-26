package manager

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go-events"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/log"
	"github.com/docker/swarmkit/manager/allocator"
	"github.com/docker/swarmkit/manager/controlapi"
	"github.com/docker/swarmkit/manager/dispatcher"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/docker/swarmkit/manager/health"
	"github.com/docker/swarmkit/manager/keymanager"
	"github.com/docker/swarmkit/manager/orchestrator/constraintenforcer"
	"github.com/docker/swarmkit/manager/orchestrator/global"
	"github.com/docker/swarmkit/manager/orchestrator/replicated"
	"github.com/docker/swarmkit/manager/orchestrator/taskreaper"
	"github.com/docker/swarmkit/manager/resourceapi"
	"github.com/docker/swarmkit/manager/scheduler"
	"github.com/docker/swarmkit/manager/state"
	"github.com/docker/swarmkit/manager/state/raft"
	"github.com/docker/swarmkit/manager/state/store"
	"github.com/docker/swarmkit/protobuf/ptypes"
	"github.com/docker/swarmkit/remotes"
	"github.com/docker/swarmkit/xnet"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	// defaultTaskHistoryRetentionLimit is the number of tasks to keep.
	defaultTaskHistoryRetentionLimit = 5
	// the raft DEK (data encryption key) is stored in the TLS key as a header
	// these are the header values
	defaultRaftDEKKey        = "raft-dek"
	defaultRaftDEKKeyPending = "raft-dek-pending"
)

// RemoteAddrs provides an listening address and an optional advertise address
// for serving the remote API.
type RemoteAddrs struct {
	// Address to bind
	ListenAddr string

	// Address to advertise to remote nodes (optional).
	AdvertiseAddr string
}

// Config is used to tune the Manager.
type Config struct {
	SecurityConfig *ca.SecurityConfig

	// ExternalCAs is a list of initial CAs to which a manager node
	// will make certificate signing requests for node certificates.
	ExternalCAs []*api.ExternalCA

	// ControlAPI is an address for serving the control API.
	ControlAPI string

	// RemoteAPI is a listening address for serving the remote API, and
	// an optional advertise address.
	RemoteAPI RemoteAddrs

	// JoinRaft is an optional address of a node in an existing raft
	// cluster to join.
	JoinRaft string

	// Top-level state directory
	StateDir string

	// ForceNewCluster defines if we have to force a new cluster
	// because we are recovering from a backup data directory.
	ForceNewCluster bool

	// ElectionTick defines the amount of ticks needed without
	// leader to trigger a new election
	ElectionTick uint32

	// HeartbeatTick defines the amount of ticks between each
	// heartbeat sent to other members for health-check purposes
	HeartbeatTick uint32

	// AutoLockManagers determines whether or not an unlock key will be generated
	// when bootstrapping a new cluster for the first time
	AutoLockManagers bool

	// UnlockKey is the key to unlock a node - used for decrypting at rest.  This
	// only applies to nodes that have already joined a cluster.
	UnlockKey []byte
}

// Manager is the cluster manager for Swarm.
// This is the high-level object holding and initializing all the manager
// subsystems.
type Manager struct {
	config    *Config
	listeners []net.Listener

	caserver               *ca.Server
	dispatcher             *dispatcher.Dispatcher
	replicatedOrchestrator *replicated.Orchestrator
	globalOrchestrator     *global.Orchestrator
	taskReaper             *taskreaper.TaskReaper
	constraintEnforcer     *constraintenforcer.ConstraintEnforcer
	scheduler              *scheduler.Scheduler
	allocator              *allocator.Allocator
	keyManager             *keymanager.KeyManager
	server                 *grpc.Server
	localserver            *grpc.Server
	raftNode               *raft.Node
	keyRotator             *raftDEKRotator

	cancelFunc context.CancelFunc

	mu      sync.Mutex
	started chan struct{}
	stopped bool
}

type closeOnceListener struct {
	once sync.Once
	net.Listener
}

func (l *closeOnceListener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Listener.Close()
	})
	return err
}

// New creates a Manager which has not started to accept requests yet.
func New(config *Config) (*Manager, error) {
	dispatcherConfig := dispatcher.DefaultConfig()

	// If an AdvertiseAddr was specified, we use that as our
	// externally-reachable address.
	advertiseAddr := config.RemoteAPI.AdvertiseAddr

	var advertiseAddrPort string
	if advertiseAddr == "" {
		// Otherwise, we know we are joining an existing swarm. Use a
		// wildcard address to trigger remote autodetection of our
		// address.
		var err error
		_, advertiseAddrPort, err = net.SplitHostPort(config.RemoteAPI.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("missing or invalid listen address %s", config.RemoteAPI.ListenAddr)
		}

		// Even with an IPv6 listening address, it's okay to use
		// 0.0.0.0 here. Any "unspecified" (wildcard) IP will
		// be substituted with the actual source address.
		advertiseAddr = net.JoinHostPort("0.0.0.0", advertiseAddrPort)
	}

	err := os.MkdirAll(config.StateDir, 0700)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create state directory")
	}

	raftStateDir := filepath.Join(config.StateDir, "raft")
	err = os.MkdirAll(raftStateDir, 0700)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create raft state directory")
	}

	var listeners []net.Listener

	// don't create a socket directory if we're on windows. we used named pipe
	if runtime.GOOS != "windows" {
		err := os.MkdirAll(filepath.Dir(config.ControlAPI), 0700)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create socket directory")
		}
	}

	l, err := xnet.ListenLocal(config.ControlAPI)

	// A unix socket may fail to bind if the file already
	// exists. Try replacing the file.
	if runtime.GOOS != "windows" {
		unwrappedErr := err
		if op, ok := unwrappedErr.(*net.OpError); ok {
			unwrappedErr = op.Err
		}
		if sys, ok := unwrappedErr.(*os.SyscallError); ok {
			unwrappedErr = sys.Err
		}
		if unwrappedErr == syscall.EADDRINUSE {
			os.Remove(config.ControlAPI)
			l, err = xnet.ListenLocal(config.ControlAPI)
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen on control API address")
	}

	listeners = append(listeners, l)

	l, err = net.Listen("tcp", config.RemoteAPI.ListenAddr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen on remote API address")
	}
	if advertiseAddrPort == "0" {
		advertiseAddr = l.Addr().String()
		config.RemoteAPI.ListenAddr = advertiseAddr
	}
	listeners = append(listeners, l)

	raftCfg := raft.DefaultNodeConfig()

	if config.ElectionTick > 0 {
		raftCfg.ElectionTick = int(config.ElectionTick)
	}
	if config.HeartbeatTick > 0 {
		raftCfg.HeartbeatTick = int(config.HeartbeatTick)
	}

	keyRotator := &raftDEKRotator{
		rotationChan: make(chan struct{}),
	}

	newNodeOpts := raft.NodeOptions{
		ID:              config.SecurityConfig.ClientTLSCreds.NodeID(),
		Addr:            advertiseAddr,
		JoinAddr:        config.JoinRaft,
		Config:          raftCfg,
		StateDir:        raftStateDir,
		ForceNewCluster: config.ForceNewCluster,
		TLSCredentials:  config.SecurityConfig.ClientTLSCreds,
		KeyRotator:      keyRotator,
	}
	raftNode := raft.NewNode(newNodeOpts)

	opts := []grpc.ServerOption{
		grpc.Creds(config.SecurityConfig.ServerTLSCreds)}

	m := &Manager{
		config:      config,
		listeners:   listeners,
		caserver:    ca.NewServer(raftNode.MemoryStore(), config.SecurityConfig),
		dispatcher:  dispatcher.New(raftNode, dispatcherConfig),
		server:      grpc.NewServer(opts...),
		localserver: grpc.NewServer(opts...),
		raftNode:    raftNode,
		started:     make(chan struct{}),
		keyRotator:  keyRotator,
	}

	return m, nil
}

// Addr returns tcp address on which remote api listens.
func (m *Manager) Addr() string {
	return m.config.RemoteAPI.ListenAddr
}

// Run starts all manager sub-systems and the gRPC server at the configured
// address.
// The call never returns unless an error occurs or `Stop()` is called.
func (m *Manager) Run(parent context.Context) error {
	ctx, ctxCancel := context.WithCancel(parent)
	defer ctxCancel()

	m.cancelFunc = ctxCancel

	leadershipCh, cancel := m.raftNode.SubscribeLeadership()
	defer cancel()

	go m.handleLeadershipEvents(ctx, leadershipCh)

	authorize := func(ctx context.Context, roles []string) error {
		var (
			blacklistedCerts map[string]*api.BlacklistedCertificate
			clusters         []*api.Cluster
			err              error
		)

		m.raftNode.MemoryStore().View(func(readTx store.ReadTx) {
			clusters, err = store.FindClusters(readTx, store.ByName("default"))

		})

		// Not having a cluster object yet means we can't check
		// the blacklist.
		if err == nil && len(clusters) == 1 {
			blacklistedCerts = clusters[0].BlacklistedCertificates
		}

		// Authorize the remote roles, ensure they can only be forwarded by managers
		_, err = ca.AuthorizeForwardedRoleAndOrg(ctx, roles, []string{ca.ManagerRole}, m.config.SecurityConfig.ClientTLSCreds.Organization(), blacklistedCerts)
		return err
	}

	baseControlAPI := controlapi.NewServer(m.raftNode.MemoryStore(), m.raftNode, m.config.SecurityConfig.RootCA())
	baseResourceAPI := resourceapi.New(m.raftNode.MemoryStore())
	healthServer := health.NewHealthServer()
	localHealthServer := health.NewHealthServer()

	authenticatedControlAPI := api.NewAuthenticatedWrapperControlServer(baseControlAPI, authorize)
	authenticatedResourceAPI := api.NewAuthenticatedWrapperResourceAllocatorServer(baseResourceAPI, authorize)
	authenticatedDispatcherAPI := api.NewAuthenticatedWrapperDispatcherServer(m.dispatcher, authorize)
	authenticatedCAAPI := api.NewAuthenticatedWrapperCAServer(m.caserver, authorize)
	authenticatedNodeCAAPI := api.NewAuthenticatedWrapperNodeCAServer(m.caserver, authorize)
	authenticatedRaftAPI := api.NewAuthenticatedWrapperRaftServer(m.raftNode, authorize)
	authenticatedHealthAPI := api.NewAuthenticatedWrapperHealthServer(healthServer, authorize)
	authenticatedRaftMembershipAPI := api.NewAuthenticatedWrapperRaftMembershipServer(m.raftNode, authorize)

	proxyDispatcherAPI := api.NewRaftProxyDispatcherServer(authenticatedDispatcherAPI, m.raftNode, ca.WithMetadataForwardTLSInfo)
	proxyCAAPI := api.NewRaftProxyCAServer(authenticatedCAAPI, m.raftNode, ca.WithMetadataForwardTLSInfo)
	proxyNodeCAAPI := api.NewRaftProxyNodeCAServer(authenticatedNodeCAAPI, m.raftNode, ca.WithMetadataForwardTLSInfo)
	proxyRaftMembershipAPI := api.NewRaftProxyRaftMembershipServer(authenticatedRaftMembershipAPI, m.raftNode, ca.WithMetadataForwardTLSInfo)
	proxyResourceAPI := api.NewRaftProxyResourceAllocatorServer(authenticatedResourceAPI, m.raftNode, ca.WithMetadataForwardTLSInfo)

	// localProxyControlAPI is a special kind of proxy. It is only wired up
	// to receive requests from a trusted local socket, and these requests
	// don't use TLS, therefore the requests it handles locally should
	// bypass authorization. When it proxies, it sends them as requests from
	// this manager rather than forwarded requests (it has no TLS
	// information to put in the metadata map).
	forwardAsOwnRequest := func(ctx context.Context) (context.Context, error) { return ctx, nil }
	localProxyControlAPI := api.NewRaftProxyControlServer(baseControlAPI, m.raftNode, forwardAsOwnRequest)

	// Everything registered on m.server should be an authenticated
	// wrapper, or a proxy wrapping an authenticated wrapper!
	api.RegisterCAServer(m.server, proxyCAAPI)
	api.RegisterNodeCAServer(m.server, proxyNodeCAAPI)
	api.RegisterRaftServer(m.server, authenticatedRaftAPI)
	api.RegisterHealthServer(m.server, authenticatedHealthAPI)
	api.RegisterRaftMembershipServer(m.server, proxyRaftMembershipAPI)
	api.RegisterControlServer(m.server, authenticatedControlAPI)
	api.RegisterResourceAllocatorServer(m.server, proxyResourceAPI)
	api.RegisterDispatcherServer(m.server, proxyDispatcherAPI)

	api.RegisterControlServer(m.localserver, localProxyControlAPI)
	api.RegisterHealthServer(m.localserver, localHealthServer)

	healthServer.SetServingStatus("Raft", api.HealthCheckResponse_NOT_SERVING)
	localHealthServer.SetServingStatus("ControlAPI", api.HealthCheckResponse_NOT_SERVING)

	errServe := make(chan error, len(m.listeners))
	for _, lis := range m.listeners {
		go m.serveListener(ctx, errServe, lis)
	}

	defer func() {
		m.server.Stop()
		m.localserver.Stop()
	}()

	// Set the raft server as serving for the health server
	healthServer.SetServingStatus("Raft", api.HealthCheckResponse_SERVING)

	if err := m.joinAndStart(ctx); err != nil {
		return errors.Wrap(err, "can't initialize raft node")
	}
	m.keyRotator.SetKeyWriter(m.config.SecurityConfig.KeyWriter())

	localHealthServer.SetServingStatus("ControlAPI", api.HealthCheckResponse_SERVING)

	close(m.started)

	go m.watchForKEKChanges(ctx)

	go func() {
		if m.keyRotator.GetNewKey() != nil {
			m.keyRotator.rotationChan <- struct{}{}
		}
		err := m.raftNode.Run(ctx)
		if err != nil {
			log.G(ctx).Error(err)
			m.Stop(ctx)
			if err == raft.ErrMemberRemoved {
				if err := m.config.SecurityConfig.KeyWriter().UpdateHeaders(func(headers map[string]string, _ []byte) error {
					delete(headers, defaultRaftDEKKey)
					delete(headers, defaultRaftDEKKeyPending)
					return nil
				}); err != nil {
					log.G(ctx).Error(errors.Wrap(err, "unable to remove raft DEK from TLS key"))
				}
			}
		}
	}()

	if err := raft.WaitForLeader(ctx, m.raftNode); err != nil {
		return err
	}

	c, err := raft.WaitForCluster(ctx, m.raftNode)
	if err != nil {
		return err
	}
	raftConfig := c.Spec.Raft

	if int(raftConfig.ElectionTick) != m.raftNode.Config.ElectionTick {
		log.G(ctx).Warningf("election tick value (%ds) is different from the one defined in the cluster config (%vs), the cluster may be unstable", m.raftNode.Config.ElectionTick, raftConfig.ElectionTick)
	}
	if int(raftConfig.HeartbeatTick) != m.raftNode.Config.HeartbeatTick {
		log.G(ctx).Warningf("heartbeat tick value (%ds) is different from the one defined in the cluster config (%vs), the cluster may be unstable", m.raftNode.Config.HeartbeatTick, raftConfig.HeartbeatTick)
	}

	// wait for an error in serving.
	err = <-errServe
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	m.Stop(ctx)
	return err
}

const stopTimeout = 8 * time.Second

// Stop stops the manager. It immediately closes all open connections and
// active RPCs as well as stopping the scheduler.
func (m *Manager) Stop(ctx context.Context) {
	log.G(ctx).Info("Stopping manager")
	// It's not safe to start shutting down while the manager is still
	// starting up.
	<-m.started

	// the mutex stops us from trying to stop while we're alrady stopping, or
	// from returning before we've finished stopping.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	m.stopped = true

	srvDone, localSrvDone := make(chan struct{}), make(chan struct{})
	go func() {
		m.server.GracefulStop()
		close(srvDone)
	}()
	go func() {
		m.localserver.GracefulStop()
		close(localSrvDone)
	}()

	m.dispatcher.Stop()
	m.caserver.Stop()

	if m.allocator != nil {
		m.allocator.Stop()
	}
	if m.replicatedOrchestrator != nil {
		m.replicatedOrchestrator.Stop()
	}
	if m.globalOrchestrator != nil {
		m.globalOrchestrator.Stop()
	}
	if m.taskReaper != nil {
		m.taskReaper.Stop()
	}
	if m.constraintEnforcer != nil {
		m.constraintEnforcer.Stop()
	}
	if m.scheduler != nil {
		m.scheduler.Stop()
	}
	if m.keyManager != nil {
		m.keyManager.Stop()
	}

	m.cancelFunc()
	<-m.raftNode.Done()

	timer := time.AfterFunc(stopTimeout, func() {
		m.server.Stop()
		m.localserver.Stop()
	})
	defer timer.Stop()
	// TODO: we're not waiting on ctx because it very well could be passed from Run,
	// which is already cancelled here. We need to refactor that.
	select {
	case <-srvDone:
		<-localSrvDone
	case <-localSrvDone:
		<-srvDone
	}

	log.G(ctx).Info("Manager shut down")
	// mutex is released and Run can return now
}

func (m *Manager) joinAndStart(ctx context.Context) error {
	return m.config.SecurityConfig.KeyWriter().UpdateHeaders(func(headers map[string]string, kek []byte) error {
		if err := m.keyRotator.LoadFromHeaders(headers, kek); err != nil {
			return err
		}

		// if there is no DEK, create a new one
		dekStr, foundDEK := headers[defaultRaftDEKKey]
		if !foundDEK {
			newDEK := encryption.GenerateSecretKey()
			var err error
			if headers[defaultRaftDEKKey], err = encodePEMHeaderValue(newDEK, kek); err != nil {
				return err
			}
			return m.raftNode.JoinAndStart(ctx, newDEK)
		}

		if pendingKey := m.keyRotator.GetNewKey(); pendingKey != nil {
			// if there is a pending header, try decrypting with that first - if that doesn't work, fall back
			// on the normal dek but finish rotating
			err := m.raftNode.JoinAndStart(ctx, pendingKey)
			switch errors.Cause(err).(type) {
			case encryption.ErrCannotDecrypt:
				// if the dek hasn't been used to snapshot, fall back to the original dek - a rotation
				// still needs to happen
				break
			case nil:
				// we've successfully joined - that means the previous snapshot had succeeded - finish
				// the rotation
				return m.keyRotator.FinishKeyRotation(pendingKey)
			default:
				// we failed to join but not due to a decoding error
				return err
			}
		}

		// there is a regular header - use that to decrypt and start
		dek, err := decodePEMHeaderValue(dekStr, kek)
		if err != nil {
			return err
		}
		return m.raftNode.JoinAndStart(ctx, dek)
	})
}

func (m *Manager) watchForKEKChanges(ctx context.Context) {
	clusterWatch, clusterWatchCancel := state.Watch(m.raftNode.MemoryStore().WatchQueue(),
		state.EventUpdateCluster{},
	)
	securityConfig := m.config.SecurityConfig
	nodeID := m.config.SecurityConfig.ClientTLSCreds.NodeID()
	logger := log.G(ctx).WithFields(logrus.Fields{
		"node.id":   nodeID,
		"node.role": ca.ManagerRole,
	})

	// we are our own peer from which we get certs - try to connect over the local socket
	r := remotes.NewRemotes(api.Peer{Addr: m.Addr(), NodeID: nodeID})
	defer clusterWatchCancel()
	for {
		select {
		case event := <-clusterWatch:
			clusterEvent := event.(state.EventUpdateCluster)
			kek := clusterEvent.Cluster.UnlockKeys.Manager
			switch {
			case subtle.ConstantTimeCompare(kek, m.keyRotator.GetCurrentKEK()) == 1:
				// if the KEK hasn't changed, do nothing
				continue
			case m.keyRotator.GetCurrentKEK() == nil:
				// it was previously unencrypted, and now needs to be encrypted - trigger
				// a full rotation of the TLS keys too
				if err := ca.RenewTLSConfigNow(ctx, securityConfig, r, nil); err != nil {
					continue
				}
				// Now that we have a new TLS certificate, let's load it from disk and
				// update our key rotator
				headers, _, err := securityConfig.KeyReader().ReadHeaders()
				if err != nil {
					logger.WithError(err).Errorf("failed to read refreshed TLS key from disk")
					continue
				}
				m.keyRotator.LoadFromHeaders(headers, kek)
				// trigger a raft DEK rotation
				m.keyRotator.RotationNotify() <- struct{}{}
			default:
				// the kek has just changed - all we just to do is re-encrypt the DEK and the cert
				if err := securityConfig.KeyWriter().RotateKEK(kek); err != nil {
					logger.WithError(err).Errorf("failed to re-encrypt TLS key")
					continue
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// rotateRootCAKEK will attempt to rotate the key-encryption-key for root CA key-material in raft.
// If there is no passphrase set in ENV, it returns.
// If there is plain-text root key-material, and a passphrase set, it encrypts it.
// If there is encrypted root key-material and it is using the current passphrase, it returns.
// If there is encrypted root key-material, and it is using the previous passphrase, it
// re-encrypts it with the current passphrase.
func (m *Manager) rotateRootCAKEK(ctx context.Context, clusterID string) error {
	// If we don't have a KEK, we won't ever be rotating anything
	strPassphrase := os.Getenv(ca.PassphraseENVVar)
	if strPassphrase == "" {
		return nil
	}
	strPassphrasePrev := os.Getenv(ca.PassphraseENVVarPrev)
	passphrase := []byte(strPassphrase)
	passphrasePrev := []byte(strPassphrasePrev)

	s := m.raftNode.MemoryStore()
	var (
		cluster  *api.Cluster
		err      error
		finalKey []byte
	)
	// Retrieve the cluster identified by ClusterID
	s.View(func(readTx store.ReadTx) {
		cluster = store.GetCluster(readTx, clusterID)
	})
	if cluster == nil {
		return fmt.Errorf("cluster not found: %s", clusterID)
	}

	// Try to get the private key from the cluster
	privKeyPEM := cluster.RootCA.CAKey
	if len(privKeyPEM) == 0 {
		// We have no PEM root private key in this cluster.
		log.G(ctx).Warnf("cluster %s does not have private key material", clusterID)
		return nil
	}

	// Decode the PEM private key
	keyBlock, _ := pem.Decode(privKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("invalid PEM-encoded private key inside of cluster %s", clusterID)
	}
	// If this key is not encrypted, then we have to encrypt it
	if !x509.IsEncryptedPEMBlock(keyBlock) {
		finalKey, err = ca.EncryptECPrivateKey(privKeyPEM, strPassphrase)
		if err != nil {
			return err
		}
	} else {
		// This key is already encrypted, let's try to decrypt with the current main passphrase
		_, err = x509.DecryptPEMBlock(keyBlock, []byte(passphrase))
		if err == nil {
			// The main key is the correct KEK, nothing to do here
			return nil
		}
		// This key is already encrypted, but failed with current main passphrase.
		// Let's try to decrypt with the previous passphrase
		unencryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(passphrasePrev))
		if err != nil {
			// We were not able to decrypt either with the main or backup passphrase, error
			return err
		}
		unencryptedKeyBlock := &pem.Block{
			Type:    keyBlock.Type,
			Bytes:   unencryptedKey,
			Headers: keyBlock.Headers,
		}

		// We were able to decrypt the key, but with the previous passphrase. Let's encrypt
		// with the new one and store it in raft
		finalKey, err = ca.EncryptECPrivateKey(pem.EncodeToMemory(unencryptedKeyBlock), strPassphrase)
		if err != nil {
			log.G(ctx).Debugf("failed to rotate the key-encrypting-key for the root key material of cluster %s", clusterID)
			return err
		}
	}

	log.G(ctx).Infof("Re-encrypting the root key material of cluster %s", clusterID)
	// Let's update the key in the cluster object
	return s.Update(func(tx store.Tx) error {
		cluster = store.GetCluster(tx, clusterID)
		if cluster == nil {
			return fmt.Errorf("cluster not found: %s", clusterID)
		}
		cluster.RootCA.CAKey = finalKey
		return store.UpdateCluster(tx, cluster)
	})

}

// handleLeadershipEvents handles the is leader event or is follower event.
func (m *Manager) handleLeadershipEvents(ctx context.Context, leadershipCh chan events.Event) {
	for {
		select {
		case leadershipEvent := <-leadershipCh:
			m.mu.Lock()
			if m.stopped {
				m.mu.Unlock()
				return
			}
			newState := leadershipEvent.(raft.LeadershipState)

			if newState == raft.IsLeader {
				m.becomeLeader(ctx)
			} else if newState == raft.IsFollower {
				m.becomeFollower()
			}
			m.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

// serveListener serves a listener for local and non local connections.
func (m *Manager) serveListener(ctx context.Context, errServe chan error, l net.Listener) {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(
		logrus.Fields{
			"proto": l.Addr().Network(),
			"addr":  l.Addr().String(),
		}))
	if _, ok := l.(*net.TCPListener); !ok {
		log.G(ctx).Info("Listening for local connections")
		// we need to disallow double closes because UnixListener.Close
		// can delete unix-socket file of newer listener. grpc calls
		// Close twice indeed: in Serve and in Stop.
		errServe <- m.localserver.Serve(&closeOnceListener{Listener: l})
	} else {
		log.G(ctx).Info("Listening for connections")
		errServe <- m.server.Serve(l)
	}
}

// becomeLeader starts the subsystems that are run on the leader.
func (m *Manager) becomeLeader(ctx context.Context) {
	s := m.raftNode.MemoryStore()

	rootCA := m.config.SecurityConfig.RootCA()
	nodeID := m.config.SecurityConfig.ClientTLSCreds.NodeID()

	raftCfg := raft.DefaultRaftConfig()
	raftCfg.ElectionTick = uint32(m.raftNode.Config.ElectionTick)
	raftCfg.HeartbeatTick = uint32(m.raftNode.Config.HeartbeatTick)

	clusterID := m.config.SecurityConfig.ClientTLSCreds.Organization()

	initialCAConfig := ca.DefaultCAConfig()
	initialCAConfig.ExternalCAs = m.config.ExternalCAs

	s.Update(func(tx store.Tx) error {
		// Add a default cluster object to the
		// store. Don't check the error because
		// we expect this to fail unless this
		// is a brand new cluster.
		store.CreateCluster(tx, defaultClusterObject(
			clusterID,
			initialCAConfig,
			raftCfg,
			api.EncryptionConfig{AutoLockManagers: m.config.AutoLockManagers},
			api.UnlockKeys{Manager: m.config.UnlockKey},
			rootCA))
		// Add Node entry for ourself, if one
		// doesn't exist already.
		store.CreateNode(tx, managerNode(nodeID))
		return nil
	})

	// Attempt to rotate the key-encrypting-key of the root CA key-material
	err := m.rotateRootCAKEK(ctx, clusterID)
	if err != nil {
		log.G(ctx).WithError(err).Error("root key-encrypting-key rotation failed")
	}

	m.replicatedOrchestrator = replicated.NewReplicatedOrchestrator(s)
	m.constraintEnforcer = constraintenforcer.New(s)
	m.globalOrchestrator = global.NewGlobalOrchestrator(s)
	m.taskReaper = taskreaper.New(s)
	m.scheduler = scheduler.New(s)
	m.keyManager = keymanager.New(s, keymanager.DefaultConfig())

	// TODO(stevvooe): Allocate a context that can be used to
	// shutdown underlying manager processes when leadership is
	// lost.

	m.allocator, err = allocator.New(s)
	if err != nil {
		log.G(ctx).WithError(err).Error("failed to create allocator")
		// TODO(stevvooe): It doesn't seem correct here to fail
		// creating the allocator but then use it anyway.
	}

	if m.keyManager != nil {
		go func(keyManager *keymanager.KeyManager) {
			if err := keyManager.Run(ctx); err != nil {
				log.G(ctx).WithError(err).Error("keymanager failed with an error")
			}
		}(m.keyManager)
	}

	go func(d *dispatcher.Dispatcher) {
		if err := d.Run(ctx); err != nil {
			log.G(ctx).WithError(err).Error("Dispatcher exited with an error")
		}
	}(m.dispatcher)

	go func(server *ca.Server) {
		if err := server.Run(ctx); err != nil {
			log.G(ctx).WithError(err).Error("CA signer exited with an error")
		}
	}(m.caserver)

	// Start all sub-components in separate goroutines.
	// TODO(aluzzardi): This should have some kind of error handling so that
	// any component that goes down would bring the entire manager down.
	if m.allocator != nil {
		go func(allocator *allocator.Allocator) {
			if err := allocator.Run(ctx); err != nil {
				log.G(ctx).WithError(err).Error("allocator exited with an error")
			}
		}(m.allocator)
	}

	go func(scheduler *scheduler.Scheduler) {
		if err := scheduler.Run(ctx); err != nil {
			log.G(ctx).WithError(err).Error("scheduler exited with an error")
		}
	}(m.scheduler)

	go func(constraintEnforcer *constraintenforcer.ConstraintEnforcer) {
		constraintEnforcer.Run()
	}(m.constraintEnforcer)

	go func(taskReaper *taskreaper.TaskReaper) {
		taskReaper.Run()
	}(m.taskReaper)

	go func(orchestrator *replicated.Orchestrator) {
		if err := orchestrator.Run(ctx); err != nil {
			log.G(ctx).WithError(err).Error("replicated orchestrator exited with an error")
		}
	}(m.replicatedOrchestrator)

	go func(globalOrchestrator *global.Orchestrator) {
		if err := globalOrchestrator.Run(ctx); err != nil {
			log.G(ctx).WithError(err).Error("global orchestrator exited with an error")
		}
	}(m.globalOrchestrator)

}

// becomeFollower shuts down the subsystems that are only run by the leader.
func (m *Manager) becomeFollower() {
	m.dispatcher.Stop()
	m.caserver.Stop()

	if m.allocator != nil {
		m.allocator.Stop()
		m.allocator = nil
	}

	m.constraintEnforcer.Stop()
	m.constraintEnforcer = nil

	m.replicatedOrchestrator.Stop()
	m.replicatedOrchestrator = nil

	m.globalOrchestrator.Stop()
	m.globalOrchestrator = nil

	m.taskReaper.Stop()
	m.taskReaper = nil

	m.scheduler.Stop()
	m.scheduler = nil

	if m.keyManager != nil {
		m.keyManager.Stop()
		m.keyManager = nil
	}
}

// defaultClusterObject creates a default cluster.
func defaultClusterObject(
	clusterID string,
	initialCAConfig api.CAConfig,
	raftCfg api.RaftConfig,
	encryptionConfig api.EncryptionConfig,
	initialUnlockKeys api.UnlockKeys,
	rootCA *ca.RootCA) *api.Cluster {

	return &api.Cluster{
		ID: clusterID,
		Spec: api.ClusterSpec{
			Annotations: api.Annotations{
				Name: store.DefaultClusterName,
			},
			Orchestration: api.OrchestrationConfig{
				TaskHistoryRetentionLimit: defaultTaskHistoryRetentionLimit,
			},
			Dispatcher: api.DispatcherConfig{
				HeartbeatPeriod: ptypes.DurationProto(dispatcher.DefaultHeartBeatPeriod),
			},
			Raft:             raftCfg,
			CAConfig:         initialCAConfig,
			EncryptionConfig: encryptionConfig,
		},
		RootCA: api.RootCA{
			CAKey:      rootCA.Key,
			CACert:     rootCA.Cert,
			CACertHash: rootCA.Digest.String(),
			JoinTokens: api.JoinTokens{
				Worker:  ca.GenerateJoinToken(rootCA),
				Manager: ca.GenerateJoinToken(rootCA),
			},
		},
		UnlockKeys: initialUnlockKeys,
	}
}

// managerNode creates a new node with NodeRoleManager role.
func managerNode(nodeID string) *api.Node {
	return &api.Node{
		ID: nodeID,
		Certificate: api.Certificate{
			CN:   nodeID,
			Role: api.NodeRoleManager,
			Status: api.IssuanceStatus{
				State: api.IssuanceStateIssued,
			},
		},
		Spec: api.NodeSpec{
			Role:       api.NodeRoleManager,
			Membership: api.NodeMembershipAccepted,
		},
	}
}

// raftDEKRotator manages the raft DEK keys using TLS headers
type raftDEKRotator struct {
	mu           sync.Mutex
	currentKEK   []byte
	nextDEK      []byte
	rotationChan chan struct{}
	kw           ca.KeyWriter
}

func (r *raftDEKRotator) GetCurrentKEK() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentKEK
}

func (r *raftDEKRotator) SetKeyWriter(kw ca.KeyWriter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kw = kw
}

func (r *raftDEKRotator) GetNewKey() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextDEK
}

func (r *raftDEKRotator) RotationNotify() chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotationChan
}

func (r *raftDEKRotator) FinishKeyRotation(key []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if subtle.ConstantTimeCompare(key, r.nextDEK) == 1 {
		r.nextDEK = nil
	}
	if r.kw != nil {
		return r.kw.UpdateHeaders(func(headers map[string]string, kek []byte) error {
			r.currentKEK = kek
			// no matter what, set the current key
			headerStr, err := encodePEMHeaderValue(key, kek)
			if err != nil {
				return err
			}
			headers[defaultRaftDEKKey] = headerStr

			if pendingDEKStr, ok := headers[defaultRaftDEKKeyPending]; ok {
				pendingKey, err := decodePEMHeaderValue(pendingDEKStr, kek)
				if err != nil {
					return err
				}
				// another queued rotation
				if subtle.ConstantTimeCompare(key, pendingKey) == 0 {
					r.nextDEK = pendingKey
				} else {
					delete(headers, defaultRaftDEKKeyPending)
				}
			}
			return nil
		})
	}
	return nil
}

func (r *raftDEKRotator) LoadFromHeaders(headers map[string]string, kek []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, foundDEK := headers[defaultRaftDEKKey]
	pendingDEKStr, foundPendingDEK := headers[defaultRaftDEKKeyPending]
	if !foundDEK {
		if foundPendingDEK {
			return fmt.Errorf("there is a pending DEK but no current DEK")
		}
	}
	if foundPendingDEK {
		pendingKey, err := decodePEMHeaderValue(pendingDEKStr, kek)
		if err != nil {
			return err
		}
		r.nextDEK = pendingKey
	}
	r.currentKEK = kek
	return nil
}

func decodePEMHeaderValue(headerValue string, kek []byte) ([]byte, error) {
	var decrypter encryption.Decrypter = encryption.NoopCrypter
	if kek != nil {
		_, decrypter = encryption.Defaults(kek)
	}
	valueBytes, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, err
	}
	return encryption.Decrypt(valueBytes, decrypter)
}

func encodePEMHeaderValue(headerValue []byte, kek []byte) (string, error) {
	var encrypter encryption.Encrypter = encryption.NoopCrypter
	if kek != nil {
		encrypter, _ = encryption.Defaults(kek)
	}
	encrypted, err := encryption.Encrypt(headerValue, encrypter)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// MaintainEncryptedPEMHeaders takes a set of PEM headers, and ensures that the manager raft DEK pem headers
// are always encrypted correctly.
func MaintainEncryptedPEMHeaders(headers map[string]string, oldKEK, newKEK []byte) error {
	if subtle.ConstantTimeCompare(oldKEK, newKEK) == 1 {
		// don't bother re-encrypting anything if the keys have not changed
		return nil
	}

	dekStr, foundDEK := headers[defaultRaftDEKKey]

	// re-encrypt the current DEK
	if foundDEK {
		decodedValue, err := decodePEMHeaderValue(dekStr, oldKEK)
		if err != nil {
			return err
		}
		if headers[defaultRaftDEKKey], err = encodePEMHeaderValue(decodedValue, newKEK); err != nil {
			return err
		}
	}

	pendingDEKStr, foundPendingDEK := headers[defaultRaftDEKKeyPending]

	switch {
	case foundPendingDEK:
		// also re-encrypt the pending DEK, if that hasn't been updated yet
		decodedValue, err := decodePEMHeaderValue(pendingDEKStr, oldKEK)
		if err != nil {
			return err
		}
		if headers[defaultRaftDEKKeyPending], err = encodePEMHeaderValue(decodedValue, newKEK); err != nil {
			return err
		}

	case foundDEK && oldKEK == nil:
		// if there is a DEK, it should be rotated since the DEK was previously not encrypted with a KEK
		newDEK := encryption.GenerateSecretKey()
		var err error
		if headers[defaultRaftDEKKeyPending], err = encodePEMHeaderValue(newDEK, newKEK); err != nil {
			return err
		}
	}
	return nil
}
