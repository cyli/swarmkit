package controlapi

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/ca/testutils"
	"github.com/docker/swarmkit/manager/state/store"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type rootCARotationTestCase struct {
	cluster             api.Cluster
	rotationRequest     api.KeyRotation
	expectRootCA        api.RootCA
	expectRotationState *api.RootRotationState
	expectErrorString   string
	description         string
}

func getRootCAObj(t *testing.T, cert, key []byte) api.RootCA {
	rootCA, err := getAPIRootCA(cert, key)
	require.NoError(t, err)
	return rootCA
}

func getClusterSpecWithExternal(certs ...[]byte) api.ClusterSpec {
	var externals []*api.ExternalCA
	for _, cert := range certs {
		externals = append(externals,
			&api.ExternalCA{
				URL:        "https://externalca.com",
				CACertHash: digest.FromBytes(cert).String(),
			},
		)
	}
	return api.ClusterSpec{
		CAConfig: api.CAConfig{
			ExternalCAs: externals,
		},
	}
}

func TestValidateAndStartRotationValidRotationCertProvided(t *testing.T) {
	cert, key := testutils.ECDSA256SHA256Cert, testutils.ECDSA256Key
	startRootCA := getRootCAObj(t, cert, key)
	startRootCANoKey := startRootCA
	startRootCANoKey.CAKey = nil

	otherCert, otherKey, err := testutils.CreateRootCertAndKey("rootCN")
	require.NoError(t, err)

	priv, err := helpers.ParsePrivateKeyPEM(key)
	require.NoError(t, err)
	certParsed, err := helpers.ParseCertificatePEM(cert)
	require.NoError(t, err)

	similarCert, err := initca.RenewFromSigner(certParsed, priv)
	require.NoError(t, err)
	require.NotEqual(t, cert, similarCert)
	alternateCert, _, err := initca.NewFromSigner(&csr.CertificateRequest{CN: "other CN"}, priv)
	require.NoError(t, err)

	// Not going to bother adding the spec in the expected cluster - we're just going to test to make sure the spec
	// doesn't get changed, since it shouldn't be updatable except by the user
	testCases := []rootCARotationTestCase{
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				// leaving out the root rotation boolean causes the rest to be ignored
				RootCACert: otherCert,
				RootCAKey:  otherKey,
			},
			expectRootCA: startRootCA,
			description:  "not rotating at all",
		},
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     cert,
				RootCAKey:      key,
			},
			expectRootCA: startRootCA,
			description:  "rotating to the exact same cert and key results in no error, but no rotation change",
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				Spec:   getClusterSpecWithExternal(cert),
			},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     cert,
			},
			expectRootCA: startRootCA,
			description:  "rotating to the exact same cert but external CA results in no error, but no rotation change",
		},
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     similarCert,
				RootCAKey:      key,
			},
			expectRootCA: getRootCAObj(t, similarCert, key),
			description:  "rotating to a cert with the same subject and key results in a replacement of the root, but no rotation process",
		},
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     alternateCert,
				RootCAKey:      key,
			},
			expectRootCA: getRootCAObj(t, append(cert, alternateCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_CertificateRotation,
				NewCACert: alternateCert,
				NewCAKey:  key,
				OldCACert: cert,
				OldCAKey:  key,
			},
			description: "rotating to a cert with the same key but a different subject results in starting the root rotation process",
		},
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
				RootCAKey:      otherKey,
			},
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_CertificateRotation,
				NewCACert: otherCert,
				NewCAKey:  otherKey,
				OldCACert: cert,
				OldCAKey:  key,
			},
			description: "rotating from internal CA -> internal CA",
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				Spec:   getClusterSpecWithExternal(otherCert),
			},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
			},
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_CertificateRotation,
				NewCACert: otherCert,
				OldCACert: cert,
				OldCAKey:  key,
			},
			description: "rotating from internal CA -> external CA",
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCANoKey,
				Spec:   getClusterSpecWithExternal(cert, otherCert),
			},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
			},
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), nil),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_CertificateRotation,
				NewCACert: otherCert,
				OldCACert: cert,
			},
			description: "rotating from external CA -> external CA",
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCANoKey,
				Spec:   getClusterSpecWithExternal(cert),
			},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
				RootCAKey:      otherKey,
			},
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), nil),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_CertificateRotation,
				NewCACert: otherCert,
				NewCAKey:  otherKey,
				OldCACert: cert,
			},
			description: "rotating from external CA -> internal CA",
		},
	}

	for _, testCase := range testCases {
		startCluster := testCase.cluster
		require.NoError(t, validateAndMaybeStartRootRotation(&testCase.cluster, testCase.rotationRequest), testCase.description)

		// we can't just compare the expected cluster with the regular cluster, since the join tokens are randomly
		// generated - if the rootCA hasn't changed, ensure the join tokens haven't changed
		if bytes.Equal(testCase.cluster.RootCA.CACert, startCluster.RootCA.CACert) {
			require.Equal(t, startCluster.RootCA.JoinTokens, testCase.cluster.RootCA.JoinTokens, testCase.description)
		} else {
			require.NotEqual(t, startCluster.RootCA.JoinTokens, testCase.cluster.RootCA.JoinTokens, testCase.description)
		}
		testCase.cluster.RootCA.JoinTokens = testCase.expectRootCA.JoinTokens
		require.Equal(t, testCase.expectRootCA, testCase.cluster.RootCA, testCase.description)
		require.Equal(t, startCluster.Spec, testCase.cluster.Spec, testCase.description)

		if testCase.expectRotationState != nil {
			require.NotNil(t, testCase.cluster.RootRotationState, testCase.description)
			require.Equal(t, *testCase.expectRotationState, *testCase.cluster.RootRotationState, testCase.description)
		}
	}
}

func TestValidateAndStartRotationValidRotationGenerateCertOrKey(t *testing.T) {
	// Can't as easily just use a table test here, because half the values are generated and random

	cert, key := testutils.ECDSA256SHA256Cert, testutils.ECDSA256Key
	startRootCA := getRootCAObj(t, cert, key)

	_, otherKey, err := testutils.CreateRootCertAndKey("rootCN")
	require.NoError(t, err)

	// rotating to the exact same key, a new cert will be generated based on the old cert, and can just replace
	// old cert without beginning a root rotation process
	cluster := &api.Cluster{RootCA: startRootCA}
	require.NoError(t, validateAndMaybeStartRootRotation(cluster, api.KeyRotation{
		RootCARotation: true,
		RootCAKey:      key,
	}))
	require.Nil(t, cluster.RootRotationState)
	require.Equal(t, key, cluster.RootCA.CAKey)
	require.NotEqual(t, cert, cluster.RootCA.CACert)
	parsedCert, err := helpers.ParseCertificatePEM(cert)
	require.NoError(t, err)
	parsedGenerated, err := helpers.ParseCertificatePEM(cluster.RootCA.CACert)
	require.NoError(t, err)
	require.Equal(t, parsedCert.RawSubject, parsedGenerated.RawSubject)
	require.Equal(t, parsedCert.PublicKey, parsedGenerated.PublicKey)

	// rotating to a new key, a new cert will be generated and the root rotation process kicked off
	cluster = &api.Cluster{RootCA: startRootCA}
	require.NoError(t, validateAndMaybeStartRootRotation(cluster, api.KeyRotation{
		RootCARotation: true,
		RootCAKey:      otherKey,
	}))
	require.NotNil(t, cluster.RootRotationState)
	require.NotNil(t, cluster.RootRotationState.NewCACert)
	require.Equal(t, api.RootRotationState{
		State:     api.RootRotationState_CertificateRotation,
		NewCACert: cluster.RootRotationState.NewCACert,
		NewCAKey:  otherKey,
		OldCACert: cert,
		OldCAKey:  key,
	}, *cluster.RootRotationState)
	require.Equal(t, key, cluster.RootCA.CAKey)
	require.Equal(t, append(cert, cluster.RootRotationState.NewCACert...), cluster.RootCA.CACert)

	// rotating without providing a key or cert means a key and cert will be generated, and the root rotation
	// process kicked off
	cluster = &api.Cluster{RootCA: startRootCA}
	require.NoError(t, validateAndMaybeStartRootRotation(cluster, api.KeyRotation{
		RootCARotation: true,
	}))
	require.NotNil(t, cluster.RootRotationState)
	require.NotNil(t, cluster.RootRotationState.NewCACert)
	require.NotNil(t, cluster.RootRotationState.NewCAKey)
	require.Equal(t, api.RootRotationState{
		State:     api.RootRotationState_CertificateRotation,
		NewCACert: cluster.RootRotationState.NewCACert,
		NewCAKey:  cluster.RootRotationState.NewCAKey,
		OldCACert: cert,
		OldCAKey:  key,
	}, *cluster.RootRotationState)
	require.Equal(t, key, cluster.RootCA.CAKey)
	require.Equal(t, append(cert, cluster.RootRotationState.NewCACert...), cluster.RootCA.CACert)
}

func TestValidateAndStartRotationInvalidRotations(t *testing.T) {
	cert, key, err := testutils.CreateRootCertAndKey("rootCN")
	require.NoError(t, err)
	startRootCA, err := getAPIRootCA(cert, key)
	require.NoError(t, err)
	otherCert, otherKey, err := testutils.CreateRootCertAndKey("rootCN")
	require.NoError(t, err)

	// generate a cert that expires too soon (< 1 year)
	lessThanYear := helpers.OneDay * 364
	expireTooSoonCert, _, expireTooSoonKey, err := initca.New(&csr.CertificateRequest{
		CN:         "rootCN",
		KeyRequest: &csr.BasicKeyRequest{A: ca.RootKeyAlgo, S: ca.RootKeySize},
		CA:         &csr.CAConfig{Expiry: lessThanYear.String()},
	})
	require.NoError(t, err)

	testCases := []rootCARotationTestCase{
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				RootRotationState: &api.RootRotationState{
					State: api.RootRotationState_RotationAborted,
				},
			},
			expectErrorString: "previous root CA rotation is in progress",
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
				RootCAKey:      otherKey,
			},
		},
		// Even if there are external CAs configured, if they do not match the new cert, they are not counted
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				Spec:   getClusterSpecWithExternal(cert),
			},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
			},
			expectErrorString: "neither root key nor new external CA urls provided",
		},
		// The expiry for a new RootCA cert to be used for a swarm must be at least one year out
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     expireTooSoonCert,
				RootCAKey:      expireTooSoonKey,
			},
			expectErrorString: "expires too soon",
		},
		// These are some of the certificate/key validation cases from NewRootCA tests - we are not going
		// to re-test everything, but just check a couple as a sanity test that the same checks are being
		// run here.
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     otherCert,
				RootCAKey:      key,
			},
			expectErrorString: "certificate key mismatch",
		},
		{
			cluster: api.Cluster{RootCA: startRootCA},
			rotationRequest: api.KeyRotation{
				RootCARotation: true,
				RootCACert:     testutils.ExpiredCert,
				RootCAKey:      testutils.ExpiredKey,
			},
			expectErrorString: "expired",
		},
	}
	for _, testCase := range testCases {
		testCase.expectRootCA = *(testCase.cluster.RootCA.Copy())
		testCase.expectRotationState = testCase.cluster.RootRotationState.Copy()
		err := validateAndMaybeStartRootRotation(&testCase.cluster, testCase.rotationRequest)
		require.Error(t, err)
		require.Contains(t, grpc.ErrorDesc(err), testCase.expectErrorString)
		require.Equal(t, testCase.expectRootCA, testCase.cluster.RootCA, "cluster should not have been altered")
		require.Equal(t, testCase.expectRotationState, testCase.cluster.RootRotationState, "rotation state should not have been altered")
	}
}

type updateRootRotationTestCase struct {
	cluster             api.Cluster
	desiredState        api.RootRotationState_State
	expectRootCA        api.RootCA
	expectRotationState *api.RootRotationState
	expectErrorString   string
	description         string
}

func TestUpdateRootRotationInvalid(t *testing.T) {
	startRootCA := getRootCAObj(t, testutils.ECDSA256SHA256Cert, testutils.ECDSA256Key)

	invalids := []updateRootRotationTestCase{
		{
			cluster:           api.Cluster{RootCA: startRootCA},
			expectErrorString: "not currently in the middle of a root CA rotation",
			desiredState:      api.RootRotationState_RotationDone,
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				RootRotationState: &api.RootRotationState{
					State: api.RootRotationState_RotationAborted,
				},
			},
			expectErrorString: "cannot progress to signer rotation unless the previous state was rotating the certificate",
			desiredState:      api.RootRotationState_SignerRotation,
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				RootRotationState: &api.RootRotationState{
					State: api.RootRotationState_SignerRotation,
				},
			},
			expectErrorString: "invalid next rotation state",
			desiredState:      api.RootRotationState_CertificateRotation,
		},
		{
			cluster: api.Cluster{
				RootCA: startRootCA,
				RootRotationState: &api.RootRotationState{
					State: api.RootRotationState_CertificateRotation,
				},
			},
			expectErrorString: "cannot complete root rotation yet",
			desiredState:      api.RootRotationState_RotationDone,
		},
	}

	ts := newTestServer(t)
	defer ts.Stop()

	for i, invalid := range invalids {
		invalid.cluster.ID = fmt.Sprintf("%d", i)
		invalid.cluster.Spec.Annotations.Name = invalid.cluster.ID

		var cluster *api.Cluster
		require.NoError(t, ts.Store.Update(func(tx store.Tx) error {
			if err := store.CreateCluster(tx, &invalid.cluster); err != nil {
				return err
			}
			cluster = store.GetCluster(tx, invalid.cluster.ID)
			require.NotNil(t, cluster)
			return nil
		}))

		_, err := ts.Client.UpdateRootRotation(context.Background(), &api.UpdateRootRotationRequest{
			ClusterID:    cluster.ID,
			DesiredState: invalid.desiredState,
		})
		require.Error(t, err, invalid.expectErrorString)
		require.Contains(t, err.Error(), invalid.expectErrorString)

		ts.Store.View(func(tx store.ReadTx) {
			gotCluster := store.GetCluster(tx, cluster.ID)
			require.Equal(t, cluster, gotCluster)
		})
	}
}

// if the desired state == current state, do not error, but do nothing
func TestUpdateRootRotationNoop(t *testing.T) {
	startRootCA := getRootCAObj(t, testutils.ECDSA256SHA256Cert, testutils.ECDSA256Key)
	ts := newTestServer(t)
	defer ts.Stop()

	for enumNum := range api.RootRotationState_State_name {
		desiredState := api.RootRotationState_State(enumNum)
		if desiredState == api.RootRotationState_RotationDone {
			continue
		}
		idName := fmt.Sprintf("%d", enumNum)

		var cluster *api.Cluster

		require.NoError(t, ts.Store.Update(func(tx store.Tx) error {
			err := store.CreateCluster(tx, &api.Cluster{
				RootCA:            startRootCA,
				RootRotationState: &api.RootRotationState{State: desiredState},
				ID:                idName,
				Spec: api.ClusterSpec{
					Annotations: api.Annotations{
						Name: idName,
					},
				},
			})
			if err != nil {
				return err
			}
			cluster = store.GetCluster(tx, idName)
			require.NotNil(t, cluster)
			return nil
		}))

		_, err := ts.Client.UpdateRootRotation(context.Background(), &api.UpdateRootRotationRequest{
			ClusterID:    cluster.ID,
			DesiredState: desiredState,
		})
		require.NoError(t, err)

		ts.Store.View(func(tx store.ReadTx) {
			updatedCluster := store.GetCluster(tx, cluster.ID)
			require.NotNil(t, updatedCluster)
			require.Equal(t, cluster, updatedCluster)
		})
	}
}

func TestUpdateRootRotationValid(t *testing.T) {
	cert, key := testutils.ECDSA256SHA256Cert, testutils.ECDSA256Key
	otherCert, otherKey, err := testutils.CreateRootCertAndKey("rootCN")
	require.NoError(t, err)

	valids := []updateRootRotationTestCase{
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(cert, otherCert...), key),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_CertificateRotation,
					NewCACert: otherCert,
					NewCAKey:  otherKey,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_SignerRotation,
			description:  "cert rotation -> signer rotation (internal CA)",
			expectRootCA: getRootCAObj(t, append(otherCert, cert...), otherKey),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_SignerRotation,
				NewCACert: otherCert,
				NewCAKey:  otherKey,
				OldCACert: cert,
				OldCAKey:  key,
			},
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(cert, otherCert...), key),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_CertificateRotation,
					NewCACert: otherCert,
					NewCAKey:  otherKey,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_RotationAborted,
			description:  "cert rotation -> rotation aborted (internal CA)",
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_RotationAborted,
				NewCACert: otherCert,
				NewCAKey:  otherKey,
				OldCACert: cert,
				OldCAKey:  key,
			},
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(otherCert, cert...), otherKey),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_SignerRotation,
					NewCACert: otherCert,
					NewCAKey:  otherKey,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_RotationAborted,
			description:  "signer rotation -> rotation aborted (internal CA)",
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_RotationAborted,
				NewCACert: otherCert,
				NewCAKey:  otherKey,
				OldCACert: cert,
				OldCAKey:  key,
			},
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(otherCert, cert...), otherKey),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_SignerRotation,
					NewCACert: otherCert,
					NewCAKey:  otherKey,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_RotationDone,
			description:  "signer rotation -> rotation done (internal CA)",
			expectRootCA: getRootCAObj(t, otherCert, otherKey),
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(cert, otherCert...), key),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_RotationAborted,
					NewCACert: otherCert,
					NewCAKey:  otherKey,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_RotationDone,
			description:  "rotation aborted -> rotation done (internal CA)",
			expectRootCA: getRootCAObj(t, cert, key),
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(cert, otherCert...), key),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_CertificateRotation,
					NewCACert: otherCert,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_SignerRotation,
			description:  "cert rotation -> signer rotation (external CA)",
			expectRootCA: getRootCAObj(t, append(otherCert, cert...), nil),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_SignerRotation,
				NewCACert: otherCert,
				OldCACert: cert,
				OldCAKey:  key,
			},
		},
		{
			cluster: api.Cluster{
				RootCA: getRootCAObj(t, append(otherCert, cert...), nil),
				RootRotationState: &api.RootRotationState{
					State:     api.RootRotationState_SignerRotation,
					NewCACert: otherCert,
					OldCACert: cert,
					OldCAKey:  key,
				},
			},
			desiredState: api.RootRotationState_RotationAborted,
			description:  "signer rotation -> rotation aborted (external CA)",
			expectRootCA: getRootCAObj(t, append(cert, otherCert...), key),
			expectRotationState: &api.RootRotationState{
				State:     api.RootRotationState_RotationAborted,
				NewCACert: otherCert,
				OldCACert: cert,
				OldCAKey:  key,
			},
		}}

	ts := newTestServer(t)
	defer ts.Stop()

	for i, valid := range valids {
		valid.cluster.ID = fmt.Sprintf("%d", i)
		valid.cluster.Spec.Annotations.Name = valid.cluster.ID

		var cluster *api.Cluster
		require.NoError(t, ts.Store.Update(func(tx store.Tx) error {
			if err := store.CreateCluster(tx, &valid.cluster); err != nil {
				return err
			}
			cluster = store.GetCluster(tx, valid.cluster.ID)
			require.NotNil(t, cluster)
			return nil
		}))

		_, err := ts.Client.UpdateRootRotation(context.Background(), &api.UpdateRootRotationRequest{
			ClusterID:    valid.cluster.ID,
			DesiredState: valid.desiredState,
		})
		require.NoError(t, err, valid.description)

		ts.Store.View(func(tx store.ReadTx) {
			gotCluster := store.GetCluster(tx, valid.cluster.ID)
			require.NotEqual(t, cluster.Meta.Version, gotCluster.Meta.Version, valid.description)
			require.NotEqual(t, cluster.RootCA.JoinTokens, gotCluster.RootCA.JoinTokens, valid.description) // join tokens have changed
			// can't compare them, because they're random
			gotCluster.RootCA.JoinTokens = api.JoinTokens{}
			valid.expectRootCA.JoinTokens = api.JoinTokens{}
			require.Equal(t, valid.expectRootCA, gotCluster.RootCA, valid.description)
			if valid.expectRotationState == nil {
				require.Nil(t, gotCluster.RootRotationState, valid.description)
			} else {
				require.Equal(t, *valid.expectRotationState, *gotCluster.RootRotationState, valid.description)
			}
		})
	}
}
