package controlapi

import (
	"bytes"
	"testing"

	"google.golang.org/grpc"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"github.com/docker/swarmkit/ca/testutils"
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
