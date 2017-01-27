package controlapi

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"bytes"

	"crypto/subtle"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/ca"
	"golang.org/x/net/context"
)

var minRootExpiration = helpers.OneYear

func getAPIRootCA(cert, key []byte) (api.RootCA, error) {
	rootCA, err := ca.NewRootCA(cert, key, ca.DefaultNodeCertExpiration)
	if err != nil {
		return api.RootCA{}, err
	}
	return api.RootCA{
		CACert:     rootCA.Cert,
		CAKey:      rootCA.Key,
		CACertHash: rootCA.Digest.String(),
		JoinTokens: api.JoinTokens{
			Worker:  ca.GenerateJoinToken(&rootCA),
			Manager: ca.GenerateJoinToken(&rootCA),
		},
	}, nil
}

// Start root rotation - this creates the RootRotationState object, and sets it to the first root
// rotation phase (CertificateRotation).  This function assumes that a root rotation is not already
// in progress.
func startRootRotation(cluster *api.Cluster, rootCACert, rootCAKey []byte) (err error) {
	cluster.RootRotationState = &api.RootRotationState{
		State:     api.RootRotationState_CertificateRotation,
		NewCACert: rootCACert,
		NewCAKey:  rootCAKey,
		OldCACert: cluster.RootCA.CACert,
		OldCAKey:  cluster.RootCA.CAKey,
	}
	cluster.RootCA, err = getAPIRootCA(
		append(cluster.RootCA.CACert, rootCACert...),
		cluster.RootCA.CAKey,
	)
	if err != nil {
		err = grpc.Errorf(codes.Internal, "current root cert and key do not match: %v", err)
	}
	return
}

// UpdateRootRotation forcefully transitions the root rotation from the current phase to the desired phase
func (s *Server) UpdateRootRotation(ctx context.Context, request *api.UpdateRootRotationRequest) (*api.UpdateRootRotationResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "not yet implemented")
}

// validateAndMaybeStartRootRotation validates a cluster update's root rotation request and spec, and updates the cluster
// object as necessary to begin the root CA rotation process
func validateAndMaybeStartRootRotation(cluster *api.Cluster, rotation api.KeyRotation) error {
	if !rotation.RootCARotation { // only attempt to rotate if the boolean is set
		return nil
	}

	if cluster.RootRotationState != nil {
		return grpc.Errorf(codes.FailedPrecondition, "cannot start new root CA rotation while a previous root CA rotation is in progress")
	}

	switch {
	case rotation.RootCACert != nil:
		newRootCA, err := ca.NewRootCA(rotation.RootCACert, rotation.RootCAKey, ca.DefaultNodeCertExpiration)
		if err != nil {
			return grpc.Errorf(codes.InvalidArgument, err.Error())
		}
		// We had to validate above first using NewRootCA, since it's possible the user gave us a non-matching key.
		if bytes.Equal(cluster.RootCA.CACert, rotation.RootCACert) {
			return nil
		}

		if len(newRootCA.Pool.Subjects()) != 1 {
			return grpc.Errorf(codes.InvalidArgument, "exactly one root certificate must be provided")
		}

		// if NewRootCA succeeded, parsing will be successful
		parsedCert, _ := helpers.ParseCertificatePEM(rotation.RootCACert)
		// for root rotation, the certificate expiry must be at least one year away
		if parsedCert.NotAfter.Before(time.Now().Add(minRootExpiration)) {
			return grpc.Errorf(codes.InvalidArgument, "root certificate expires too soon")
		}

		// Check if the root cert has the same public key and subject as the previous one, we can just
		// replace the old root with the new one and be done.  This is true even if a key is provided - because
		// the key must match the old key
		oldCert, err := helpers.ParseCertificatePEM(cluster.RootCA.CACert)
		if err != nil {
			return grpc.Errorf(codes.Internal, "invalid root certificate: %v", err.Error())
		}
		if bytes.Equal(oldCert.RawSubject, parsedCert.RawSubject) &&
			bytes.Equal(oldCert.RawSubjectPublicKeyInfo, parsedCert.RawSubjectPublicKeyInfo) &&
			oldCert.PublicKeyAlgorithm == parsedCert.PublicKeyAlgorithm {

			cluster.RootCA.CACert = rotation.RootCACert
			cluster.RootCA.CACertHash = newRootCA.Digest.String()
			cluster.RootCA.JoinTokens = api.JoinTokens{
				Worker:  ca.GenerateJoinToken(&newRootCA),
				Manager: ca.GenerateJoinToken(&newRootCA),
			}
			return nil
		}

		if rotation.RootCAKey != nil {
			return startRootRotation(cluster, rotation.RootCACert, rotation.RootCAKey)
		}

		// There's no key and the new root does not match the old key, so there must be external CA urls provided that
		// match the new root.
		// TODO (cyli): should we validate external CAs by attempting to get a TLS cert and verify that the TLS cert
		// is indeed signed by the new root cert?
		rootDigest := newRootCA.Digest.String()
		for _, extCA := range cluster.Spec.CAConfig.ExternalCAs {
			if extCA.CACertHash == rootDigest {
				return startRootRotation(cluster, rotation.RootCACert, nil)
			}
		}

		// No key, the new root does not match the old key, and there are no external CAs that match the new root -
		// we can't rotate.
		return grpc.Errorf(codes.InvalidArgument, "root certificate provided, but neither root key nor new external CA urls provided")

	case rotation.RootCAKey == nil:
		// neither a cert nor a key - generate both
		newRootCA, err := ca.CreateRootCA(ca.DefaultRootCN)
		if err != nil {
			return grpc.Errorf(codes.Internal, err.Error())
		}
		return startRootRotation(cluster, newRootCA.Cert, newRootCA.Key)

	case subtle.ConstantTimeCompare(rotation.RootCAKey, cluster.RootCA.CAKey) == 1:
		// the same key was provided - just renew the existing cert
		newRootCA, err := ca.CreateRootCAFromSigner(ca.DefaultRootCN, cluster.RootCA.CAKey, cluster.RootCA.CACert)
		if err != nil {
			return grpc.Errorf(codes.Internal, err.Error())
		}
		cluster.RootCA.CACert = newRootCA.Cert
		cluster.RootCA.CACertHash = newRootCA.Digest.String()
		cluster.RootCA.JoinTokens = api.JoinTokens{
			Worker:  ca.GenerateJoinToken(&newRootCA),
			Manager: ca.GenerateJoinToken(&newRootCA),
		}
		return nil

	default:
		// only a new key was provided - generate the corresponding cert
		rootCA, err := ca.CreateRootCAFromSigner(ca.DefaultRootCN, rotation.RootCAKey, nil)
		if err != nil {
			return grpc.Errorf(codes.InvalidArgument, err.Error())
		}
		return startRootRotation(cluster, rootCA.Cert, rootCA.Key)
	}
}
