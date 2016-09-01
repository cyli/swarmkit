package secretsapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/docker/swarm-v2/identity"
	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/manager/state/store"
)

// MaxSecretSize is the maximum size of the data for any secret
const MaxSecretSize int = 500 * 1024

var (
	errNotImplemented  = errors.New("not implemented")
	errInvalidArgument = errors.New("invalid argument")
	isValidName        = regexp.MustCompile(`^[a-zA-Z0-9](?:[-_.]*[A-Za-z0-9]+)*$`)
)

// Server is the Secrets API gRPC server.
type Server struct {
	memstore *store.MemoryStore
}

// NewServer creates a Secrets API server.
func NewServer(memstore *store.MemoryStore) *Server {
	return &Server{
		memstore: memstore,
	}
}

// CreateSecret creates and return a Secret based on the provided SecretSpec.
// - Returns `InvalidArgument` if the SecretSpec is malformed.
// - Returns `AlreadyExists` if the Secret's name conflicts.
// - Returns an error if the creation fails.
func (s *Server) CreateSecret(ctx context.Context, request *api.CreateSecretRequest) (*api.CreateSecretResponse, error) {
	if err := validateSecretSpec(request.Spec); err != nil {
		return nil, err
	}

	checksumBytes := sha256.Sum256(request.Spec.Data)
	secretDataID := identity.NewID()

	// creates a secret object and try to insert it into the store - the store will handle name conflicts
	storedSecret := api.Secret{
		ID: identity.NewID(),
		SecretData: map[string]*api.SecretData{
			secretDataID: {
				ID:     secretDataID,
				Spec:   *request.Spec,
				Digest: "sha256:" + hex.EncodeToString(checksumBytes[:]),
			},
		},
		Name: request.Spec.Annotations.Name,
	}

	createSecretFunc := func(tx store.Tx) error {
		return store.CreateSecret(tx, &storedSecret)
	}

	if err := s.memstore.Update(createSecretFunc); err != nil {
		if err == store.ErrNameConflict {
			return nil, grpc.Errorf(codes.AlreadyExists, "secret %s already exists", request.Spec.Annotations.Name)
		}
		return nil, err
	}

	// Create a new secret with the data zero-ed out, so we don't overwrite the stored one
	cleanedSpec := *request.Spec
	cleanedSpec.Data = nil

	returnedSecret := storedSecret
	returnedSecret.SecretData[secretDataID].Spec = cleanedSpec

	return &api.CreateSecretResponse{
		Secret: &returnedSecret,
	}, nil
}

// UpdateSecret adds a SecretSpec to a Secret as a new version.
// - Returns `NotFound` if the Secret with the given name is not found.
// - Returns `InvalidArgument` if the ServiceSpec is malformed.
// - Returns an error if the update fails.
func (s *Server) UpdateSecret(ctx context.Context, request *api.UpdateSecretRequest) (*api.UpdateSecretResponse, error) {
	if err := validateSecretSpec(request.Spec); err != nil {
		return nil, err
	}
	return nil, errNotImplemented
}

// RemoveSecret removes a Secret referenced by name or a version of the Secret referenced by name and version.
// - Returns `InvalidArgument` if name is not provided.
// - Returns `NotFound` if the Secret is not found.
// - Returns an error if the deletion fails.
func (s *Server) RemoveSecret(ctx context.Context, request *api.RemoveSecretRequest) (*api.RemoveSecretResponse, error) {
	if request.Name == "" {
		return nil, grpc.Errorf(codes.InvalidArgument, "errInvalidArgument.Error()")
	}
	// get the secret by name
	deleteSecretFunc := func(tx store.Tx) error {
		secrets, err := store.FindSecrets(tx, store.ByCN(request.Name))
		if err != nil {
			return err
		}

		if len(secrets) == 0 {
			return store.ErrNotExist
		}

		if len(secrets) > 1 {
			return fmt.Errorf("more than one secret with name %s", request.Name)
		}

		switch request.Version {
		case "":
			return store.DeleteSecret(tx, secrets[0].ID)
		default:
			if _, ok := secrets[0].SecretData[request.Version]; ok {
				// delete secret version
				delete(secrets[0].SecretData, request.Version)
				return store.UpdateSecret(tx, secrets[0])
			}
			// this secret version doesn't exist
			return store.ErrNotExist
		}
	}

	err := s.memstore.Update(deleteSecretFunc)
	switch {
	case err == store.ErrNotExist && request.Version == "":
		return nil, grpc.Errorf(codes.NotFound, "secret %s not found", request.Name)
	case err == store.ErrNotExist:
		return nil, grpc.Errorf(codes.NotFound, "version %s not found for secret %s", request.Version, request.Name)
	case err != nil:
		return nil, err
	default:
		return &api.RemoveSecretResponse{}, nil
	}
}

// ListSecrets returns a list of all secrets.
func (s *Server) ListSecrets(ctx context.Context, request *api.ListSecretsRequest) (*api.ListSecretsResponse, error) {
	return nil, errNotImplemented
}

func validateSecretSpec(spec *api.SecretSpec) error {
	if spec == nil {
		return grpc.Errorf(codes.InvalidArgument, errInvalidArgument.Error())
	}
	if err := validateAnnotations(spec.Annotations); err != nil {
		return err
	}
	if _, ok := api.SecretType_name[int32(spec.Type)]; !ok {
		return grpc.Errorf(codes.InvalidArgument, errInvalidArgument.Error())
	}

	if len(spec.Data) > MaxSecretSize {
		return grpc.Errorf(codes.InvalidArgument, "secret data too large: max %d bytes", MaxSecretSize)
	}
	return nil
}

func validateAnnotations(m api.Annotations) error {
	if m.Name == "" {
		return grpc.Errorf(codes.InvalidArgument, "meta: name must be provided")
	} else if !isValidName.MatchString(m.Name) {
		// if the name doesn't match the regex
		return grpc.Errorf(codes.InvalidArgument, "invalid name, only [a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9] are allowed")
	}
	return nil
}
