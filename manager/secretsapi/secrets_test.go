package secretsapi

import (
	"testing"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/manager/state/store"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type mockProposer struct {
	index uint64
}

func (mp *mockProposer) ProposeValue(ctx context.Context, storeAction []*api.StoreAction, cb func()) error {
	if cb != nil {
		cb()
	}
	return nil
}

func (mp *mockProposer) GetVersion() *api.Version {
	mp.index += 3
	return &api.Version{Index: mp.index}
}

func createSpec(name string, data []byte, secretType api.SecretType) *api.SecretSpec {
	return &api.SecretSpec{
		Annotations: api.Annotations{
			Name: name,
		},
		Type: secretType,
		Data: data,
	}
}

func TestValidateSecretSpec(t *testing.T) {
	type BadServiceSpec struct {
		spec *api.ServiceSpec
		c    codes.Code
	}

	for _, badName := range []string{
		"",
		".",
		"-",
		"_",
		".name",
		"name.",
		"-name",
		"name-",
		"_name",
		"name_",
		"withexclamation!",
		"with spaces",
		"with\nnewline",
		"with@splat",
		"with:colon",
		"snowman☃",
	} {
		err := validateSecretSpec(createSpec(badName, []byte("valid secret"), api.SecretType_ContainerSecret))
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, grpc.Code(err), grpc.ErrorDesc(err))
	}

	for _, badSpec := range []*api.SecretSpec{
		nil,
		createSpec("validName", make([]byte, MaxSecretSize+1), api.SecretType_ContainerSecret),
		createSpec("validName", []byte("valid secret"), api.SecretType(100)),
	} {
		err := validateSecretSpec(badSpec)
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, grpc.Code(err), grpc.ErrorDesc(err))
	}

	for _, goodName := range []string{
		"0",
		"a",
		"A",
		"name-with-dashes",
		"name.with.dots",
		"name_with_underscores",
		"name.with-all_special",
		"02624name035with1699numbers015125",
	} {
		err := validateSecretSpec(createSpec(goodName, []byte("valid secret"), api.SecretType_ContainerSecret))
		assert.NoError(t, err)
	}

	for _, good := range []*api.SecretSpec{
		createSpec("validName", nil, api.SecretType_ContainerSecret),
		createSpec("validName", []byte("☃\n\t\r\x00 dg09236l;kajdgaj5%#9836[Q@!$]"), api.SecretType_ContainerSecret),
		createSpec("validName", []byte("valid secret"), api.SecretType_NodeSecret),
	} {
		err := validateSecretSpec(good)
		assert.NoError(t, err)
	}
}

func TestCreateSecret(t *testing.T) {
	memstore := store.NewMemoryStore(&mockProposer{})
	s := NewServer(memstore)

	// creating a secret with an invalid spec fails, thus checking that CreateSecret validates the spec
	_, err := s.CreateSecret(context.Background(), &api.CreateSecretRequest{Spec: createSpec("", nil, api.SecretType_ContainerSecret)})
	assert.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpc.Code(err), grpc.ErrorDesc(err))

	// creating a secret with a valid spec succeeds, and returns a secret that reflects the secret in the store
	// exactly, but without the private data
	validSpecRequest := api.CreateSecretRequest{Spec: createSpec("name", []byte("secret"), api.SecretType_ContainerSecret)}
	resp, err := s.CreateSecret(context.Background(), &validSpecRequest)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)

	var storedSecret *api.Secret
	memstore.View(func(tx store.ReadTx) {
		storedSecret = store.GetSecret(tx, resp.Secret.ID)
	})
	assert.NotNil(t, storedSecret)
	assert.NotEqual(t, storedSecret, resp.Secret)

	for _, secretData := range resp.Secret.SecretData {
		assert.Nil(t, secretData.Spec.Data)
	}
	for id, secretData := range storedSecret.SecretData {
		assert.NotNil(t, secretData.Spec.Data)
		assert.NotNil(t, resp.Secret.SecretData[id])
		// the returned one has no data, so assign the data to the returned one so we can compare both
		resp.Secret.SecretData[id].Spec.Data = secretData.Spec.Data
	}
	assert.Equal(t, *storedSecret, *resp.Secret)

	// creating a secret with the same name, even if it's the exact same spec, fails due to a name conflict
	_, err = s.CreateSecret(context.Background(), &validSpecRequest)
	assert.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, grpc.Code(err), grpc.ErrorDesc(err))
}
