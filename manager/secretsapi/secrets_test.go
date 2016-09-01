package secretsapi

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/api/timestamp"
	"github.com/docker/swarmkit/identity"
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
		Annotations: api.Annotations{Name: name},
		Type:        secretType,
		Data:        data,
	}
}

func createSecret(name string, dataVersions [][]byte) (api.Secret, []string) {
	secret := api.Secret{
		ID:         identity.NewID(),
		SecretData: make(map[string]*api.SecretData),
		Name:       name,
	}
	ids := make([]string, len(dataVersions))
	for i, data := range dataVersions {
		secretData := secretDataFromSecretSpec(createSpec(name, data, api.SecretType_ContainerSecret))
		secret.SecretData[secretData.ID] = secretData
		ids[i] = secretData.ID
	}
	secret.LatestVersion = ids[len(ids)-1]

	return secret, ids
}

func validateChecksum(t *testing.T, secretData *api.SecretData, data []byte) {
	checksumBytes := sha256.Sum256(data)
	assert.Equal(t, "sha256:"+hex.EncodeToString(checksumBytes[:]), secretData.Digest)
	assert.EqualValues(t, len(data), secretData.SecretSize)
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
		"/a",
		"a/",
		"a/b",
		"..",
		"../a",
		"a/..",
		"withexclamation!",
		"with spaces",
		"with\nnewline",
		"with@splat",
		"with:colon",
		"with;semicolon",
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

	// ---- creating a secret with an invalid spec fails, thus checking that CreateSecret validates the spec ----
	_, err := s.CreateSecret(context.Background(), &api.CreateSecretRequest{Spec: createSpec("", nil, api.SecretType_ContainerSecret)})
	assert.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpc.Code(err), grpc.ErrorDesc(err))

	// ---- creating a secret with a valid spec succeeds, and returns a secret that reflects the secret in the store
	// exactly, but without the private data ----
	data := []byte("secret")
	validSpecRequest := api.CreateSecretRequest{Spec: createSpec("name", data, api.SecretType_ContainerSecret)}
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
	assert.Equal(t, "name", storedSecret.Name)

	var id string
	assert.Len(t, storedSecret.SecretData, 1)
	for _, secretData := range storedSecret.SecretData {
		id = secretData.ID
		// the stored secret contains the data
		assert.Equal(t, data, secretData.Spec.Data)
		// the metadata for the version and the secret are the same
		assert.Equal(t, secretData.Meta, storedSecret.Meta)
		validateChecksum(t, secretData, data)
	}
	assert.Equal(t, id, storedSecret.LatestVersion)

	assert.Len(t, resp.Secret.SecretData, 1)
	for _, secretData := range resp.Secret.SecretData {
		// assert that this starts as nil
		assert.Nil(t, secretData.Spec.Data)
		// assign data to it to ensure we can compare the storedSecret and the response secret
		secretData.Spec.Data = data
	}
	assert.Equal(t, *storedSecret, *resp.Secret)

	// ---- creating a secret with the same name, even if it's the exact same spec, fails due to a name conflict ----
	_, err = s.CreateSecret(context.Background(), &validSpecRequest)
	assert.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, grpc.Code(err), grpc.ErrorDesc(err))
}

func TestGetSecret(t *testing.T) {
	memstore := store.NewMemoryStore(&mockProposer{})
	s := NewServer(memstore)

	// ---- getting a non-existant secret fails with NotFound ----
	_, err := s.GetSecret(context.Background(), &api.GetSecretRequest{Name: "secretName"})
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, grpc.Code(err), grpc.ErrorDesc(err))

	data := [][]byte{[]byte("data1"), []byte("data2")}
	secret, ids := createSecret("validSecretName", data)
	err = memstore.Update(func(tx store.Tx) error {
		return store.CreateSecret(tx, &secret)
	})
	assert.NoError(t, err)

	// ---- getting an existing secret returns the secret with all the private data cleaned ----
	resp, err := s.GetSecret(context.Background(), &api.GetSecretRequest{Name: secret.Name})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)

	var storedSecret *api.Secret
	memstore.View(func(tx store.ReadTx) {
		storedSecret = store.GetSecret(tx, resp.Secret.ID)
	})
	assert.NotNil(t, storedSecret)
	assert.NotEqual(t, storedSecret, resp.Secret)

	assert.Len(t, resp.Secret.SecretData, 2)
	assert.Len(t, storedSecret.SecretData, 2)
	for i, id := range ids {
		// the stored secret contains the data - it has not been altered
		assert.Equal(t, data[i], storedSecret.SecretData[id].Spec.Data)
		// the response does not have any data
		assert.Nil(t, nil, resp.Secret.SecretData[id].Spec.Data)

		// assign it to the response so we can compare
		resp.Secret.SecretData[id].Spec.Data = data[i]
	}

	assert.Equal(t, *storedSecret, *resp.Secret)
}

func TestUpdateSecret(t *testing.T) {
	memstore := store.NewMemoryStore(&mockProposer{})
	s := NewServer(memstore)

	data1 := []byte("data1")
	data2 := []byte("data2")

	// ---- updating a secret that does not exist fails  ----
	_, err := s.UpdateSecret(context.Background(), &api.UpdateSecretRequest{Spec: createSpec("name", data2, api.SecretType_ContainerSecret)})
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, grpc.Code(err), grpc.ErrorDesc(err))

	secret, ids := createSecret("name", [][]byte{data1})
	err = memstore.Update(func(tx store.Tx) error {
		return store.CreateSecret(tx, &secret)
	})
	assert.NoError(t, err)
	assert.Equal(t, ids[0], secret.LatestVersion)

	// ---- updating a secret with an invalid spec fails, thus checking that UpdateSecret validates the spec ----
	_, err = s.UpdateSecret(context.Background(), &api.UpdateSecretRequest{Spec: createSpec(secret.Name, data2, api.SecretType(100))})
	assert.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpc.Code(err), grpc.ErrorDesc(err))

	// ---- updating the secret with a valid spec adds the spec to the given secret, and returns a response representation of the secret with all
	// the data zeroed out ----
	resp, err := s.UpdateSecret(context.Background(),
		&api.UpdateSecretRequest{Spec: createSpec(secret.Name, data2, api.SecretType_ContainerSecret)})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)
	assert.Equal(t, secret.ID, resp.Secret.ID)

	var storedSecret *api.Secret
	memstore.View(func(tx store.ReadTx) {
		storedSecret = store.GetSecret(tx, secret.ID)
	})
	assert.NotNil(t, storedSecret)
	assert.NotEqual(t, storedSecret, resp.Secret)

	assert.Len(t, storedSecret.SecretData, 2)
	assert.NotEqual(t, *storedSecret.Meta.CreatedAt, *storedSecret.Meta.UpdatedAt)
	var newID string
	for id := range storedSecret.SecretData {
		if id != ids[0] {
			newID = id
		}
	}

	assert.Equal(t, newID, storedSecret.LatestVersion) // latest version should have been updated to the new version

	// ensure the old secret hasn't changed
	oldSecret, ok := storedSecret.SecretData[ids[0]]
	assert.True(t, ok)
	assert.Equal(t, data1, oldSecret.Spec.Data)
	validateChecksum(t, oldSecret, data1)
	// the metadata for the version and the secret are no longer the same, because secret was recently updated, but
	// the creation time and update time for this version is the same as the creation time of the secret
	assert.NotEqual(t, oldSecret.Meta, storedSecret.Meta)
	assert.Equal(t, *oldSecret.Meta.CreatedAt, *oldSecret.Meta.UpdatedAt)
	assert.Equal(t, *storedSecret.Meta.CreatedAt, *oldSecret.Meta.CreatedAt)

	// ensure the new secret has been added with the proper meta
	newSecret, ok := storedSecret.SecretData[newID]
	assert.True(t, ok)
	assert.Equal(t, data2, newSecret.Spec.Data)
	validateChecksum(t, newSecret, data2)
	// the metadata for the version and the secret are no longer the same, because secret was recently updated, but
	// the creation time and update time for this version is the same as the creation time of the secret
	assert.NotEqual(t, newSecret.Meta, storedSecret.Meta)
	assert.Equal(t, *newSecret.Meta.CreatedAt, *newSecret.Meta.UpdatedAt)
	assert.Equal(t, *storedSecret.Meta.UpdatedAt, *newSecret.Meta.CreatedAt)

	// delete the data on the stored response so that the response secret and the stored secret can be compared
	oldSecret.Spec.Data = nil
	newSecret.Spec.Data = nil
	assert.Equal(t, *storedSecret, *resp.Secret)

	// ---- updating the secret with the exact same spec succeeds and all timestamps differ ----
	resp, err = s.UpdateSecret(context.Background(),
		&api.UpdateSecretRequest{Spec: createSpec(secret.Name, data2, api.SecretType_ContainerSecret)})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)
	assert.Equal(t, secret.ID, resp.Secret.ID)
	assert.Len(t, resp.Secret.SecretData, 3)
	prevTimestamps := []*timestamp.Timestamp{}
	for _, secretData := range resp.Secret.SecretData {
		assert.Equal(t, *secretData.Meta.CreatedAt, *secretData.Meta.UpdatedAt)
		for _, prev := range prevTimestamps {
			assert.NotEqual(t, *prev, *secretData.Meta.CreatedAt)
		}
		prevTimestamps = append(prevTimestamps, secretData.Meta.CreatedAt)
	}

	// ---- updating the secret with a previous spec succeeds and all timestamps differ ----
	resp, err = s.UpdateSecret(context.Background(),
		&api.UpdateSecretRequest{Spec: createSpec(secret.Name, data1, api.SecretType_ContainerSecret)})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)
	assert.Equal(t, secret.ID, resp.Secret.ID)
	assert.Len(t, resp.Secret.SecretData, 4)
	prevTimestamps = []*timestamp.Timestamp{}
	for _, secretData := range resp.Secret.SecretData {
		assert.Equal(t, *secretData.Meta.CreatedAt, *secretData.Meta.UpdatedAt)
		for _, prev := range prevTimestamps {
			assert.NotEqual(t, *prev, *secretData.Meta.CreatedAt)
		}
		prevTimestamps = append(prevTimestamps, secretData.Meta.CreatedAt)
	}
}

func TestRemoveSecret(t *testing.T) {
	memstore := store.NewMemoryStore(&mockProposer{})
	s := NewServer(memstore)

	// ---- removing a non-existant secret fails with NotFound ----
	for _, req := range []*api.RemoveSecretRequest{
		{Name: "secretName"},
		{Name: "secretName", Version: "12345"},
	} {
		_, err := s.RemoveSecret(context.Background(), req)
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, grpc.Code(err), grpc.ErrorDesc(err))
		assert.Equal(t, req.Version != "", strings.Contains(grpc.ErrorDesc(err), "12345"))
	}

	origSecret, ids := createSecret("validSecretName", [][]byte{[]byte("data1"), []byte("data2"), []byte("data3")})
	err := memstore.Update(func(tx store.Tx) error {
		return store.CreateSecret(tx, &origSecret)
	})
	assert.NoError(t, err)
	// manually update the meta times so that they can be sorted (they won't all have the same time)
	err = memstore.Update(func(tx store.Tx) error {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
		secrets[0].SecretData[ids[2]].Meta.CreatedAt.Seconds += 10
		secrets[0].SecretData[ids[2]].Meta.UpdatedAt.Seconds += 10
		secrets[0].SecretData[ids[1]].Meta.CreatedAt.Seconds += 5
		secrets[0].SecretData[ids[1]].Meta.UpdatedAt.Seconds += 5
		return store.UpdateSecret(tx, secrets[0])
	})
	assert.NoError(t, err)

	// ---- removing an invalid version of an existing secret fails with NotFound ----
	_, err = s.RemoveSecret(context.Background(), &api.RemoveSecretRequest{Name: origSecret.Name, Version: "12345"})
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, grpc.Code(err), grpc.ErrorDesc(err))
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
		assert.Len(t, secrets[0].SecretData, 3)
	})

	// ---- removing not the latest version of a secret does not delete the whole secret, and does not update the latest version ----
	resp, err := s.RemoveSecret(context.Background(), &api.RemoveSecretRequest{Name: origSecret.Name, Version: ids[0]})
	assert.NoError(t, err)
	assert.Equal(t, api.RemoveSecretResponse{}, *resp)
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
		assert.Len(t, secrets[0].SecretData, 2)
		for _, i := range []int{1, 2} {
			assert.Contains(t, secrets[0].SecretData, ids[i])
			// the metadata for the secret data hasn't been modified, even if the one for the secret hasn
			assert.NotEqual(t, secrets[0].Meta, secrets[0].SecretData[ids[i]].Meta)
		}
		// the LatestVersion has not updated from the original
		assert.Equal(t, origSecret.LatestVersion, secrets[0].LatestVersion)
	})

	// ---- removing the latest version of a secret updates the latest version to be the next latest version ----
	resp, err = s.RemoveSecret(context.Background(), &api.RemoveSecretRequest{Name: origSecret.Name, Version: ids[2]})
	assert.NoError(t, err) // this isn't the last one
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
		assert.Len(t, secrets[0].SecretData, 1)
		assert.Contains(t, secrets[0].SecretData, ids[1])
		// the LatestVersion has been updated to reflect the only version remaining
		assert.Equal(t, ids[1], secrets[0].LatestVersion)
	})

	// ---- removing the last version of a secret removes the secret entirely ----
	resp, err = s.RemoveSecret(context.Background(), &api.RemoveSecretRequest{Name: origSecret.Name, Version: ids[1]})
	assert.NoError(t, err) // this is the last one
	assert.Equal(t, api.RemoveSecretResponse{}, *resp)
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 0)
	})

	// ---- add the secret back with versions, and assert that removing secret without providing a version will remove
	// the whole secret ----
	err = memstore.Update(func(tx store.Tx) error {
		return store.CreateSecret(tx, &origSecret)
	})
	assert.NoError(t, err)
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 1)
		assert.Len(t, secrets[0].SecretData, 3)
	})

	resp, err = s.RemoveSecret(context.Background(), &api.RemoveSecretRequest{Name: origSecret.Name})
	assert.NoError(t, err)
	assert.Equal(t, api.RemoveSecretResponse{}, *resp)
	memstore.View(func(tx store.ReadTx) {
		secrets, err := store.FindSecrets(tx, store.All)
		assert.NoError(t, err)
		assert.Len(t, secrets, 0)
	})
}

func TestListSecrets(t *testing.T) {
	memstore := store.NewMemoryStore(&mockProposer{})
	s := NewServer(memstore)

	listSecrets := func(req *api.ListSecretsRequest) map[string]*api.Secret {
		resp, err := s.ListSecrets(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Secrets)

		byName := make(map[string]*api.Secret)
		for _, secret := range resp.Secrets {
			byName[secret.Name] = secret
		}
		return byName
	}

	// ---- Listing secrets when there are no secrets returns an empty list but no error ----
	result := listSecrets(&api.ListSecretsRequest{})
	assert.Len(t, result, 0)

	secretNamesToID := make(map[string]string)
	for _, secretName := range []string{"aaa", "aab", "abc", "bbb", "bac", "bbc", "ccc", "cac", "cbc"} {
		secret, _ := createSecret(secretName, [][]byte{[]byte("secret")})

		err := memstore.Update(func(tx store.Tx) error {
			return store.CreateSecret(tx, &secret)
		})
		assert.NoError(t, err)
		secretNamesToID[secretName] = secret.ID
	}

	// ---- Listing secrets without a filter lists all the available secrets ----
	result = listSecrets(&api.ListSecretsRequest{})
	assert.Len(t, result, len(secretNamesToID))
	for name, id := range secretNamesToID {
		assert.Contains(t, result, name)
		assert.NotNil(t, result[name])
		assert.Equal(t, id, result[name].ID)
	}

	// ---- Listing secrets filters by name ----
	result = listSecrets(&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{Names: []string{"aaa"}}})
	assert.Len(t, result, 1)
	assert.Contains(t, result, "aaa")

	// ---- Listing secrets filters by name, multiple names can be passed ----
	names := []string{"aaa", "bbb", "ccc"}
	result = listSecrets(&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{Names: names}})
	assert.Len(t, result, len(names))
	for _, name := range names {
		assert.Contains(t, result, name)
	}

	// ---- Listing secrets filters by name prefix ----
	names = []string{"aaa", "aab"}
	result = listSecrets(&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{NamePrefixes: []string{"aa"}}})
	assert.Len(t, result, len(names))
	for _, name := range names {
		assert.Contains(t, result, name)
	}

	// ---- Listing secrets filters by name prefix, multiple name prefixes can be passed ----
	names = []string{"aaa", "aab", "bbb", "bbc"}
	result = listSecrets(&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{NamePrefixes: []string{"aa", "bb"}}})
	assert.Len(t, result, len(names))
	for _, name := range names {
		assert.Contains(t, result, name)
	}

	// ---- Listing secret filters by both name prefix and name ors the results together
	names = []string{"aaa", "aab", "bbb", "bbc", "ccc"}
	result = listSecrets(&api.ListSecretsRequest{
		Filters: &api.ListSecretsRequest_Filters{Names: []string{"aaa", "ccc"}, NamePrefixes: []string{"aa", "bb"}}})
	assert.Len(t, result, len(names))
	for _, name := range names {
		assert.Contains(t, result, name)
	}
}
