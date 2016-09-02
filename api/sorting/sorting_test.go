package sorting

import (
	"testing"
	"time"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/api/timestamp"
	"github.com/stretchr/testify/assert"
)

func TestGetSortedSecretVersions(t *testing.T) {
	now := time.Now()
	secret := &api.Secret{
		SecretData: map[string]*api.SecretData{
			"1": {
				ID: "1",
				Meta: api.Meta{
					CreatedAt: &timestamp.Timestamp{Seconds: now.Unix() + 10},
				},
			},
			"2": {
				ID: "2",
				Meta: api.Meta{
					CreatedAt: &timestamp.Timestamp{Seconds: now.Unix() + 5},
				},
			},
			"3": {
				ID: "3",
				Meta: api.Meta{
					CreatedAt: &timestamp.Timestamp{Seconds: now.Unix() + 8},
				},
			},
			"4": {
				ID: "4",
				Meta: api.Meta{
					CreatedAt: &timestamp.Timestamp{Seconds: now.Unix()},
				},
			},
			"5": {
				ID: "5",
				Meta: api.Meta{
					CreatedAt: &timestamp.Timestamp{Seconds: now.Unix() + 1},
				},
			},
		},
	}

	sorted := GetSortedSecretVersions(secret)
	assert.Len(t, sorted, 5)
	for i, expectedID := range []string{"1", "3", "2", "5", "4"} {
		assert.Equal(t, expectedID, sorted[i].ID)
	}
}
