package service

import (
	"errors"
	"fmt"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return errors.New("create command takes a unique secret name and the secret data as arguments")
		}

		conn, err := Dial(cmd)
		if err != nil {
			return err
		}
		client := api.NewSecretsClient(conn)

		spec := &api.SecretSpec{
			Annotations: api.Annotations{
				Name: args[0],
			},
			Type: api.SecretType_ContainerSecret,
			Data: []byte(args[1]),
		}

		resp, err := client.CreateSecret(common.Context(cmd), &api.CreateSecretRequest{Spec: spec})
		if err != nil {
			return err
		}
		fmt.Println(resp.Secret.ID)
		return nil
	},
}
