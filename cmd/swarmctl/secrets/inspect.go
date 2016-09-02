package secrets

import (
	"errors"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

var (
	inspectCmd = &cobra.Command{
		Use:   "inspect <secret Name>",
		Short: "Inspect a secret's versions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("inspect command takes a single secret name")
			}

			conn, err := Dial(cmd)
			if err != nil {
				return err
			}
			client := api.NewSecretsClient(conn)

			r, err := client.GetSecret(common.Context(cmd), &api.GetSecretRequest{Name: args[0]})
			if err != nil {
				return err
			}

			printSecret(r.Secret)

			return nil
		},
	}
)
