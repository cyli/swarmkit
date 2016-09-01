package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:     "remove <secret name> [<secret name>...]",
	Short:   "Remove one or more secrets",
	Aliases: []string{"rm"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("secret name missing")
		}

		conn, err := Dial(cmd)
		if err != nil {
			return err
		}
		client := api.NewSecretsClient(conn)

		for _, secretIdentifier := range args {
			tokens := strings.Split(secretIdentifier, "@")
			var req api.RemoveSecretRequest
			switch {
			case len(tokens) == 1:
				req = api.RemoveSecretRequest{Name: tokens[0]}
			case len(tokens) == 2 && tokens[1] != "":
				req = api.RemoveSecretRequest{
					Name:    tokens[0],
					Version: tokens[1],
				}
			default:
				return fmt.Errorf("invalid secret name: %s", secretIdentifier)
			}
			_, err := client.RemoveSecret(common.Context(cmd), &req)
			if err != nil {
				return err
			}
			fmt.Printf("Removed %s\n", secretIdentifier)
		}
		return nil
	},
}
