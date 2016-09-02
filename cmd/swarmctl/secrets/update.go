package secrets

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update <secret Name>",
	Short: "Update a secret with a new version",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("update command takes an existing secret name as an argument, and accepts secret data as stdin")
		}

		secretData, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("Error reading content from STDIN: %v", err)
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
			Data: secretData,
		}

		resp, err := client.UpdateSecret(common.Context(cmd), &api.UpdateSecretRequest{Spec: spec})
		if err != nil {
			return err
		}
		fmt.Println("Update success")
		printSecret(resp.Secret)
		return nil
	},
}
