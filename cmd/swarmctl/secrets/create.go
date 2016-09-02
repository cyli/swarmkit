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

var createCmd = &cobra.Command{
	Use:   "create <secret Name>",
	Short: "Create a secret",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("create command takes a unique secret name as an argument, and accepts secret data as stdin")
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

		resp, err := client.CreateSecret(common.Context(cmd), &api.CreateSecretRequest{Spec: spec})
		if err != nil {
			return err
		}
		fmt.Println("Create success")
		printSecret(resp.Secret)
		return nil
	},
}
