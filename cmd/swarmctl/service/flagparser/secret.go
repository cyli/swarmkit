package flagparser

import (
	"fmt"
	"strings"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

func parseSecretString(secretString string) (secretName, versionID, presentName string, err error) {
	tokens := strings.Split(secretString, ":")

	secretTokens := strings.Split(tokens[0], "@")
	secretName = strings.TrimSpace(secretTokens[0])
	if len(secretTokens) > 1 {
		versionID = strings.TrimSpace(secretTokens[1])
		if versionID == "" {
			err = fmt.Errorf("invalid secret version value provided")
			return
		}
	}

	if secretName == "" {
		err = fmt.Errorf("invalid secret name provided")
		return
	}

	if len(tokens) > 1 {
		presentName = strings.TrimSpace(tokens[1])
		if presentName == "" {
			err = fmt.Errorf("invalid presentation name provided")
			return
		}
	} else {
		presentName = secretName
	}
	return
}

// ParseAddSecret validates secrets passed on the command line
func ParseAddSecret(cmd *cobra.Command, spec *api.ServiceSpec, flagName string) error {
	flags := cmd.Flags()

	if flags.Changed(flagName) {
		secrets, err := flags.GetStringSlice(flagName)
		if err != nil {
			return err
		}

		container := spec.Task.GetContainer()
		if container == nil {
			spec.Task.Runtime = &api.TaskSpec_Container{
				Container: &api.ContainerSpec{},
			}
		}

		lookupSecretNames := []string{}
		needSecrets := make(map[string]*api.SecretReference)

		for _, secret := range secrets {
			n, v, p, err := parseSecretString(secret)
			if err != nil {
				return err
			}

			secretRef := &api.SecretReference{
				Name:         n,
				SecretDataID: v,
				Mode:         api.SecretReference_FILE,
				Target:       p,
			}

			lookupSecretNames = append(lookupSecretNames, n)
			needSecrets[n] = secretRef
		}

		conn, err := common.DialGetConn(cmd)
		if err != nil {
			return err
		}
		client := api.NewSecretsClient(conn)

		r, err := client.ListSecrets(common.Context(cmd),
			&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{Names: lookupSecretNames}})
		if err != nil {
			return err
		}

		foundSecrets := make(map[string]*api.Secret)
		for _, secret := range r.Secrets {
			foundSecrets[secret.Name] = secret
		}

		for secretName, secretRef := range needSecrets {
			secret, ok := foundSecrets[secretName]
			if !ok {
				return fmt.Errorf("secret not found: %s", secretName)
			}
			if secretRef.SecretDataID == "" {
				secretRef.SecretDataID = secret.LatestVersion
			} else if _, ok := secret.SecretData[secretRef.SecretDataID]; !ok {
				return fmt.Errorf("secret not found: %s@%s", secretName, secretRef.SecretDataID)
			}

			container.Secrets = append(container.Secrets, secretRef)
		}
	}

	return nil
}

// ParseRemoveSecret removes a set of secrets from the task spec's secret references
func ParseRemoveSecret(cmd *cobra.Command, spec *api.ServiceSpec, flagName string) error {
	flags := cmd.Flags()

	if flags.Changed(flagName) {
		secrets, err := flags.GetStringSlice(flagName)
		if err != nil {
			return err
		}

		container := spec.Task.GetContainer()
		if container == nil {
			return nil
		}

		wantToDelete := make(map[string]string)

		for _, secret := range secrets {
			n, v, _, err := parseSecretString(secret)
			if err != nil {
				return err
			}

			wantToDelete[n] = v
		}

		secretRefs := []*api.SecretReference{}

		for _, secretRef := range container.Secrets {
			if version, ok := wantToDelete[secretRef.Name]; ok {
				if version == secretRef.SecretDataID || version == "" {
					continue
				}
			}
			secretRefs = append(secretRefs, secretRef)
		}

		container.Secrets = secretRefs
	}
	return nil
}

// UpdateSecretsToLatest takes all the secrets in a service spec and updates them to the latest version
func UpdateSecretsToLatest(cmd *cobra.Command, spec *api.ServiceSpec) error {
	lookupSecretNames := []string{}
	needSecrets := make(map[string]*api.SecretReference)

	container := spec.Task.GetContainer()
	if container == nil {
		return nil
	}

	for _, secretRef := range container.Secrets {
		lookupSecretNames = append(lookupSecretNames, secretRef.Name)
		needSecrets[secretRef.Name] = secretRef
	}

	conn, err := common.DialGetConn(cmd)
	if err != nil {
		return err
	}
	client := api.NewSecretsClient(conn)

	r, err := client.ListSecrets(common.Context(cmd),
		&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{Names: lookupSecretNames}})
	if err != nil {
		return err
	}

	foundSecrets := make(map[string]*api.Secret)
	for _, secret := range r.Secrets {
		foundSecrets[secret.Name] = secret
	}

	for secretName, secretRef := range needSecrets {
		secret, ok := foundSecrets[secretName]
		if !ok {
			return fmt.Errorf("secret not found: %s", secretName)
		}
		secretRef.SecretDataID = secret.LatestVersion
	}
	return nil
}
