package cluster

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/docker/swarmkit/manager/encryption"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// get the unlock key

func getNodeCAClient(cmd *cobra.Command) (api.NodeCAClient, error) {
	addr, err := cmd.Flags().GetString("socket")
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{}
	insecureCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	opts = append(opts, grpc.WithTransportCredentials(insecureCreds))
	opts = append(opts, grpc.WithDialer(
		func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}

	return api.NewNodeCAClient(conn), nil
}

var (
	unlockKeyCmd = &cobra.Command{
		Use:   "unlock-key <cluster name>",
		Short: "Get the unlock key for a cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("cluster name missing")
			}

			if len(args) > 1 {
				return errors.New("inspect command takes exactly 1 argument")
			}

			c, err := common.Dial(cmd)
			if err != nil {
				return err
			}

			cluster, err := getCluster(common.Context(cmd), c, args[0])
			if err != nil {
				return err
			}

			c2, err := getNodeCAClient(cmd)
			if err != nil {
				return err
			}

			resp, err := c2.GetUnlockKey(common.Context(cmd), &api.GetUnlockKeyRequest{})
			if err != nil {
				return err
			}

			if cluster.Spec.EncryptionConfig.AutoLockManagers {
				fmt.Printf("Managers auto-locked.  Unlock key: %s\n", encryption.HumanReadableKey(resp.UnlockKey))
			} else {
				fmt.Println("Managers not auto-locked.")
			}

			return nil
		},
	}
)
