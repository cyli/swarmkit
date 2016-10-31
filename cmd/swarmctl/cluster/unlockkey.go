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

func displayUnlockKey(cluster *api.Cluster, cmd *cobra.Command) error {
	if !cluster.Spec.EncryptionConfig.AutoLockManagers {
		fmt.Println("Managers not auto-locked.")
		return nil
	}

	addr, err := cmd.Flags().GetString("socket")
	if err != nil {
		return err
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
		return err
	}
	defer conn.Close()

	resp, err := api.NewCAClient(conn).GetUnlockKey(common.Context(cmd), &api.GetUnlockKeyRequest{})
	if err != nil {
		return err
	}

	fmt.Printf("Managers auto-locked.  Unlock key: %s\n", encryption.HumanReadableKey(resp.UnlockKey))
	return nil
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

			return displayUnlockKey(cluster, cmd)
		},
	}
)
