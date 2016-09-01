package service

import (
	"crypto/tls"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/spf13/cobra"
)

// Dial establishes a connection and creates a secrets client.
// TODO: this should be swarmctl/common's Dial - I just didn't want to refactor
// everything else yet
// It infers connection parameters from CLI options.
func Dial(cmd *cobra.Command) (*grpc.ClientConn, error) {
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
	return grpc.Dial(addr, opts...)
}
