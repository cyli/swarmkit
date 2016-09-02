package secrets

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/api/sorting"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
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

func printSecret(s *api.Secret) {
	w := tabwriter.NewWriter(os.Stdout, 8, 8, 8, ' ', 0)
	fmt.Fprintf(w, "Name\t: %s\n", s.Name)
	fmt.Fprintf(w, "Created\t: %s\n", common.TimestampTime(s.Meta.CreatedAt))
	fmt.Fprintf(w, "Last Updated\t: %s\n", common.TimestampTime(s.Meta.UpdatedAt))
	fmt.Fprintf(w, "Latest Version\t: %s\n", s.LatestVersion)
	fmt.Fprintf(w, "Number of Versions\t: %d\n\n", len(s.SecretData))
	_ = w.Flush()

	// now print the individual versions
	w = tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
	defer func() {
		_ = w.Flush()
	}()
	common.PrintHeader(w, "", "Created", "Version", "Digest", "Size")
	sorted := sorting.GetSortedSecretVersions(s)
	for _, secretData := range sorted {
		fmt.Fprintf(w, "\t%s\t%s\t%s\t%d\n",
			common.TimestampTime(secretData.Meta.CreatedAt),
			secretData.ID,
			secretData.Digest,
			secretData.SecretSize,
			// api.SecretType_name[int32(secretData.Spec.Type)],
		)
	}
}
