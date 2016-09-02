package secrets

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/docker/swarmkit/api"
	"github.com/docker/swarmkit/cmd/swarmctl/common"
	"github.com/spf13/cobra"
)

type secretSorter []*api.Secret

func (k secretSorter) Len() int      { return len(k) }
func (k secretSorter) Swap(i, j int) { k[i], k[j] = k[j], k[i] }
func (k secretSorter) Less(i, j int) bool {
	iTime := time.Unix(k[i].Meta.CreatedAt.Seconds, int64(k[i].Meta.CreatedAt.Nanos))
	jTime := time.Unix(k[j].Meta.CreatedAt.Seconds, int64(k[j].Meta.CreatedAt.Nanos))
	return jTime.Before(iTime)
}

var (
	listCmd = &cobra.Command{
		Use:   "ls",
		Short: "List secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("ls command takes no arguments")
			}

			flags := cmd.Flags()

			quiet, err := flags.GetBool("quiet")
			if err != nil {
				return err
			}

			names, err := flags.GetStringSlice("name")
			if err != nil {
				return err
			}

			prefixes, err := flags.GetStringSlice("prefix")
			if err != nil {
				return err
			}

			conn, err := Dial(cmd)
			if err != nil {
				return err
			}
			client := api.NewSecretsClient(conn)

			r, err := client.ListSecrets(common.Context(cmd),
				&api.ListSecretsRequest{Filters: &api.ListSecretsRequest_Filters{Names: names, NamePrefixes: prefixes}})
			if err != nil {
				return err
			}

			var output func(*api.Secret)

			if !quiet {
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 4, ' ', 0)
				defer func() {
					// Ignore flushing errors - there's nothing we can do.
					_ = w.Flush()
				}()
				common.PrintHeader(w, "Name", "Created", "Last Updated", "Versions")
				output = func(s *api.Secret) {
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\n",
						s.Name,
						common.TimestampTime(s.Meta.CreatedAt),
						common.TimestampTime(s.Meta.UpdatedAt),
						len(s.SecretData),
					)
				}

			} else {
				output = func(s *api.Secret) { fmt.Println(s.ID) }
			}

			sorted := secretSorter(r.Secrets)
			sort.Sort(sorted)
			for _, s := range sorted {
				output(s)
			}
			return nil
		},
	}
)

func init() {
	listCmd.Flags().BoolP("quiet", "q", false, "Only display secret names")
	listCmd.Flags().StringSlice("name", []string{}, "Filter by name(s)")
	listCmd.Flags().StringSlice("prefix", []string{}, "Filter by name prefix(es)")
}
