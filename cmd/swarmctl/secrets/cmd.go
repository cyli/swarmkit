package secrets

import "github.com/spf13/cobra"

var (
	// Cmd exposes the top-level service command.
	Cmd = &cobra.Command{
		Use:     "secrets",
		Aliases: nil,
		Short:   "Secrets management",
	}
)

func init() {
	Cmd.AddCommand(
		inspectCmd,
		listCmd,
		createCmd,
		updateCmd,
		removeCmd,
	)
}
