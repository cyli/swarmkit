package main

import (
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	mainCmd = &cobra.Command{
		Use:   os.Args[0],
		Short: "Tool to translate and decrypt the raft logs of a swarm manager",
	}

	decryptCmd = &cobra.Command{
		Use:   "decrypt <output directory>",
		Short: "Decrypt a swarm manager's raft logs to an optional directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("output directory required")
			}

			if len(args) > 1 {
				return errors.New(os.Args[0] + " command takes exactly 1 argument")
			}

			outDir := args[0]

			stateDir, err := cmd.Flags().GetString("state-dir")
			if err != nil {
				return err
			}

			unlockKey, err := cmd.Flags().GetString("unlock-key")
			if err != nil {
				return err
			}

			return decryptRaftData(stateDir, outDir, unlockKey)
		},
	}

	downgradeCmd = &cobra.Command{
		Use:   "downgrade",
		Short: "downgrade the manager logs from v3 encrypted format to v2 format",
		RunE: func(cmd *cobra.Command, args []string) error {
			stateDir, err := cmd.Flags().GetString("state-dir")
			if err != nil {
				return err
			}

			unlockKey, err := cmd.Flags().GetString("unlock-key")
			if err != nil {
				return err
			}

			return downgrade(stateDir, unlockKey)
		},
	}
)

func init() {
	mainCmd.PersistentFlags().StringP("state-dir", "d", "./swarmkitstate", "State directory")
	mainCmd.PersistentFlags().String("unlock-key", "", "Unlock key, if raft logs are encrypted")
	mainCmd.AddCommand(
		decryptCmd,
		downgradeCmd,
	)
}

func main() {
	if _, err := mainCmd.ExecuteC(); err != nil {
		os.Exit(-1)
	}
}
