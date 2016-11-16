package main

import (
	"fmt"
	"os"

	"github.com/docker/swarmkit/ca"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	mainCmd = &cobra.Command{
		Use:   os.Args[0] + " <output directory>",
		Short: "Decrypt a swarm manager's raft logs to an output directory",
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

			deks, err := getDEKs(stateDir, unlockKey)
			switch errors.Cause(err).(type) {
			case ca.ErrInvalidKEK:
				return fmt.Errorf("invalid unlock key")
			case nil:
				break
			default:
				return nil
			}

			return decryptRaftData(stateDir, outDir, deks)
		},
	}
)

func init() {
	mainCmd.Flags().StringP("state-dir", "d", "./swarmkitstate", "State directory")
	mainCmd.Flags().String("unlock-key", "", "Unlock key, if raft logs are encrypted")
}

func main() {
	if _, err := mainCmd.ExecuteC(); err != nil {
		os.Exit(-1)
	}
}
