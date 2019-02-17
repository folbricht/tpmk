package main

import (
	"github.com/spf13/cobra"
)

func newSSHCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "ssh",
		Short:        "Manage SSH certificates",
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newSSHCertCommand(),
	)
	return cmd
}
