package main

import (
	"github.com/spf13/cobra"
)

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "key",
		Short:        "Manage TPM2 keys",
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newKeyGenCommand(),
		newKeyrmCommand(),
		newKeyReadCommand(),
		newKeyLsCommand(),
	)
	return cmd
}
