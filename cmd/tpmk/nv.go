package main

import (
	"github.com/spf13/cobra"
)

func newNVCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "nv",
		Short:        "Manage TPM2 NV storage",
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newNVWriteCommand(),
		newNVReadCommand(),
		newNVRmCommand(),
		newNVLsCommand(),
	)
	return cmd
}
