package main

import (
	"github.com/spf13/cobra"
)

func newOpenPGPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "openpgp",
		Short:        "Manage OpenPGP identities and sign data",
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newOpenPGPGenCommand(),
		newOpenPGPSignCommand(),
		newOpenPGPDecryptCommand(),
	)
	return cmd
}
