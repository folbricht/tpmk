package main

import (
	"github.com/spf13/cobra"
)

func newx509Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "x509",
		Short:        "Manage x509 certificates",
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newx509GenCommand(),
	)
	return cmd
}
