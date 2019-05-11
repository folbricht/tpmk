package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	// Register the sub-commands under root
	rootCmd := newRootCommand()
	rootCmd.AddCommand(
		newNVCommand(),
		newKeyCommand(),
		newx509Command(),
		newSSHCommand(),
	)
	rootCmd.SetOutput(os.Stderr)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tpmk",
		Short: "TPM2 key and storage management toolkit",
	}
	return cmd
}
