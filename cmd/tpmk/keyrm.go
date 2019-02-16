package main

import (
	"github.com/folbricht/tpmk"
	"github.com/spf13/cobra"
)

type keyrmOptions struct {
	device   string
	password string
}

func newKeyrmCommand() *cobra.Command {
	var opt keyrmOptions

	cmd := &cobra.Command{
		Use:     "rm <handle>",
		Short:   "Remove a persistent key",
		Long:    `Remove a persistent key at the specified handle.`,
		Example: `  tpmk key rm 0x81000000`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyRm(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	return cmd
}

func runKeyRm(opt keyrmOptions, args []string) error {
	// Parse arguments
	handle, err := ParseHandle(args[0])
	if err != nil {
		return err
	}

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	return tpmk.DeleteKey(dev, handle, opt.password)
}
