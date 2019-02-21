package main

import (
	"github.com/folbricht/tpmk"
	"github.com/spf13/cobra"
)

type nvRmOptions struct {
	device   string
	password string
}

func newNVRmCommand() *cobra.Command {
	var opt nvRmOptions

	cmd := &cobra.Command{
		Use:   "rm <index>",
		Short: "Delete an NV index",
		Long: `Delete data in an NV index and make the index available
again.

Use '-' to print the data to STDOUT.`,
		Example: `  tpmk nv rm 0x1500000`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNVRm(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	return cmd
}

func runNVRm(opt nvRmOptions, args []string) error {
	// Parse arguments
	index, err := ParseHandle(args[0])
	if err != nil {
		return err
	}

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Delete the index
	return tpmk.NVDelete(dev, index, opt.password)
}
