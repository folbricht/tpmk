package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/spf13/cobra"
)

type nvReadOptions struct {
	device   string
	password string
}

func newNVReadCommand() *cobra.Command {
	var opt nvReadOptions

	cmd := &cobra.Command{
		Use:   "read <index> <file>",
		Short: "Read raw data from an NV index",
		Long: `Read data from an NV index.

Use '-' to print the data to STDOUT.`,
		Example: `  tpmk nv read 0x1500000 cert.der`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNVRead(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	return cmd
}

func runNVRead(opt nvReadOptions, args []string) error {
	// Parse arguments
	index, err := ParseHandle(args[0])
	if err != nil {
		return err
	}
	output := args[1]

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Read the data
	b, err := tpmk.NVRead(dev, index, opt.password)
	if err != nil {
		return err
	}

	// Write the data into the output file or STDOUT
	if output == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return ioutil.WriteFile(output, b, 0755)
}
