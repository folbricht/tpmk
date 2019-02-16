package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

type nvwriteOptions struct {
	device   string
	password string
}

func newNVWriteCommand() *cobra.Command {
	var opt nvwriteOptions

	cmd := &cobra.Command{
		Use:   "write <index> <file>",
		Short: "Write raw data into an NV index",
		Long: `Write data into an NV index.

Use '-' to read the data from STDIN.`,
		Example: `  tpmk nv write 0x1500000 cert.der`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNVWrite(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	return cmd
}

func runNVWrite(opt nvwriteOptions, args []string) error {
	// Parse arguments
	index, err := ParseHandle(args[0])
	if err != nil {
		return err
	}
	input := args[1]

	// Read the input, from file or stdin
	var b []byte
	if input == "-" {
		b, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		b, err = ioutil.ReadFile(input)
		if err != nil {
			return err
		}
	}

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Write to the index
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPPRead
	return tpmk.NVWrite(dev, index, b, opt.password, attr)
}
