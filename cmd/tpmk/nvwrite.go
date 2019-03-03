package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type nvwriteOptions struct {
	device   string
	password string
	attr     string
}

func newNVWriteCommand() *cobra.Command {
	var opt nvwriteOptions

	cmd := &cobra.Command{
		Use:   "write <index> <file>",
		Short: "Write raw data into an NV index",
		Long: `Create a new NV index and write data into it.

NV Index attributes determine how the data can be written or
accessed. See the TPM 2.0 spec, Part 2, section 13.4 for details.
Available attributes:
  ppwrite     
  ownerwrite
  authwrite
  policywrite
  policydelete
  writelocked
  writeall
  writedefine
  writestclear
  globallock
  ppread
  ownerread
  authread
  policyread
  noda
  orderly
  clearstclear
  readlocked
  written
  platformcreate
  readstclear

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
	flags.StringVarP(&opt.attr, "attributes", "a", "ownerwrite|ownerread|authread|ppread", "NV index attributes")
	return cmd
}

func runNVWrite(opt nvwriteOptions, args []string) error {
	// Parse arguments
	index, err := ParseHandle(args[0])
	if err != nil {
		return err
	}
	input := args[1]
	attr, err := parseNVAttributes(opt.attr)
	if err != nil {
		return errors.Wrap(err, "NV index attributes")
	}

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
	return tpmk.NVWrite(dev, index, b, opt.password, attr)
}
