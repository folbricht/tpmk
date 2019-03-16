package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type keygenOptions struct {
	device   string
	password string
	attr     string
}

func newKeyGenCommand() *cobra.Command {
	var opt keygenOptions

	cmd := &cobra.Command{
		Use:   "generate <handle> <public-key>",
		Short: "Generate a key and make it persistent",
		Long: `Generate a primary key in the TPM and make it persistent.

Key attributes determine how the generated key can be used.
The default attributes allow it to be used for signing and
decryption. Refer to the TPM 2.0 specification, Part 2,
Section 8.3 for a detailed description of the attributes.
Available attributes:
  fixedtpm
  fixedparent
  sensitivedataorigin
  userwithauth
  adminwithpolicy
  noda
  restricted
  decrypt
  sign

Use '-' to write the key to STDOUT.`,
		Example: `  tpmk key generate 0x81000000 public.pem`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyGen(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	flags.StringVarP(&opt.attr, "attributes", "a", "sign|decrypt|userwithauth|sensitivedataorigin", "Key attributes")
	return cmd
}

func runKeyGen(opt keygenOptions, args []string) error {
	// Parse arguments
	handle, err := parseHandle(args[0])
	if err != nil {
		return err
	}
	output := args[1]
	attr, err := parseKeyAttributes(opt.attr)
	if err != nil {
		return errors.Wrap(err, "key attributes")
	}

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Generate the key
	pub, err := tpmk.GenRSAPrimaryKey(dev, handle, opt.password, opt.password, attr)
	if err != nil {
		return err
	}

	// Encode the public key
	pem, err := tpmk.PubKeyToPEM(pub)
	if err != nil {
		return err
	}

	// Write the public portion to file or STDOUT
	if output == "-" {
		_, err = os.Stdout.Write(pem)
		return err
	}
	return ioutil.WriteFile(output, pem, 0755)
}
