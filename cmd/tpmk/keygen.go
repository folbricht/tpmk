package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

type keygenOptions struct {
	device   string
	password string
}

func newKeyGenCommand() *cobra.Command {
	var opt keygenOptions

	cmd := &cobra.Command{
		Use:   "generate <handle> <public-key>",
		Short: "Generate a key and make it persistent",
		Long: `Generate a key in the TPM and make the key persistent.

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
	return cmd
}

func runKeyGen(opt keygenOptions, args []string) error {
	// Parse arguments
	handle, err := ParseHandle(args[0])
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

	// Generate the key
	attr := tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
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
