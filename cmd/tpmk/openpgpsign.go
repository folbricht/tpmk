package main

import (
	"io"
	"os"

	"github.com/folbricht/tpmk"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/spf13/cobra"
)

type openpgpSignOptions struct {
	armor    bool
	device   string
	password string
}

func newOpenPGPSignCommand() *cobra.Command {
	var opt openpgpSignOptions

	cmd := &cobra.Command{
		Use:   "sign <handle> <input> <signature>",
		Short: "Sign data with a TPM key",
		Long: `Signs data using an existing private key in the TPM.
The key must already be present and be an RSA key. Generates a
detached signature for the <input> data. Input can either be a
file or '-' to read the data from STDIN. Use '-' to write the
signature to STDOUT.`,
		Example: `  tpmk openpgp sign 0x81000000 input.txt input.sig
  tpmk openpgp sign -a 0x81000000 - -`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpenPGPSign(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&opt.armor, "armor", "a", false, "Create ASCII armored output")
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password for the TPM key")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func runOpenPGPSign(opt openpgpSignOptions, args []string) error {
	handle, err := parseHandle(args[0])
	if err != nil {
		return err
	}
	input := args[1]
	output := args[2]

	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Open the TPM key
	priv, err := tpmk.NewRSAPrivateKey(dev, handle, opt.password)
	if err != nil {
		return err
	}

	// Data reader
	var r io.Reader = os.Stdin
	if input != "-" {
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	// Signature writer
	var w io.Writer = os.Stdout
	if output != "-" {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	if opt.armor {
		encoder, err := armor.Encode(w, openpgp.SignatureType, nil)
		if err != nil {
			return err
		}
		defer encoder.Close()
		w = encoder
	}

	// Generate and write the signature
	return tpmk.OpenPGPDetachSign(w, priv, r, nil)
}
