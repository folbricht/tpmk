package main

import (
	"io"
	"os"

	"github.com/folbricht/tpmk"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/spf13/cobra"
)

type openpgpGenOptions struct {
	armor    bool
	device   string
	password string
	name     string
	comment  string
	email    string
}

func newOpenPGPGenCommand() *cobra.Command {
	var opt openpgpGenOptions

	cmd := &cobra.Command{
		Use:   "generate <handle> <pubkeyfile>",
		Short: "Generate an public key",
		Long: `Generate an OpenPGP public key using an existing private key in the TPM.
The key must already be present and be an RSA key. The generated public
key will contain one identity which must be provided with -n and -e.

Use '-' to write the public key to STDOUT.`,
		Example: `  tpmk openpgp generate -n Testing -e test@example.com 0x81000000 pub.pgp
  tpmk openpgp generate -a -n Testing -e test@example.com 0x81000000 -`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpenPGPGen(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&opt.armor, "armor", "a", false, "Create ASCII armored output")
	flags.StringVarP(&opt.name, "name", "n", "", "Identity name")
	flags.StringVarP(&opt.comment, "comment", "c", "", "Identity comment")
	flags.StringVarP(&opt.email, "email", "e", "", "Identity email")
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password for the TPM key")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("email")
	return cmd
}

func runOpenPGPGen(opt openpgpGenOptions, args []string) error {
	handle, err := parseHandle(args[0])
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

	// Open the TPM key
	priv, err := tpmk.NewRSAPrivateKey(dev, handle, opt.password)
	if err != nil {
		return err
	}

	// Build an identity with the TPM key
	entity, err := tpmk.NewOpenPGPEntity(opt.name, opt.comment, opt.email, nil, priv)
	if err != nil {
		return err
	}

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
		encoder, err := armor.Encode(w, openpgp.PublicKeyType, nil)
		if err != nil {
			return err
		}
		defer encoder.Close()
		w = encoder
	}

	// Serialize the entity (public part)
	return entity.Serialize(w)
}
