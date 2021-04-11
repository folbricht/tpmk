package main

import (
	"io"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/spf13/cobra"
)

type openpgpSignOptions struct {
	armor       bool
	pubArmor    bool
	clearSigned bool
	device      string
	password    string
}

func newOpenPGPSignCommand() *cobra.Command {
	var opt openpgpSignOptions

	cmd := &cobra.Command{
		Use:   "sign <handle> <public> <input> <signature>",
		Short: "Sign data with a TPM key",
		Long: `Signs data using an existing private key in the TPM.
The key must already be present and be an RSA key. Generates a
signature for the <input> data. Input can either be a file or '-' to
read the data from STDIN. Use '-' to write the signature to STDOUT.

By default a detached signature is produced. Use --clear-sign to
generate a clear text signature instead.

While the public key can also be read from STDIN, it is not possible
to read the input data from there at
the same time.`,
		Example: `  tpmk openpgp sign 0x81000000 pub.pgp input.txt input.sig
  tpmk openpgp sign -a 0x81000000 pup.pgp - -
  tpmk openpgp sign -c -m 0x81000000 public.gpg input.txt input.txt.asc
  tpmk openpgp sign -a -m 0x81000000 - input.txt -`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpenPGPSign(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&opt.armor, "armor", "a", false, "Create ASCII armored output")
	flags.BoolVarP(&opt.pubArmor, "public-armor", "m", false, "Public key is armored")
	flags.BoolVarP(&opt.clearSigned, "clear-sign", "c", false, "Output a clear-text signature")
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password for the TPM key")
	return cmd
}

func runOpenPGPSign(opt openpgpSignOptions, args []string) error {
	handle, err := parseHandle(args[0])
	if err != nil {
		return err
	}
	pubkey := args[1]
	input := args[2]
	output := args[3]

	if pubkey == "-" && input == "-" {
		return errors.New("only the public key or the input can be read from stdin, not both")
	}

	if opt.clearSigned && opt.armor {
		return errors.New("can't use --armor with --clear-sign, already armored")
	}

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

	// Read the public key
	var pubData io.Reader = os.Stdin
	if pubkey != "-" {
		f, err := os.Open(pubkey)
		if err != nil {
			return err
		}
		defer f.Close()
		pubData = f
	}
	if opt.pubArmor {
		block, err := armor.Decode(pubData)
		if err != nil {
			return err
		}
		if block.Type != openpgp.PublicKeyType {
			return errors.New("not a public key")
		}
		pubData = block.Body
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(pubData))
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
	if opt.clearSigned {
		return tpmk.OpenPGPClearSign(w, entity, r, nil, priv)
	}
	return tpmk.OpenPGPDetachSign(w, entity, r, nil, priv)
}
