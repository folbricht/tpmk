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

type openpgpDecryptOptions struct {
	armor    bool
	pubArmor bool
	device   string
	password string
}

func newOpenPGPDecryptCommand() *cobra.Command {
	var opt openpgpDecryptOptions

	cmd := &cobra.Command{
		Use:   "decrypt <handle> <public> <input> <output>",
		Short: "Decrypt data with a TPM key",
		Long: `Decrypt data using an existing private key in the TPM.
The key must already be present and be an RSA key. Input can either 
be a file or '-' to read the data from STDIN. Use '-' to write the
output to STDOUT.

This command does not validate any signatures, but it will exit with
a non-zero exit code if an invalid MAC is encountered. Note that the
decrypted data is written to the output even though validation may
only happen after it is fully decrypted. The exit code has to be used
to determine if decryption was successful.

While the public key can also be read from STDIN, it is not possible
to read the input data from there at the same time.`,
		Example: `  tpmk openpgp decrypt 0x81000000 pub.pgp encrypted.pgp decrypted.txt
  tpmk openpgp decrypt -a 0x81000000 pup.pgp - -
  tpmk openpgp decrypt -a -m 0x81000000 - secret.txt.pgp -`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpenPGPDecrypt(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.BoolVarP(&opt.armor, "armor", "a", false, "Input data is armored")
	flags.BoolVarP(&opt.pubArmor, "public-armor", "m", false, "Public key is armored")
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password for the TPM key")
	return cmd
}

func runOpenPGPDecrypt(opt openpgpDecryptOptions, args []string) error {
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
	entity, err := tpmk.ReadOpenPGPEntity(packet.NewReader(pubData), priv)
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
	if opt.armor {
		block, err := armor.Decode(r)
		if err != nil {
			return err
		}
		r = block.Body
	}

	// Output writer
	var w io.Writer = os.Stdout
	if output != "-" {
		f, err := os.Create(output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	// Decrypt the data, md.UnverifiedBody needs to be read whole before any signature or
	// MAC is checked.
	md, err := openpgp.ReadMessage(r, openpgp.EntityList([]*openpgp.Entity{entity}), nil, nil)
	if err != nil {
		return err
	}
	if _, err = io.Copy(w, md.UnverifiedBody); err != nil {
		return err
	}
	return md.SignatureError
}
