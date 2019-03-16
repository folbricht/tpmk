package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type keyReadOptions struct {
	device string
}

func newKeyReadCommand() *cobra.Command {
	var opt keyReadOptions

	cmd := &cobra.Command{
		Use:   "read <handle> <public-key>",
		Short: "Read the public key",
		Long: `Read the public part of a key in the TPM.
Use '-' to write the key to STDOUT.`,
		Example: `  tpmk key read 0x81000000 public.pem`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyRead(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	return cmd
}

func runKeyRead(opt keyReadOptions, args []string) error {
	// Parse arguments
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

	_, pub, err := tpmk.ReadPublicKey(dev, handle)
	if err != nil {
		return errors.Wrap(err, "reading public key")
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
