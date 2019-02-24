package main

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type keyImportOptions struct {
	device   string
	password string
}

func newKeyImportCommand() *cobra.Command {
	var opt keyImportOptions

	cmd := &cobra.Command{
		Use:   "import <handle> <private-key>",
		Short: "Import an existing key",
		Long: `Import a key into the TPM. The key should be
in PEM-encode PKCS#1 format.

Use '-' to read the key from STDIN.`,
		Example: `  tpmk key import 0x81000000 private.pem`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyImport(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.password, "password", "p", "", "Password")
	return cmd
}

func runKeyImport(opt keyImportOptions, args []string) error {
	return errors.New("not yet implemented")
	// // Parse arguments
	// handle, err := ParseHandle(args[0])
	// if err != nil {
	// 	return err
	// }
	// keyfile := args[1]

	// // Open device or simulator
	// dev, err := tpmk.OpenDevice(opt.device)
	// if err != nil {
	// 	return err
	// }
	// defer dev.Close()

	// // Read the public key from file or stdin and turn it into an SSH public key
	// var pk []byte
	// if keyfile == "-" {
	// 	pk, err = ioutil.ReadAll(os.Stdin)
	// 	if err != nil {
	// 		return err
	// 	}
	// } else {
	// 	pk, err = ioutil.ReadFile(keyfile)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// private, err := tpmk.PEMToPrivKey(pk)
	// if err != nil {
	// 	return errors.Wrap(err, "decode private key")
	// }

	// // Import the key
	// attr := tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
	// return tpmk.ImportKey(dev, handle, private, opt.password, attr)
}
