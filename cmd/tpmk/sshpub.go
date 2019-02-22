package main

import (
	"io/ioutil"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"
)

type sshPubOptions struct {
}

func newSSHPubCommand() *cobra.Command {
	var opt sshPubOptions

	cmd := &cobra.Command{
		Use:   "pub <PEMKey> <OpenSSHkey>",
		Short: "Convert a public key into OpenSSH format",
		Long: `Read a PKCS1 public key and turn it into a key compatible
with OpenSSH.

Use '-' to read the key from STDIN, or to output the OpenSSH key 
to STDOUT.`,
		Example: `  tpmk ssh pub publickey.pem id_rsa.pub
  tpmk ssh pub - -`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHPub(opt, args)
		},
		SilenceUsage: true,
	}
	return cmd
}

func runSSHPub(opt sshPubOptions, args []string) error {
	inKeyfile := args[0]
	outKeyfile := args[1]

	// Read the public key from file or stdin and turn it into an SSH public key
	var (
		pk  []byte
		err error
	)
	if inKeyfile == "-" {
		pk, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		pk, err = ioutil.ReadFile(inKeyfile)
		if err != nil {
			return err
		}
	}
	public, err := tpmk.PEMToPubKey(pk)
	if err != nil {
		return errors.Wrap(err, "decode public key")
	}

	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return errors.Wrap(err, "read public key")
	}

	// Write the certificate to file or STDOUT
	b := tpmk.MarshalSSHPublic(sshPublic, "")
	if outKeyfile == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return ioutil.WriteFile(outKeyfile, b, 0755)
}
