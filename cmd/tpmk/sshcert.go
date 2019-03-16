package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math"
	"os"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"
)

type sshCertOptions struct {
	cakey      string
	id         string
	serial     uint64
	options    []string
	extensions []string
	host       bool
	outFormat  string
}

func newSSHCertCommand() *cobra.Command {
	var opt sshCertOptions

	cmd := &cobra.Command{
		Use:   "certificate <keyfile> <certfile>",
		Short: "Generate a certificate",
		Long: `Generate an SSH certificate using the provided public key and
sign it with a CA key.

The certificat format can be 'openssh' or 'wire' which is smaller
and more suitable for storage in NV indexes.

Use '-' to read the key from STDIN, or to output the certificate 
to STDOUT.`,
		Example: `  tpmk ssh certificate publickey.pem tpm-cert.pub
  tpmk ssh certificate -O force-command=ls --serial 123 - -`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHCert(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.cakey, "ca-key", "k", "", "SSH CA key file")
	flags.StringVar(&opt.id, "id", "", "Certificate identifier")
	flags.Uint64Var(&opt.serial, "serial", 0, "Serial")
	flags.StringSliceVarP(&opt.options, "option", "O", nil, "Certificate option in the form <key>=[<value>]")
	flags.StringSliceVarP(&opt.extensions, "extension", "E", nil, "Certificate extension in the form <key>=[<value>]")
	flags.BoolVarP(&opt.host, "host", "H", false, "Generate a host certificate instead of a user certificate")
	flags.StringVarP(&opt.outFormat, "out-format", "f", "openssh", "Output format")
	cmd.MarkFlagRequired("ca-key")
	return cmd
}

func runSSHCert(opt sshCertOptions, args []string) error {
	keyfile := args[0]
	crtfile := args[1]
	format, err := parseSSHFormat(opt.outFormat)
	if err != nil {
		return err
	}

	// Parse certificate options and extensions
	criticalOptions := parseOptionsMap(opt.options)
	extensions := parseOptionsMap(opt.extensions)

	// Read the CA
	k, err := ioutil.ReadFile(opt.cakey)
	if err != nil {
		return errors.Wrap(err, "opening CA")
	}
	caKey, err := ssh.ParsePrivateKey(k)
	if err != nil {
		return errors.Wrap(err, "reading CA")
	}

	// Read the public key from file or stdin and turn it into an SSH public key
	var pk []byte
	if keyfile == "-" {
		pk, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		pk, err = ioutil.ReadFile(keyfile)
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

	// Build a cert
	cert := ssh.Certificate{
		Key:         sshPublic,
		CertType:    ssh.UserCert,
		KeyId:       opt.id,
		ValidAfter:  0, // 0 - MaxUint64 = "forever"
		ValidBefore: math.MaxUint64,
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}
	if opt.host {
		cert.CertType = ssh.HostCert
	}

	// Sign the cert
	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		return errors.Wrap(err, "signing certificate")
	}

	// Marshal the cert into the desired format
	var b []byte
	switch format {
	case formatOpenSSH:
		b = tpmk.MarshalSSHPublic(&cert, cert.KeyId)
	case formatWire:
		b = cert.Marshal()
	default:
		return fmt.Errorf("unsupported output format %d", format)
	}

	// Write it to file or STDOUT
	if crtfile == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return ioutil.WriteFile(crtfile, b, 0755)
}
