package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

type x509GenOptions struct {
	cakey, cacrt string
	outFormat    string
	duration     string
	commonName   string
	serial       int64
	ipAddresses  []net.IP
	dnsNames     []string
}

func newx509GenCommand() *cobra.Command {
	var opt x509GenOptions

	cmd := &cobra.Command{
		Use:   "generate <keyfile> <certfile>",
		Short: "Generate a certificate",
		Long: `Generate an x509 certificate using the provided public key and
sign it with a CA key.

Use '-' to read the key from STDIN, or to output the certificate 
to STDOUT.`,
		Example: `  tpmk x509 generate publickey.pem certificate.pem`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runx509Gen(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.cakey, "ca-key", "k", "", "CA key file in PEM format")
	flags.StringVarP(&opt.cacrt, "ca-crt", "c", "", "CA certificate file in PEM format")
	flags.StringVarP(&opt.outFormat, "out-format", "f", "pem", "Output format of the certificate")
	flags.StringVar(&opt.duration, "valid-for", "1:0:0", "<years>:<months>:<days> from now the certificate will be valid")
	flags.StringVar(&opt.commonName, "common-name", "", "Common Name")
	flags.Int64Var(&opt.serial, "serial", 0, "Serial number")
	flags.IPSliceVar(&opt.ipAddresses, "san-ips", nil, "SAN IP addresses")
	flags.StringSliceVar(&opt.dnsNames, "san-dns", nil, "SAN DNS names")
	cmd.MarkFlagRequired("ca-key")
	cmd.MarkFlagRequired("ca-crt")
	return cmd
}

func runx509Gen(opt x509GenOptions, args []string) error {
	keyfile := args[0]
	crtfile := args[1]

	expiry, err := ParseDuration(opt.duration)
	if err != nil {
		return errors.Wrap(err, "parsing valid-for")
	}

	// Read the CA
	caCrt, caKey, err := tpmk.LoadKeyPair(opt.cacrt, opt.cakey)
	if err != nil {
		return errors.Wrap(err, "loading CA")
	}

	// Read the public key from file or stdin
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

	// Build the x509 cert template
	template := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     expiry,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(opt.serial),
	}
	if opt.commonName != "" {
		template.Subject = pkix.Name{CommonName: opt.commonName}
	}
	if len(opt.ipAddresses) > 0 {
		template.IPAddresses = opt.ipAddresses
	}
	if len(opt.dnsNames) > 0 {
		template.DNSNames = opt.dnsNames
	}

	// Sign the template
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caCrt,
		public,
		caKey,
	)
	if err != nil {
		return errors.Wrap(err, "generating certificate")
	}

	// Convert DER to the desired output format
	var b []byte
	switch opt.outFormat {
	case "pem":
		b = tpmk.CertToPEM(derBytes)
	case "der":
		b = derBytes
	default:
		return fmt.Errorf("unsupported output format '%s'", opt.outFormat)
	}

	// Write the certificate to file or STDOUT
	if crtfile == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return ioutil.WriteFile(crtfile, b, 0755)
}
