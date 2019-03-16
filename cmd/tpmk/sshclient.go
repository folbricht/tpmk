package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type sshClientOptions struct {
	device      string
	keyPassword string
	crtPassword string
	crtFormat   string
	crtFile     string
	crtHandle   string
	hostKeyFile string
	insecure    bool
}

func newSSHClientCommand() *cobra.Command {
	var opt sshClientOptions

	cmd := &cobra.Command{
		Use:   "client <handle> <user@host:port> <command>",
		Short: "Execute a command remotely",
		Long: `Executes a command on an SSH server using a key in the TPM
and reads/writes to it via STDIN/STDOUT.`,
		Example: `  tpmk ssh client 0x81000000 root@host:22 "ls -l"

  tpmk ssh client -i 0x1500000 -s ca.pub 0x81000000 root@host:22 "whoami"`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHClient(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	flags.StringVarP(&opt.keyPassword, "key-password", "p", "", "TPM key password")
	flags.StringVarP(&opt.hostKeyFile, "host-key-file", "s", "", "Acceptable host key or CA")
	flags.StringVarP(&opt.crtFile, "crt-file", "c", "", "Client certificate file")
	flags.StringVarP(&opt.crtHandle, "crt-handle", "i", "", "Read the client cert from TPM NV index")
	flags.StringVarP(&opt.crtPassword, "crt-password", "n", "", "TPM NV index password")
	flags.StringVarP(&opt.crtFormat, "crt-format", "f", "openssh", "Format of the client cert")
	flags.BoolVarP(&opt.insecure, "insecure", "k", false, "Accept any host key")
	return cmd
}

func runSSHClient(opt sshClientOptions, args []string) error {
	keyHandle, err := parseHandle(args[0])
	if err != nil {
		return err
	}
	remote := args[1]
	command := args[2]

	// Confirm that the provided arguments make sense
	if opt.insecure && opt.hostKeyFile != "" {
		return errors.New("can't use -k with -s")
	}
	if !opt.insecure && opt.hostKeyFile == "" {
		return errors.New("require either -k or -s")
	}
	if opt.crtFile != "" && opt.crtHandle != "" {
		return errors.New("can use either -c or -i, not both")
	}

	// Parse the remote location into user and host
	s := strings.Split(remote, "@")
	if len(s) != 2 {
		return errors.New("require user@host:port for remote endpoint")
	}
	user := s[0]
	host := s[1]

	// Open the TPM
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return errors.Wrap(err, "opening "+opt.device)
	}
	defer dev.Close()

	// Use the key in the TPM to build an ssh.Signer
	pk, err := tpmk.NewRSAPrivateKey(dev, keyHandle, opt.keyPassword)
	if err != nil {
		return errors.Wrap(err, "accessing key")
	}
	signer, err := ssh.NewSignerFromSigner(pk)
	if err != nil {
		return errors.Wrap(err, "invalid key")
	}

	// Use client certificate, if provided to extend the ssh.Signer with
	if opt.crtFile != "" || opt.crtHandle != "" {
		var b []byte
		var err error
		if opt.crtHandle != "" { // Read the cert from NV
			crtHandle, err := parseHandle(opt.crtHandle)
			if err != nil {
				return err
			}
			b, err = tpmk.NVRead(dev, crtHandle, "")
			if err != nil {
				return errors.Wrap(err, "reading crt from TPM")
			}
		} else { // Read the cert from file
			b, err = ioutil.ReadFile(opt.crtFile)
			if err != nil {
				return errors.Wrap(err, "reading client crt file")
			}
		}

		// Unmarshall the certificate according to the provided format
		var pub ssh.PublicKey
		switch opt.crtFormat {
		case "openssh":
			pub, err = tpmk.ParseOpenSSHPublicKey(b)
		case "wire":
			pub, err = ssh.ParsePublicKey(b)
		default:
			return fmt.Errorf("unsupported certificate format '%s", opt.crtFormat)
		}
		if err != nil {
			return errors.Wrap(err, "parsing client crt file")
		}

		// Make sure the provided cert really was one
		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			return errors.New("client cert file not of the right type")
		}

		// Extend the signer used in the handshake to present the cert to the server
		signer, err = ssh.NewCertSigner(crt, signer)
		if err != nil {
			return err
		}
	}

	// Decide how to validate the host key
	var hostKeyCallback ssh.HostKeyCallback
	if opt.hostKeyFile != "" {
		b, err := ioutil.ReadFile(opt.hostKeyFile)
		if err != nil {
			return errors.Wrap(err, "reading host key file")
		}
		hostKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return errors.Wrap(err, "parsing host key file")
		}
		cc := ssh.CertChecker{
			// Either the signer of the presented cert matches our allowed host key
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return bytes.Equal(hostKey.Marshal(), auth.Marshal())
			},
			// Or the allowed host key is presented directly
			HostKeyFallback: ssh.FixedHostKey(hostKey),
		}
		hostKeyCallback = cc.CheckHostKey
	}

	// If -k is used, don't validate and accept anything presented by the host
	if opt.insecure {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// Build SSH client config with just public key auth
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	// Connect to the SSH server and start a session
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return errors.Wrap(err, "connecting to "+host)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return errors.Wrap(err, "creating SSH session")
	}
	defer session.Close()

	// Hook up in/out/err to the command and execute it
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	return session.Run(command)
}
