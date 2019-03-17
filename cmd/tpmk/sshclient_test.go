package main

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/folbricht/tpmk"
	"github.com/folbricht/tpmk/sshtest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error { return nil }

func TestSSHClient(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "tpmk")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)

	// Handles
	const (
		keyHandle = "0x81000000"
		crtHandle = "0x1000000"
	)

	// Define file paths
	pubKeyFile := filepath.Join(tmpdir, "pub-key.pem")
	clientCrtFile := filepath.Join(tmpdir, "id_rsa-cert.pub")
	clientCrtFileWire := filepath.Join(tmpdir, "id_rsa_wire-cert.pub")
	caKeyFile := filepath.Join("testdata", "ssh-ca")
	caPubFile := filepath.Join("testdata", "ssh-ca.pub")
	hostKeyFile := filepath.Join("testdata", "ssh-host-key")
	hostPubFile := filepath.Join("testdata", "ssh-host-key.pub")
	hostCrtFile := filepath.Join("testdata", "ssh-host-key-cert.pub")
	hostCrtFileWrongType := filepath.Join("testdata", "ssh-host-key-cert-wrong-type.pub")
	hostKeyFileBad := filepath.Join("testdata", "ssh-host-key-bad")
	hostCrtFileBad := filepath.Join("testdata", "ssh-host-key-bad-cert.pub")

	// Open sim device
	var dev io.ReadWriteCloser
	dev, err = simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	// Make sure the device doesn't get closed prematurely by one of the commands
	dev = nopCloser{dev}
	tpmk.SimDev = dev

	// Generate the client key in the TPM using "tpmk key generate ..."
	cmd := newKeyGenCommand()
	cmd.SetArgs([]string{"-d", "sim", keyHandle, pubKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	// Generate SSH certificate file with "tpmk ssh certificate ..."
	cmd = newSSHCertCommand()
	cmd.SetArgs([]string{"--ca-key", caKeyFile, pubKeyFile, clientCrtFile})
	err = cmd.Execute()
	require.NoError(t, err)

	// Convert the cert in wire format for storage in the TPM
	b, err := ioutil.ReadFile(clientCrtFile)
	require.NoError(t, err)
	pub, err := tpmk.ParseOpenSSHPublicKey(b)
	require.NoError(t, err)
	crt, ok := pub.(*ssh.Certificate)
	if !ok {
		require.True(t, ok, "client cert file not of the right type")
	}
	ioutil.WriteFile(clientCrtFileWire, crt.Marshal(), 0660)
	require.NoError(t, err)

	// Store the wire-format cert in the TPM in an NV index
	cmd = newNVWriteCommand()
	cmd.SetArgs([]string{"-d", "sim", crtHandle, clientCrtFileWire})
	err = cmd.Execute()
	require.NoError(t, err)

	// Read the host keys/certs
	hostKeyGood := hostKeyFromFile(t, hostKeyFile, "")
	hostKeyCrtGood := hostKeyFromFile(t, hostKeyFile, hostCrtFile)
	hostKeyCrtWrongType := hostKeyFromFile(t, hostKeyFile, hostCrtFileWrongType)
	hostKeyBad := hostKeyFromFile(t, hostKeyFileBad, "")
	hostKeyCrtBad := hostKeyFromFile(t, hostKeyFileBad, hostCrtFileBad)

	tests := map[string]struct {
		hostKey   ssh.Signer
		args      []string
		shoudFail bool
	}{
		"Insecure": {
			hostKey:   hostKeyGood,
			args:      []string{"-d", "sim", "--insecure", keyHandle},
			shoudFail: false,
		},
		"Simple Host Key": {
			hostKey:   hostKeyGood,
			args:      []string{"-d", "sim", "--host-key-file", hostPubFile, keyHandle},
			shoudFail: false,
		},
		"Signed Host Key": {
			hostKey:   hostKeyCrtGood,
			args:      []string{"-d", "sim", "--host-key-file", caPubFile, keyHandle},
			shoudFail: false,
		},
		"Signed Host Key With Client CRT in TPM": {
			hostKey:   hostKeyCrtGood,
			args:      []string{"-d", "sim", "--crt-handle", crtHandle, "--crt-format", "wire", "--host-key-file", caPubFile, keyHandle},
			shoudFail: false,
		},
		"Signed Host Key with Wrong Cert Type": {
			hostKey:   hostKeyCrtWrongType,
			args:      []string{"-d", "sim", "--host-key-file", caPubFile, keyHandle},
			shoudFail: true,
		},
		"Wrong Host Key": {
			hostKey:   hostKeyBad,
			args:      []string{"-d", "sim", "--host-key-file", hostPubFile, keyHandle},
			shoudFail: true,
		},
		"Wrong Host Certificate": {
			hostKey:   hostKeyCrtBad,
			args:      []string{"-d", "sim", "--host-key-file", hostPubFile, keyHandle},
			shoudFail: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Start an SSH server
			server := sshtest.NewServer(test.hostKey)
			defer server.Close()

			// Expand the command line args with the right endpoint address
			test.args = append(test.args, "root@"+server.Endpoint, "")

			// Run the command and make sure we got the expected error
			cmd := newSSHClientCommand()
			cmd.SetArgs(test.args)
			cmd.SilenceErrors = true
			err = cmd.Execute()
			if test.shoudFail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func hostKeyFromFile(t *testing.T, keyfile, crtfile string) ssh.Signer {
	b, err := ioutil.ReadFile(keyfile)
	require.NoError(t, err)
	hostKey, err := ssh.ParsePrivateKey(b)
	require.NoError(t, err)
	// If a cert is provided as well, extend the ssh.Signer with a cert
	if crtfile != "" {
		b, err := ioutil.ReadFile(crtfile)
		require.NoError(t, err)
		pub, err := tpmk.ParseOpenSSHPublicKey(b)
		require.NoError(t, err)
		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			require.True(t, ok, "client cert file not of the right type")
		}
		hostKey, err = ssh.NewCertSigner(crt, hostKey)
		require.NoError(t, err)
	}
	return hostKey
}
