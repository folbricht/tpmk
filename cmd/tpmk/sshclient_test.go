package main

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"

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

	t.Run("Insecure", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key", "")
		defer server.Close()
		err := runClient("-d", "sim", "-k", keyHandle, "user@"+endpoint, "")
		require.NoError(t, err)
	})

	t.Run("Simple Host Key", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key", "")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-host-key.pub", false)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, keyHandle, "user@"+endpoint, "")
		require.NoError(t, err)
	})

	t.Run("Signed Host Key", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key", "testdata/ssh-host-key-cert.pub")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-ca.pub", true)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, keyHandle, "user@"+endpoint, "")
		require.NoError(t, err)
	})

	t.Run("Client Cert in TPM", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key", "testdata/ssh-host-key-cert.pub")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-ca.pub", true)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, "--crt-handle", crtHandle, "--crt-format", "wire", keyHandle, "user@"+endpoint, "")
		require.NoError(t, err)
	})

	t.Run("Signed Host Key with Wrong Cert Type", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key", "testdata/ssh-host-key-cert-wrong-type.pub")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-ca.pub", true)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, "--crt-handle", crtHandle, "--crt-format", "wire", keyHandle, "user@"+endpoint, "")
		require.Error(t, err)
	})

	t.Run("Wrong Host Key", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key-bad", "")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-host-key.pub", false)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, keyHandle, "user@"+endpoint, "")
		require.Error(t, err)
	})

	t.Run("Wrong Host Certificate", func(t *testing.T) {
		endpoint, server := startServer(t, "testdata/ssh-host-key-bad", "testdata/ssh-host-key-bad-cert.pub")
		defer server.Close()
		knownHostsFile := buildKnownHosts(t, tmpdir, endpoint, "testdata/ssh-ca.pub", true)
		err := runClient("-d", "sim", "--known-hosts", knownHostsFile, keyHandle, "user@"+endpoint, "")
		require.Error(t, err)
	})

}

func buildKnownHosts(t *testing.T, tmpdir, addr, keyfile string, isCA bool) string {
	b, err := ioutil.ReadFile(keyfile)
	require.NoError(t, err)
	pub, err := tpmk.ParseOpenSSHPublicKey(b)
	require.NoError(t, err)
	ln := knownhosts.Line([]string{addr}, pub)
	if isCA {
		ln = "@cert-authority " + ln
	}

	f, err := ioutil.TempFile(tmpdir, "")
	require.NoError(t, err)
	defer f.Close()
	_, err = io.Copy(f, strings.NewReader(ln))
	require.NoError(t, err)
	return f.Name()
}

func runClient(args ...string) error {
	cmd := newSSHClientCommand()
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func startServer(t *testing.T, hostKey, hostCrt string) (string, *sshtest.Server) {
	key, err := sshtest.KeyFromFile(hostKey, hostCrt)
	require.NoError(t, err)

	server := sshtest.NewServer(key)
	return server.Endpoint, server
}
