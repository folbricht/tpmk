package tpmk

import (
	"crypto/rand"
	"crypto/rsa"
	"math"
	"net"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSSHClient(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		clientHandle = 0x81000000
		serverHandle = 0x81000001
		pw           = ""
		clientAttr   = tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
		serverAttr   = tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
	)

	// Generate the primary client key as well as a server key (could use the same)
	_, err = GenRSAPrimaryKey(dev, clientHandle, pw, pw, clientAttr)
	require.NoError(t, err)
	_, err = GenRSAPrimaryKey(dev, serverHandle, pw, pw, serverAttr)
	require.NoError(t, err)

	// Use the private keys in the TPM
	clientPriv, err := NewRSAPrivateKey(dev, clientHandle, pw)
	require.NoError(t, err)
	serverPriv, err := NewRSAPrivateKey(dev, serverHandle, pw)
	require.NoError(t, err)

	// Create ssh.Signer for server and client
	clientKey, err := ssh.NewSignerFromSigner(clientPriv)
	require.NoError(t, err)
	hostKey, err := ssh.NewSignerFromSigner(serverPriv)
	require.NoError(t, err)

	// SSH server and client configs
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	serverConfig.AddHostKey(hostKey)
	clientConfig := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Start a listener on a random port. It'd be nice to use net.Pipe() instead but that won't work
	// with SSH since those pipes are fully synchronous. The SSH server and client first write their
	// version and then read the others version. The Write blocks indefinitely when using net.Pipe().
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Start the SSH server
	go func() {
		// Accept a single incoming connection
		serverConn, err := listener.Accept()
		require.NoError(t, err)
		defer serverConn.Close()

		// Perform the SSH handshake on the connection
		_, _, _, err = ssh.NewServerConn(serverConn, serverConfig)
		require.NoError(t, err)

		// Terminate the server without actually using the channels or servicing requests.
		// The handshake is all that matters here.
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()
	// Connect to the server and build an SSH client
	c, chans, reqs, err := ssh.NewClientConn(clientConn, ":22", clientConfig)
	require.NoError(t, err)

	// Perform SSH handshake with the server
	ssh.NewClient(c, chans, reqs)
}

func TestUnmarshalSSHCertificate(t *testing.T) {
	// Generate am SSH CA
	ca, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sshCA, err := ssh.NewSignerFromSigner(ca)
	require.NoError(t, err)

	// Generate a key for the cert
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sshPublic, err := ssh.NewPublicKey(key.Public())
	require.NoError(t, err)

	// Build a cert for the key, and sign it with the CA
	in := &ssh.Certificate{
		Serial:      123,
		Key:         sshPublic,
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidAfter:  0,
		ValidBefore: math.MaxUint64,
		Reserved:    []uint8{},
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{
				"force-command": "ls",
			},
			Extensions: map[string]string{},
		},
	}
	err = in.SignCert(rand.Reader, sshCA)
	require.NoError(t, err)

	// Encode the cert into OpenSSH format
	// encoded := in.Marshal()
	encoded := MarshalOpenSSHPublic(in, in.KeyId)

	// Decode OpenSSH format
	decoded, err := ParseOpenSSHPublicKey(encoded)
	require.NoError(t, err)

	// Compare the decoded cert to what went in
	out, ok := decoded.(*ssh.Certificate)
	require.True(t, ok)
	require.Equal(t, in, out)
}
