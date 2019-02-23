package tpmk

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestMutualTLS(t *testing.T) {
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
	clientPub, err := GenRSAPrimaryKey(dev, clientHandle, pw, pw, clientAttr)
	require.NoError(t, err)
	serverPub, err := GenRSAPrimaryKey(dev, serverHandle, pw, pw, serverAttr)
	require.NoError(t, err)

	// Use the private keys in the TPM
	clientPriv, err := NewRSAPrivateKey(dev, clientHandle, pw)
	require.NoError(t, err)
	serverPriv, err := NewRSAPrivateKey(dev, serverHandle, pw)
	require.NoError(t, err)

	// Load the CA
	caCrt, caKey, err := LoadKeyPair("testdata/ca.crt", "testdata/ca.key")
	require.NoError(t, err)

	// Build the x509 certificate templates for client and server
	clientTemplate := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(0),
	}
	serverTemplate := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: big.NewInt(0),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Sign the templates with the same CA
	clientCrtDER, err := x509.CreateCertificate(
		rand.Reader,
		&clientTemplate,
		caCrt,
		clientPub,
		caKey,
	)
	require.NoError(t, err)
	serverCrtDER, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		caCrt,
		serverPub,
		caKey,
	)
	require.NoError(t, err)

	// Build the TLS certificates for the mutual TLS connection
	clientCrt := tls.Certificate{
		Certificate: [][]byte{clientCrtDER},
		PrivateKey:  clientPriv,
	}
	serverCrt := tls.Certificate{
		Certificate: [][]byte{serverCrtDER},
		PrivateKey:  serverPriv,
	}

	// Certificate pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCrt)

	// Build the client TLS config
	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCrt},
		RootCAs:      caPool,
	}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCrt},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Initialize the server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	server.TLS = serverCfg

	server.StartTLS()
	defer server.Close()

	// Initialize an client and do an HTTP GET to the server
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientCfg,
		},
	}
	res, err := client.Get(server.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, "Hello, client\n", string(b))
}
