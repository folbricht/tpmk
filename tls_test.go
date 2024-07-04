package tpmk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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
	"github.com/google/go-tpm/legacy/tpm2"
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

func TestSign(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		handle = 0x81000000
		pw     = ""
		attr   = tpm2.FlagSign | tpm2.FlagUserWithAuth | tpm2.FlagSensitiveDataOrigin
	)

	pub, err := GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)

	// Use the key in the TPM for signing
	priv, err := NewRSAPrivateKey(dev, handle, pw)
	require.NoError(t, err)

	data := []byte("This is a test")
	digestSHA256 := sha256.Sum256(data)
	digestSHA1 := sha1.Sum(data)

	tests := map[string]struct {
		digest []byte
		opts   crypto.SignerOpts
	}{
		"RSA-PKCS#1 v1.5 with SHA1":   {digestSHA1[:], crypto.SHA1},
		"RSA-PKCS#1 v1.5 with SHA256": {digestSHA256[:], crypto.SHA256},
		"RSA-PSS with SHA1":           {digestSHA1[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA1}},
		"RSA-PSS with SHA256":         {digestSHA256[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Sign the data with the loaded key in the TPM
			signature, err := priv.Sign(nil, test.digest, test.opts)
			require.NoError(t, err)

			// Verify the signature, depending on algorithm
			switch opts := test.opts.(type) {
			case crypto.Hash:
				err = rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), opts, test.digest, signature)
				require.NoError(t, err)
			case *rsa.PSSOptions:
				err = rsa.VerifyPSS(pub.(*rsa.PublicKey), opts.Hash, test.digest, signature, opts)
				require.NoError(t, err)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)

	const (
		handle = 0x81000000
		pw     = ""
		attr   = tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagFixedTPM | tpm2.FlagSensitiveDataOrigin
	)

	pub, err := GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)
	defer DeleteKey(dev, handle, pw)

	// Use the key in the TPM for decryption
	priv, err := NewRSAPrivateKey(dev, handle, pw)
	require.NoError(t, err)

	data := []byte("This is a test")

	tests := map[string]struct {
		opts crypto.DecrypterOpts
	}{
		"RSAES-PKCS1":                  {nil},
		"RSAES-PKCS1 with options":     {&rsa.PKCS1v15DecryptOptions{}},
		"RSAES-OAEP-SHA1":              {&rsa.OAEPOptions{Hash: crypto.SHA1}},
		"RSAES-OAEP-SHA256":            {&rsa.OAEPOptions{Hash: crypto.SHA256}},
		"RSAES-OAEP-SHA256 with label": {&rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("label")}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				encrypted []byte
				err       error
			)

			switch opts := test.opts.(type) {
			case *rsa.OAEPOptions:
				// The TPM only uses null-terminated labels, and those are included in the calculations.
				// We need to do the same for the results to match, even though the null isn't really
				// needed in the Go library for the same caluclations.
				label := opts.Label
				if len(label) > 0 {
					label = append(label, 0)
				}
				encrypted, err = rsa.EncryptOAEP(opts.Hash.New(), rand.Reader, pub.(*rsa.PublicKey), data, label)
			default:
				encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), data)
			}
			require.NoError(t, err)

			decrypted, err := priv.Decrypt(rand.Reader, encrypted, test.opts)
			require.NoError(t, err)

			require.Equal(t, data, decrypted)
		})
	}
}
