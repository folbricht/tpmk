package tpmk

import (
	"bytes"
	"crypto"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

func TestOpenPGPSign(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		handle = 0x81000000
		pw     = ""
		attr   = tpm2.FlagSign | tpm2.FlagUserWithAuth | tpm2.FlagSensitiveDataOrigin
	)

	// Generate and use the key in the TPM for signing
	_, err = GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)
	priv, err := NewRSAPrivateKey(dev, handle, pw)
	require.NoError(t, err)

	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	}

	// Build an identity with the TPM key
	entity, err := NewOpenPGPEntity("test", "comment", "test@example.com", config, priv)
	require.NoError(t, err)

	// Serialize the entity (public part) then load it back from that
	exported := new(bytes.Buffer)
	err = entity.Serialize(exported)
	require.NoError(t, err)

	entityRead, err := ReadOpenPGPEntity(packet.NewReader(exported), priv)
	require.NoError(t, err)

	// Sign something with the TPM key producing a detached signature
	sigDetached := new(bytes.Buffer)
	msg := "signed message\n"
	err = openpgp.DetachSign(sigDetached, entityRead, strings.NewReader(msg), config)
	require.NoError(t, err)

	// Verify the signature
	keyring := openpgp.EntityList{entityRead}
	signedBy, err := openpgp.CheckDetachedSignature(keyring, strings.NewReader(msg), sigDetached)
	require.NoError(t, err)
	require.Equal(t, entityRead, signedBy)

	// Sign it with a clear text signature
	sigClear := new(bytes.Buffer)
	wc, err := clearsign.Encode(sigClear, entityRead.PrivateKey, config)
	require.NoError(t, err)
	_, err = io.Copy(wc, strings.NewReader(msg))
	require.NoError(t, err)
	err = wc.Close()
	require.NoError(t, err)

	block, rest := clearsign.Decode(sigClear.Bytes())
	require.Empty(t, rest)
	require.Equal(t, msg, string(block.Plaintext))
}

func TestOpenPGPDecrypt(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		handle = 0x81000000
		pw     = ""
		attr   = tpm2.FlagSign | tpm2.FlagDecrypt | tpm2.FlagUserWithAuth | tpm2.FlagSensitiveDataOrigin
	)

	// Generate and use the key in the TPM for signing
	_, err = GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)
	priv, err := NewRSAPrivateKey(dev, handle, pw)
	require.NoError(t, err)

	// Build an identity with the TPM key
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 2048,
	}
	entity, err := NewOpenPGPEntity("test", "comment", "test@example.com", config, priv)
	require.NoError(t, err)

	// Encrypt something for the TPM entity
	msg := []byte("secret message")
	ciphertext := new(bytes.Buffer)
	wc, err := openpgp.Encrypt(ciphertext, []*openpgp.Entity{entity}, nil, nil, config)
	require.NoError(t, err)
	_, err = wc.Write(msg)
	require.NoError(t, err)
	err = wc.Close()
	require.NoError(t, err)

	// Decrypt the message
	md, err := openpgp.ReadMessage(ciphertext, openpgp.EntityList([]*openpgp.Entity{entity}), nil, config)
	require.NoError(t, err)
	decrypted, err := ioutil.ReadAll(md.UnverifiedBody)
	require.NoError(t, err)
	require.True(t, md.IsEncrypted)
	require.Equal(t, entity, md.DecryptedWith.Entity)
	require.Equal(t, msg, decrypted)
}
