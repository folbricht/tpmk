package tpmk

import (
	"bytes"
	"crypto"
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

	entityPub, err := openpgp.ReadEntity(packet.NewReader(exported))
	require.NoError(t, err)

	// Sign something with the TPM key producing a detached signature
	sigDetached := new(bytes.Buffer)
	msg := "signed message\n"
	err = OpenPGPDetachSign(sigDetached, entityPub, strings.NewReader(msg), config, priv)
	require.NoError(t, err)

	// Verify the signature
	keyring := openpgp.EntityList{entityPub}
	signedBy, err := openpgp.CheckDetachedSignature(keyring, strings.NewReader(msg), sigDetached)
	require.NoError(t, err)
	require.Equal(t, entityPub, signedBy)

	// Sign it with a clear text signature
	sigClear := new(bytes.Buffer)
	err = OpenPGPClearSign(sigClear, entityPub, strings.NewReader(msg), config, priv)
	require.NoError(t, err)

	block, rest := clearsign.Decode(sigClear.Bytes())
	require.Empty(t, rest)
	require.Equal(t, msg, string(block.Plaintext))
}
