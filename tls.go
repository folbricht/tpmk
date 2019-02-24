package tpmk

import (
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// RSAPrivateKey represents an RSA key in a TPM and implements the crypto.PrivateKey interface which
// allows it to be used in TLS connections.
type RSAPrivateKey struct {
	dev       io.ReadWriter
	handle    tpmutil.Handle
	pub       tpm2.Public
	publicKey crypto.PublicKey
	password  string
}

// NewRSAPrivateKey initializes crypto.PrivateKey with a private key that is held in the TPM.
func NewRSAPrivateKey(dev io.ReadWriteCloser, handle tpmutil.Handle, password string) (RSAPrivateKey, error) {
	pub, publicKey, err := ReadPublicKey(dev, handle)
	if err != nil {
		return RSAPrivateKey{}, err
	}
	if pub.Type != tpm2.AlgRSA {
		return RSAPrivateKey{}, fmt.Errorf("unsupported algorithm %T", publicKey)
	}
	return RSAPrivateKey{dev, handle, pub, publicKey, password}, nil
}

// Public returns the public part of the key.
func (k RSAPrivateKey) Public() crypto.PublicKey {
	return k.publicKey
}

var tpmToHashFunc = map[tpm2.Algorithm]crypto.Hash{
	tpm2.AlgSHA1:   crypto.SHA1,
	tpm2.AlgSHA384: crypto.SHA384,
	tpm2.AlgSHA256: crypto.SHA256,
	tpm2.AlgSHA512: crypto.SHA512,
}

// Sign data via a key in the TPM. Implements crypto.Signer.
func (k RSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != tpmToHashFunc[k.pub.NameAlg] {
		return nil, fmt.Errorf("unsupported hash algorithm: %d", opts.HashFunc())
	}
	scheme := k.pub.RSAParameters.Sign
	sig, err := tpm2.Sign(k.dev, k.handle, k.password, digest, scheme)
	if err != nil {
		return nil, err
	}
	return sig.RSA.Signature, err
}
