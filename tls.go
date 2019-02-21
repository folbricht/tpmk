package tpmk

import (
	"crypto"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// RSAPrivateKey represents an RSA key in a TPM and implements the crypto.PrivateKey interface which
// allows it to be used in TLS connections.
type RSAPrivateKey struct {
	dev      io.ReadWriter
	handle   tpmutil.Handle
	pub      crypto.PublicKey
	password string
}

// NewRSAPrivateKey initializes crypto.PrivateKey with a private key that is held in the TPM.
func NewRSAPrivateKey(dev io.ReadWriteCloser, handle tpmutil.Handle, password string) (RSAPrivateKey, error) {
	pub, err := ReadPublicKey(dev, handle)
	return RSAPrivateKey{dev, handle, pub, password}, err
}

// Public returns the public part of the key.
func (k RSAPrivateKey) Public() crypto.PublicKey {
	return k.pub
}

// Sign data via a key in the TPM. Implements crypto.Signer.
func (k RSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	}
	sig, err := tpm2.Sign(k.dev, k.handle, k.password, digest, scheme)
	if err != nil {
		return nil, err
	}
	return sig.RSA.Signature, err
}
