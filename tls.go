package tpmk

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
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

// Map a crypto.Hash algorithm to a tpm2 constant
var tpmToHashFunc = map[crypto.Hash]tpm2.Algorithm{
	crypto.SHA1:   tpm2.AlgSHA1,
	crypto.SHA384: tpm2.AlgSHA384,
	crypto.SHA256: tpm2.AlgSHA256,
	crypto.SHA512: tpm2.AlgSHA512,
}

// Map the crypto.Hash values to strings. Used to report errors
// when a Hash algorithm isn't available.
var hashToName = map[crypto.Hash]string{
	crypto.MD4:         "MD4",
	crypto.MD5:         "MD5",
	crypto.SHA1:        "SHA1",
	crypto.SHA224:      "SHA224",
	crypto.SHA256:      "SHA256",
	crypto.SHA384:      "SHA384",
	crypto.SHA512:      "SHA512",
	crypto.MD5SHA1:     "MD5SHA1",
	crypto.RIPEMD160:   "RIPEMD160",
	crypto.SHA3_224:    "SHA3_224",
	crypto.SHA3_256:    "SHA3_256",
	crypto.SHA3_384:    "SHA3_384",
	crypto.SHA3_512:    "SHA3_512",
	crypto.SHA512_224:  "SHA512_224",
	crypto.SHA512_256:  "SHA512_256",
	crypto.BLAKE2s_256: "BLAKE2s_256",
	crypto.BLAKE2b_256: "BLAKE2b_256",
	crypto.BLAKE2b_384: "BLAKE2b_384",
	crypto.BLAKE2b_512: "BLAKE2b_512",
}

// Sign digests via a key in the TPM. Implements crypto.Signer. If opts are *rsa.PSSOptions,
// the PSS signature algorithm is used, PKCS#1 1.5 otherwise. To use this function, tpm2.FlagSign
// needs to be set on the key, and tpm2.FlagRestricted needs to be clear.
func (k RSAPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash, ok := tpmToHashFunc[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %d (%s)", opts.HashFunc(), hashToName[opts.HashFunc()])
	}
	alg := tpm2.AlgRSASSA
	if _, ok := opts.(*rsa.PSSOptions); ok {
		alg = tpm2.AlgRSAPSS
	}
	scheme := &tpm2.SigScheme{
		Alg:  alg,
		Hash: hash,
	}
	sig, err := tpm2.Sign(k.dev, k.handle, k.password, digest, nil, scheme)
	if err != nil {
		return nil, err
	}
	return sig.RSA.Signature, err
}

// Decrypt decrypts ciphertext with the key in the TPM. If opts is nil or of type
// *PKCS1v15DecryptOptions then PKCS#1 v1.5 decryption is performed. Otherwise opts must have
// type *OAEPOptions and OAEP decryption is performed. tpm2.FlagDecrypt needs to be set and
// tpm2.FlagRestricted clear in the key properties. Implements crypto.Decrypter.
// Note that using OAEP with a label requires a null-terminated string.
func (k RSAPrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	switch opt := opts.(type) {
	case *rsa.OAEPOptions:
		hash, ok := tpmToHashFunc[opt.Hash]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %d (%s)", opt.Hash, hashToName[opt.Hash])
		}
		scheme := &tpm2.AsymScheme{
			Alg:  tpm2.AlgOAEP,
			Hash: hash,
		}
		return tpm2.RSADecrypt(k.dev, k.handle, k.password, msg, scheme, string(opt.Label))
	case nil, *rsa.PKCS1v15DecryptOptions:
		scheme := &tpm2.AsymScheme{Alg: tpm2.AlgRSAES}
		return tpm2.RSADecrypt(k.dev, k.handle, k.password, msg, scheme, "")
	default:
		return nil, errors.New("invalid options for Decrypt")
	}
}
