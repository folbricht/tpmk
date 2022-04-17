package tpmk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// GenRSAPrimaryKey generates a primary RSA key and makes it persistent under the given handle.
func GenRSAPrimaryKey(dev io.ReadWriteCloser, handle tpmutil.Handle, parentPW, ownerPW string, attr tpm2.KeyProp) (crypto.PublicKey, error) {
	// Define the TPM key template
	pub := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: attr,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgNull,
				Hash: tpm2.AlgNull,
			},
			KeyBits: uint16(2048),
		},
	}

	// Generate the Key
	pcrSelection := tpm2.PCRSelection{}
	signerHandle, pubKey, err := tpm2.CreatePrimary(dev, tpm2.HandleOwner, pcrSelection, parentPW, ownerPW, pub)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(dev, signerHandle)

	// Make the key persistent
	return pubKey, tpm2.EvictControl(dev, ownerPW, tpm2.HandleOwner, signerHandle, handle)
}

// LoadExternal loads an existing key-pair into the TPM and returns the key handle. The key is loaded
/// into the Null hierarchy and not persistent.
func LoadExternal(dev io.ReadWriteCloser, handle tpmutil.Handle, pk crypto.PrivateKey, password string, attr tpm2.KeyProp) (tpmutil.Handle, error) {
	var (
		tpm2Pub  tpm2.Public
		tpm2Priv tpm2.Private
	)
	switch private := pk.(type) {
	case *rsa.PrivateKey:
		tpm2Pub = tpm2.Public{
			Type:       tpm2.AlgRSA,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: attr,
			RSAParameters: &tpm2.RSAParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgNull,
					Hash: tpm2.AlgNull,
				},
				KeyBits:     uint16(private.Size() * 8),
				ExponentRaw: uint32(private.PublicKey.E),
				ModulusRaw:  private.PublicKey.N.Bytes(),
			},
		}
		tpm2Priv = tpm2.Private{
			Type:      tpm2.AlgRSA,
			Sensitive: private.Primes[0].Bytes(),
		}
	case *ecdsa.PrivateKey:
		if private.Curve != elliptic.P256() {
			return 0, errors.New("only curve P256 supported")
		}
		tpm2Pub = tpm2.Public{
			Type:       tpm2.AlgECC,
			NameAlg:    tpm2.AlgSHA1,
			Attributes: attr,
			ECCParameters: &tpm2.ECCParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgECDSA,
					Hash: tpm2.AlgSHA1,
				},
				CurveID: tpm2.CurveNISTP256,
				Point:   tpm2.ECPoint{XRaw: private.PublicKey.X.Bytes(), YRaw: private.PublicKey.Y.Bytes()},
			},
		}
		tpm2Priv = tpm2.Private{
			Type:      tpm2.AlgECC,
			Sensitive: private.D.Bytes(),
		}
	default:
		return 0, fmt.Errorf("unsupported key type %T", private)
	}
	h, _, err := tpm2.LoadExternal(dev, tpm2Pub, tpm2Priv, tpm2.HandleNull)
	return h, err
}

// DeleteKey removes a persistent key.
func DeleteKey(dev io.ReadWriteCloser, handle tpmutil.Handle, password string) error {
	return tpm2.EvictControl(dev, password, tpm2.HandleOwner, handle, handle)
}

// ReadPublicKey reads the public part of a key stored in the TPM. It returns the whole public part
// as well as the public key from it
func ReadPublicKey(dev io.ReadWriteCloser, handle tpmutil.Handle) (tpm2.Public, crypto.PublicKey, error) {
	pub, _, _, err := tpm2.ReadPublic(dev, handle)
	if err != nil {
		return pub, nil, err
	}
	publicKey, err := pub.Key()
	return pub, publicKey, err
}

// KeyList returns a list of persistent key handles.
func KeyList(dev io.ReadWriteCloser) ([]tpmutil.Handle, error) {
	return GetHandles(dev, tpm2.PersistentFirst)
}
