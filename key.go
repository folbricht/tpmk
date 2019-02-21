package tpmk

import (
	"crypto"
	"io"
	"math/big"

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
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: uint16(2048),
			Modulus: big.NewInt(0),
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

// DeleteKey removes a persistent key.
func DeleteKey(dev io.ReadWriteCloser, handle tpmutil.Handle, password string) error {
	return tpm2.EvictControl(dev, password, tpm2.HandleOwner, handle, handle)
}

// ReadPublicKey reads the public part of a key stored in the TPM.
func ReadPublicKey(dev io.ReadWriteCloser, handle tpmutil.Handle) (crypto.PublicKey, error) {
	pub, _, _, err := tpm2.ReadPublic(dev, handle)
	if err != nil {
		return nil, err
	}
	return pub.Key()
}
