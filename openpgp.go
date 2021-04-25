package tpmk

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

func NewOpenPGPEntity(name, comment, email string, config *packet.Config, signer crypto.Signer) (*openpgp.Entity, error) {
	now := config.Now()

	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, errors.InvalidArgumentError("signer must be an rsa key")
	}

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.InvalidArgumentError("user id field contained invalid characters")
	}

	e := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(now, pub),
		PrivateKey: packet.NewSignerPrivateKey(now, signer),
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := true
	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: now,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}
	if err := e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, config); err != nil {
		return nil, err
	}

	// Set the PreferredHash for the SelfSignature if one was provided in the config
	if config != nil && config.DefaultHash != 0 {
		v, ok := s2k.HashToHashId(config.DefaultHash)
		if !ok {
			return nil, fmt.Errorf("unsupported hash: %s", config.DefaultHash.String())
		}
		e.Identities[uid.Id].SelfSignature.PreferredHash = []uint8{v}
	}

	// Set DefaultCipher if one was provided
	if config != nil && config.DefaultCipher != 0 {
		e.Identities[uid.Id].SelfSignature.PreferredSymmetric = []uint8{uint8(config.DefaultCipher)}
	}

	e.Subkeys = []openpgp.Subkey{
		{
			PublicKey:  packet.NewRSAPublicKey(now, pub),
			PrivateKey: packet.NewSignerPrivateKey(now, signer),
			Sig: &packet.Signature{
				CreationTime:              now,
				SigType:                   packet.SigTypeSubkeyBinding,
				PubKeyAlgo:                packet.PubKeyAlgoRSA,
				Hash:                      config.Hash(),
				FlagsValid:                true,
				FlagEncryptStorage:        true,
				FlagEncryptCommunications: true,
				IssuerKeyId:               &e.PrimaryKey.KeyId,
			},
		},
	}
	e.Subkeys[0].PublicKey.IsSubkey = true
	e.Subkeys[0].PrivateKey.IsSubkey = true
	err := e.Subkeys[0].Sig.SignKey(e.Subkeys[0].PublicKey, e.PrivateKey, config)
	return e, err
}

// ReadOpenPGPEntity reads a public key and returns an openpgp.Entity with the provided crypto.Signer.
// The returned entity can be used for signing or decryption. The private key must match the primary
// public key.
func ReadOpenPGPEntity(packets *packet.Reader, signer crypto.Signer) (*openpgp.Entity, error) {
	e, err := openpgp.ReadEntity(packets)
	if err != nil {
		return nil, err
	}
	privateKey := packet.NewSignerPrivateKey(e.PrimaryKey.CreationTime, signer)

	if privateKey.KeyId != e.PrimaryKey.KeyId {
		return nil, fmt.Errorf("id of private key %q does not match public key %q", privateKey.KeyIdString(), e.PrimaryKey.KeyIdString())
	}
	e.PrivateKey = privateKey
	for i := range e.Subkeys {
		if e.Subkeys[i].PublicKey.KeyId == privateKey.KeyId {
			e.Subkeys[i].PrivateKey = privateKey
			e.Subkeys[i].PrivateKey.IsSubkey = true
		}
	}
	return e, nil
}
