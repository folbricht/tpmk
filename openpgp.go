package tpmk

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
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

// OpenPGPDetachSign creates a detached signature for the data read from message using the provided signer.
// The signature is written to w.
func OpenPGPDetachSign(w io.Writer, e *openpgp.Entity, message io.Reader, config *packet.Config, signer crypto.Signer) error {
	// Only need the private key for signing, ignore the rest
	// of the entity. Note that to get a consistent keyID, we
	// have to use the timestamp from the original entity.
	entity := &openpgp.Entity{
		PrivateKey: packet.NewSignerPrivateKey(e.PrimaryKey.CreationTime, signer),
	}
	return openpgp.DetachSign(w, entity, message, config)
}

func OpenPGPClearSign(w io.Writer, e *openpgp.Entity, message io.Reader, config *packet.Config, signer crypto.Signer) error {
	// Only need the private key for signing, but to get a consistent keyID, we
	// have to use the timestamp from the original entity.
	privateKey := packet.NewSignerPrivateKey(e.PrimaryKey.CreationTime, signer)
	wc, err := clearsign.Encode(w, privateKey, config)
	if err != nil {
		return err
	}
	defer wc.Close()
	_, err = io.Copy(wc, message)
	return err
}
