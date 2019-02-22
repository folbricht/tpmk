package tpmk

import (
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// MarshalSSHPublic encodes a certificate or public key into a format that
// can be used by OpenSSH.
func MarshalSSHPublic(k ssh.PublicKey, id string) []byte {
	raw := k.Marshal()
	return []byte(k.Type() + " " + base64.StdEncoding.EncodeToString(raw) + " " + id + "\n")
}
