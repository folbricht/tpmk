package tpmk

import (
	"bytes"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/ssh"
)

// MarshalSSHPublic encodes a certificate or public key into a format that
// can be used by OpenSSH.
func MarshalSSHPublic(k ssh.PublicKey, id string) []byte {
	raw := k.Marshal()
	return []byte(k.Type() + " " + base64.StdEncoding.EncodeToString(raw) + " " + id + "\n")
}

// UnmarshalSSHPublic parses a public key or certificate in OpenSSH format.
func UnmarshalSSHPublic(encoded []byte) (ssh.PublicKey, error) {
	parts := bytes.SplitN(encoded, []byte(" "), 3)
	if len(parts) < 2 {
		return nil, errors.New("public key or certificate not in OpenSSH format")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, err
	}

	return ssh.ParsePublicKey(decoded)
}
