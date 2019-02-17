package tpmk

import (
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// MarshalSSHCert encodes a cert into a format that can be read by OpenSSH.
// Certificate.Marshal() only encodes it into a binary wireformat. This
// convenience function wraps and base64-encodes it.
func MarshalSSHCert(c ssh.Certificate) []byte {
	raw := c.Marshal()
	return []byte(c.Type() + " " + base64.StdEncoding.EncodeToString(raw) + " " + c.KeyId)
}
