package sshtest

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// KeyFromFile reads a private key and optionally a certificate file in
// OpenSSH format and returns an ssh.Signer. If crtfile is not the empty
// string, the Signer will be using the SSH certificate from it.
func KeyFromFile(keyfile, crtfile string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}
	// If a certificate is provided as well, extend the ssh.Signer with a it
	if crtfile != "" {
		b, err := ioutil.ReadFile(crtfile)
		if err != nil {
			return nil, err
		}
		parts := bytes.SplitN(b, []byte(" "), 3)
		if len(parts) < 2 {
			return nil, errors.New("public key or certificate not in OpenSSH format")
		}
		decoded, err := base64.StdEncoding.DecodeString(string(parts[1]))
		if err != nil {
			return nil, err
		}
		pub, err := ssh.ParsePublicKey(decoded)
		if err != nil {
			return nil, err
		}
		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			return nil, errors.New("public key file is not a certificate")
		}
		key, err = ssh.NewCertSigner(crt, key)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}
