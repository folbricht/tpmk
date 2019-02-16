package tpmk

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// LoadKeyPair reads and parses a key and certificate file in PEM format.
func LoadKeyPair(crtFilePEM, keyFilePEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load the certificate
	crtRaw, err := ioutil.ReadFile(crtFilePEM)
	if err != nil {
		return nil, nil, err
	}
	crtBlk, _ := pem.Decode(crtRaw)
	if crtBlk == nil || crtBlk.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode PEM block containing public key")
	}
	crt, err := x509.ParseCertificate(crtBlk.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load the key
	keyRaw, err := ioutil.ReadFile(keyFilePEM)
	if err != nil {
		return nil, nil, err
	}
	keyBlk, _ := pem.Decode(keyRaw)
	if keyBlk == nil || keyBlk.Type != "RSA PRIVATE KEY" {
		return nil, nil, errors.New("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlk.Bytes)
	return crt, key, err
}

// PubKeyToPEM encodes a public key in PEM format.
func PubKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
	der := x509.MarshalPKCS1PublicKey(p)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}), nil
}

// PEMToPubKey decodes a public key in PEM format.
func PEMToPubKey(b []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	return x509.ParsePKCS1PublicKey(blk.Bytes)
}

// CertToPEM converts an x509 certificate from DER format to PEM
func CertToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
