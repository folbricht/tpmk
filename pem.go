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
	crt, err := LoadX509CertificateFile(crtFilePEM)
	if err != nil {
		return nil, nil, err
	}

	key, err := LoadRSAKeyFile(keyFilePEM)
	return crt, key, err
}

// LoadX509CertificateFile reads a certificate in PEM format from a file.
func LoadX509CertificateFile(crtFilePEM string) (*x509.Certificate, error) {
	crtRaw, err := ioutil.ReadFile(crtFilePEM)
	if err != nil {
		return nil, err
	}
	crtBlk, _ := pem.Decode(crtRaw)
	if crtBlk == nil || crtBlk.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	return x509.ParseCertificate(crtBlk.Bytes)
}

// LoadRSAKeyFile reads a private RSA key in PEM format from a file.
func LoadRSAKeyFile(keyFilePEM string) (*rsa.PrivateKey, error) {
	keyRaw, err := ioutil.ReadFile(keyFilePEM)
	if err != nil {
		return nil, err
	}
	keyBlk, _ := pem.Decode(keyRaw)
	if keyBlk == nil || keyBlk.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(keyBlk.Bytes)
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

// PEMToPubKey decodes a public key in PCKS1 PEM format.
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
