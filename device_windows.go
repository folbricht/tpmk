//go:build windows
// +build windows

package tpmk

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

// openImpl opens the TPM on Windows
func openImpl(_ string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
