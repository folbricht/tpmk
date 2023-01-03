//go:build !windows
// +build !windows

package tpmk

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

// openImpl opens the TPM identified by the device name
func openImpl(device string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(device)
}
