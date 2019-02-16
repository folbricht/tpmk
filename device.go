package tpmk

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil/mssim"
)

// OpenDevice opens a TPM2. If device is 'sim', it'll connect to a simulator. The caller is responsible
// for calling Close().
func OpenDevice(device string) (io.ReadWriteCloser, error) {
	if device == "sim" {
		return OpenSim()
	}
	return tpm2.OpenTPM(device)
}

// OpenSim opens a connection to a local TPM2 simulator via TCP and initalizes it by calling Startup.
func OpenSim() (io.ReadWriteCloser, error) {
	dev, err := mssim.Open(mssim.Config{CommandAddress: "localhost:2321", PlatformAddress: "localhost:2322"})
	if err != nil {
		return nil, err
	}

	// Initialize the simulator
	return dev, tpm2.Startup(dev, tpm2.StartupClear)
}
