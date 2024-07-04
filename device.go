package tpmk

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil/mssim"
)

// SimDev is used for testing. When set, calling OpenDevice("sim") will return it instead
// of trying to connect to a simulator. Used in command tests that first setup an internal
// simltor, set SimDev, then call the command with "sim" as device name.
var SimDev io.ReadWriteCloser

// OpenDevice opens a TPM2. If device is 'sim', it'll connect to a simulator on localhost:2321.
// The caller is responsible for calling Close().
func OpenDevice(device string) (io.ReadWriteCloser, error) {
	switch device {
	case "sim":
		if SimDev != nil {
			return SimDev, nil
		}
		return OpenSim()
	default:
		return openImpl(device)
	}
}

// Simulator is a wrapper around a simulator connection that ensures startup and shutdown are called on open/close.
// This is only necessary with simulators. If shutdown isn't called before disconnecting, the lockout counter
// in the simulator is incremented.
type Simulator struct {
	*mssim.Conn
}

// Close calls Shutdown() on the simulator before disconnecting to ensure the lockout counter doesn't
// get incremented.
func (s Simulator) Close() error {
	if err := tpm2.Shutdown(s, tpm2.StartupClear); err != nil {
		return err
	}
	return s.Conn.Close()
}

// OpenSim opens a connection to a local TPM2 simulator via TCP and initalizes it by calling Startup.
func OpenSim() (Simulator, error) {
	dev, err := mssim.Open(mssim.Config{CommandAddress: "localhost:2321", PlatformAddress: "localhost:2322"})
	if err != nil {
		return Simulator{}, err
	}

	// Initialize the simulator
	return Simulator{dev}, tpm2.Startup(dev, tpm2.StartupClear)
}
