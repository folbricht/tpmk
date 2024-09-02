package tpmk

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// GetHandles returns a list of all handles of a type determined by by the starting position.
func GetHandles(dev io.ReadWriteCloser, start tpm2.TPMProp) ([]tpmutil.Handle, error) {
	var (
		pos     = uint32(start)
		handles []tpmutil.Handle
	)
	for {
		cap, more, err := tpm2.GetCapability(dev, tpm2.CapabilityHandles, 1, pos)
		if err != nil {
			return nil, err
		}
		for _, c := range cap {
			h, ok := c.(tpmutil.Handle)
			if !ok {
				return nil, fmt.Errorf("expected tpmutil.Handle, got %T", c)
			}
			handles = append(handles, h)
		}
		if !more {
			break
		}
		pos = uint32(cap[len(cap)-1].(tpmutil.Handle)) + 1
	}
	return handles, nil
}
