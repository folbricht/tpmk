package tpmk

import (
	"errors"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// NVWrite reserves space in an NV index and writes to it starting at offset 0. It automatically
// determines the max buffer size prior to writing blocks to the index.
func NVWrite(dev io.ReadWriteCloser, index tpmutil.Handle, b []byte, password string, attr tpm2.NVAttr) error {
	// Determine MAX_NV_BUFFER_SIZE from the TPM capabilities. Needed to batch writes to NV storage.
	cap, _, err := tpm2.GetCapability(dev, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.NVMaxBufferSize))
	if err != nil {
		return err
	}
	if len(cap) != 1 {
		return errors.New("expected one property")
	}
	property, ok := cap[0].(tpm2.TaggedProperty)
	if !ok {
		return errors.New("property is of wrong type")
	}
	maxBuffer := int(property.Value)

	// Reserve the required space
	if err := tpm2.NVDefineSpace(dev,
		tpm2.HandleOwner,
		index,
		password,
		password,
		nil,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPPRead,
		uint16(len(b)),
	); err != nil {
		return err
	}

	// Can only write naxBuffer bytes at a time so need to batch up the writes until everything is written
	var offset uint16
	for len(b) > 0 {
		length := len(b)
		if length > maxBuffer {
			length = maxBuffer
		}
		if err := tpm2.NVWrite(dev, tpm2.HandleOwner, tpmutil.Handle(index), password, b[:length], offset); err != nil {
			return err
		}
		offset += uint16(length)
		b = b[length:]
	}
	return nil

}
