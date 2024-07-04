package tpmk

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func TestNVWriteRead(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		index tpmutil.Handle = 0x1000000
		pw                   = ""
		attr                 = tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPPRead
	)
	data := append([]byte("testdata"), make([]byte, 1024)...)

	err = NVWrite(dev, index, data, pw, attr)
	require.NoError(t, err)

	out, err := NVRead(dev, index, pw)
	require.NoError(t, err)

	require.Exactly(t, data, out)
}

func TestNVDelete(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		index tpmutil.Handle = 0x1000000
		pw                   = ""
		attr                 = tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPPRead
	)
	data := []byte("testdata")

	err = NVWrite(dev, index, data, pw, attr)
	require.NoError(t, err)

	indexes, err := NVList(dev)
	require.NoError(t, err)
	require.Contains(t, indexes, index)

	err = NVDelete(dev, index, pw)
	require.NoError(t, err)

	indexes, err = NVList(dev)
	require.NoError(t, err)
	require.NotContains(t, indexes, index)
}
