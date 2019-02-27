package tpmk

import (
	"testing"

	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

func TestPrimaryKeyGenerate(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		handle = 0x81000000
		pw     = ""
		attr   = tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
	)

	pub1, err := GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)
	require.NotEmpty(t, pub1)

	_, pub2, err := ReadPublicKey(dev, handle)
	require.NoError(t, err)

	require.Exactly(t, pub1, pub2)
}

func TestKeyDelete(t *testing.T) {
	dev, err := simulator.Get()
	require.NoError(t, err)
	defer dev.Close()

	const (
		handle tpmutil.Handle = 0x81000000
		pw                    = ""
		attr                  = tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagUserWithAuth | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin
	)

	_, err = GenRSAPrimaryKey(dev, handle, pw, pw, attr)
	require.NoError(t, err)

	handles, err := KeyList(dev)
	require.NoError(t, err)
	require.Contains(t, handles, handle)

	err = DeleteKey(dev, handle, pw)
	require.NoError(t, err)

	handles, err = KeyList(dev)
	require.NoError(t, err)
	require.NotContains(t, handles, handle)
}

// func TestRSAKeyImport(t *testing.T) {
// 	dev, err := simulator.Get()
// 	require.NoError(t, err)
// 	defer dev.Close()

// 	const (
// 		handle tpmutil.Handle = 0x81000000
// 		pw                    = ""
// 		attr                  = tpm2.FlagSign | tpm2.FlagUserWithAuth | tpm2.FlagSensitiveDataOrigin
// 	)

// 	key, err := rsa.GenerateKey(rand.Reader, 2048)
// 	require.NoError(t, err)

// 	err = ImportKey(dev, handle, key, pw, attr)
// 	require.NoError(t, err)
// }
