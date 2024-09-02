package main

import (
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestParseKeyAttributes(t *testing.T) {
	expected := tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent
	actual, err := parseKeyAttributes("sign|fixedtpm|fixedparent")
	require.NoError(t, err)
	require.Equal(t, expected, actual)

	actual, err = parseKeyAttributes(" sign |  fixedtpm|fixedparent ")
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func TestParseNVAttributes(t *testing.T) {
	expected := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPPRead
	actual, err := parseNVAttributes("ownerwrite|ownerread|authread|ppread")
	require.NoError(t, err)
	require.Equal(t, expected, actual)

	actual, err = parseNVAttributes(" ownerwrite |  ownerread|authread|ppread ")
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
