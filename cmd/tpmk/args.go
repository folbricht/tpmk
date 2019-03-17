package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// parseHandle parses a string (typically from the command line) into tpmutil.Handle
func parseHandle(s string) (tpmutil.Handle, error) {
	i, err := strconv.ParseUint(s, 0, 32)
	return tpmutil.Handle(i), err
}

// parseDuration takes a string "<years>:<months>:<days>" and adds it to time.Now().
func parseDuration(s string) (time.Time, error) {
	var years, months, days int
	_, err := fmt.Sscanf(s, "%d:%d:%d", &years, &months, &days)
	return time.Now().UTC().AddDate(years, months, days), err
}

// parseOptionsMap breaks up a slice of <key>=<value> strings into a map. Used to parse
// SSH certificate options and extensions.
func parseOptionsMap(opt []string) map[string]string {
	m := make(map[string]string)
	for _, o := range opt {
		s := strings.SplitN(o, "=", 2)
		if len(s) > 1 {
			m[s[0]] = s[1]
			continue
		}
		m[s[0]] = ""
	}
	return m
}

// Parses a string of key properties as specified in the command line and returns
// the propery value. For example "sign|fixedtpm|fixedparent" becomes
// tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent.
func parseKeyAttributes(s string) (tpm2.KeyProp, error) {
	var keyProp tpm2.KeyProp
	s = strings.ReplaceAll(s, " ", "")
	for _, prop := range strings.Split(s, "|") {
		v, ok := stringToKeyAttribute[prop]
		if !ok {
			return keyProp, fmt.Errorf("unknown attribute property '%s'", prop)
		}
		keyProp |= v
	}

	return keyProp, nil
}

// Parses a string of NV properties as specified in the command line and returns
// the propery value. For example "ownerwrite|ownerread|authread|ppread" becomes
// tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrAuthRead | tpm2.AttrPPRead.
func parseNVAttributes(s string) (tpm2.NVAttr, error) {
	var nvAttr tpm2.NVAttr
	s = strings.ReplaceAll(s, " ", "")
	for _, prop := range strings.Split(s, "|") {
		v, ok := stringToNVAttribute[prop]
		if !ok {
			return nvAttr, fmt.Errorf("unknown attribute '%s'", prop)
		}
		nvAttr |= v
	}

	return nvAttr, nil
}

var stringToKeyAttribute = map[string]tpm2.KeyProp{
	"fixedtpm":            tpm2.FlagFixedTPM,
	"fixedparent":         tpm2.FlagFixedParent,
	"sensitivedataorigin": tpm2.FlagSensitiveDataOrigin,
	"userwithauth":        tpm2.FlagUserWithAuth,
	"adminwithpolicy":     tpm2.FlagAdminWithPolicy,
	"noda":                tpm2.FlagNoDA,
	"restricted":          tpm2.FlagRestricted,
	"decrypt":             tpm2.FlagDecrypt,
	"sign":                tpm2.FlagSign,
}

var stringToNVAttribute = map[string]tpm2.NVAttr{
	"ppwrite":        tpm2.AttrPPWrite,
	"ownerwrite":     tpm2.AttrOwnerWrite,
	"authwrite":      tpm2.AttrAuthWrite,
	"policywrite":    tpm2.AttrPolicyWrite,
	"policydelete":   tpm2.AttrPolicyDelete,
	"writelocked":    tpm2.AttrWriteLocked,
	"writeall":       tpm2.AttrWriteAll,
	"writedefine":    tpm2.AttrWriteDefine,
	"writestclear":   tpm2.AttrWriteSTClear,
	"globallock":     tpm2.AttrGlobalLock,
	"ppread":         tpm2.AttrPPRead,
	"ownerread":      tpm2.AttrOwnerRead,
	"authread":       tpm2.AttrAuthRead,
	"policyread":     tpm2.AttrPolicyRead,
	"noda":           tpm2.AttrNoDA,
	"orderly":        tpm2.AttrOrderly,
	"clearstclear":   tpm2.AttrClearSTClear,
	"readlocked":     tpm2.AttrReadLocked,
	"written":        tpm2.AttrWritten,
	"platformcreate": tpm2.AttrPlatformCreate,
	"readstclear":    tpm2.AttrReadSTClear,
}
