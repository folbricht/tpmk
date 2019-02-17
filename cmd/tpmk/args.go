package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpmutil"
)

// ParseHandle parses a string (typically from the command line) into tpmutil.Handle
func ParseHandle(s string) (tpmutil.Handle, error) {
	i, err := strconv.ParseUint(s, 0, 32)
	return tpmutil.Handle(i), err
}

// ParseDuration takes a string "<years>:<months>:<days>" and adds it to time.Now().
func ParseDuration(s string) (time.Time, error) {
	var years, months, days int
	_, err := fmt.Sscanf(s, "%d:%d:%d", &years, &months, &days)
	return time.Now().UTC().AddDate(years, months, days), err
}

// ParseOptionsMap breaks up a slice of <key>=<value> strings into a map. Used to parse
// SSH certificate options and extensions.
func ParseOptionsMap(opt []string) map[string]string {
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
