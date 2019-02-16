package main

import (
	"fmt"
	"strconv"
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
