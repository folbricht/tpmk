package main

import (
	"fmt"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type keyLsOptions struct {
	device string
}

func newKeyLsCommand() *cobra.Command {
	var opt keyLsOptions

	cmd := &cobra.Command{
		Use:     "ls",
		Short:   "List persistent keys",
		Long:    `List persistent key handles.`,
		Example: `  tpmk key ls`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyLs(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	return cmd
}

func runKeyLs(opt keyLsOptions, args []string) error {
	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return errors.Wrap(err, "opening device")
	}
	defer dev.Close()

	// Get a list of keys
	keys, err := tpmk.KeyList(dev)
	if err != nil {
		return errors.Wrap(err, "reading key list")
	}

	// Print the key handles in hex notation
	for _, handle := range keys {
		fmt.Printf("0x%x\n", handle)
	}
	return nil
}
