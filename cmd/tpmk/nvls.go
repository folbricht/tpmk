package main

import (
	"fmt"

	"github.com/folbricht/tpmk"
	"github.com/spf13/cobra"
)

type nvLsOptions struct {
	device string
}

func newNVLsCommand() *cobra.Command {
	var opt nvLsOptions

	cmd := &cobra.Command{
		Use:     "ls",
		Short:   "List NV indexes",
		Long:    `List defined NV indexes.`,
		Example: `  tpmk ls`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNVLs(opt, args)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opt.device, "device", "d", "/dev/tpmrm0", "TPM device, 'sim' for simulator")
	return cmd
}

func runNVLs(opt nvLsOptions, args []string) error {
	// Open device or simulator
	dev, err := tpmk.OpenDevice(opt.device)
	if err != nil {
		return err
	}
	defer dev.Close()

	// Get a list of indexes
	indexes, err := tpmk.NVList(dev)
	if err != nil {
		return err
	}

	// Print the index in hex notation
	for _, index := range indexes {
		fmt.Printf("0x%x\n", index)
	}
	return nil
}
