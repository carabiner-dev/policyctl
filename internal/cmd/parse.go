// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
)

type parseOptions struct {
	policyFile string
}

// Validates the options in context with arguments
func (po *parseOptions) Validate() error {
	errs := []error{}
	if po.policyFile == "" {
		errs = append(errs, errors.New("no policy file specified"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (po *parseOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&po.policyFile, "policy", "p", "", "path to policy file",
	)
}

func addParse(parentCmd *cobra.Command) {
	opts := &parseOptions{}
	parseCmd := &cobra.Command{
		Short:             "parses a file",
		Use:               "parse",
		Example:           fmt.Sprintf(`%s parse policy.json`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.policyFile == "" {
					opts.policyFile = args[0]
				}
				if args[0] != opts.policyFile {
					return fmt.Errorf("policy path speficied twice (as argument and flag)")
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			// Open the policy file
			policyFile, err := os.Open(opts.policyFile)
			if err != nil {
				return fmt.Errorf("opening file: %w", err)
			}

			// Read the data
			data, err := io.ReadAll(policyFile)
			if err != nil {
				return fmt.Errorf("readaing data: %w", err)
			}

			set, pcy, err := policy.NewParser().ParsePolicyOrSet(data)
			if err != nil {
				return fmt.Errorf("parsing input: %w", err)
			}

			fmt.Printf("Set: %+v\nPolicy: %+v", set, pcy)

			return nil
		},
	}
	opts.AddFlags(parseCmd)
	parentCmd.AddCommand(parseCmd)
}
