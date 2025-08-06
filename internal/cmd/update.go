// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/ampel/pkg/policy"
)

type updateOptions struct {
	policyFile string
}

// Validates the options in context with arguments
func (co *updateOptions) Validate() error {
	errs := []error{}
	if co.policyFile == "" {
		errs = append(errs, errors.New("no policy file specified"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (co *updateOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&co.policyFile, "policy", "p", "", "path to policy file",
	)
}

func addUpdate(parentCmd *cobra.Command) {
	opts := &compileOptions{}
	compileCmd := &cobra.Command{
		Short:             "updates a policy or policyset from sources",
		Use:               "update",
		Example:           fmt.Sprintf(`%s update policy.json`, appname),
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

			set, _, err := policy.NewParser().Open(opts.policyFile)
			if err != nil {
				return err
			}

			data, err := protojson.MarshalOptions{
				Multiline: true,
				Indent:    "  ",
			}.Marshal(set)
			if err != nil {
				return fmt.Errorf("marshaling policy data: %w", err)
			}

			var out io.Writer = os.Stdout
			fmt.Fprintln(out, string(data))

			return nil
		},
	}
	opts.AddFlags(compileCmd)
	parentCmd.AddCommand(compileCmd)
}
