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
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type compileOptions struct {
	fileOptions
	sign bool
}

// Validates the options in context with arguments
func (co *compileOptions) Validate() error {
	errs := []error{
		co.fileOptions.Validate(),
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (co *compileOptions) AddFlags(cmd *cobra.Command) {
	co.fileOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&co.sign, "sign", false, "sign policy and output signed bundle",
	)
}

func addCompile(parentCmd *cobra.Command) {
	opts := &compileOptions{}
	compileCmd := &cobra.Command{
		Short:             "compiles a policy or policySet to a standalone file",
		Use:               "compile",
		Example:           fmt.Sprintf(`%s compile policy.json`, appname),
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

			// Compile the file into a policy or set
			set, pcy, err := policy.NewCompiler().CompileFile(opts.policyFile)
			if err != nil {
				return err
			}

			// Marshall the policy to json
			marshaler := protojson.MarshalOptions{
				Multiline: true,
				Indent:    "  ",
			}
			data, err := marshaler.Marshal(policy.PolicyOrSet(set, pcy).(proto.Message)) //nolint:errcheck,forcetypeassert
			if err != nil {
				return fmt.Errorf("marshaling policy data: %w", err)
			}

			var out io.Writer = os.Stdout
			if !opts.sign {
				if _, err := fmt.Fprintln(out, string(data)); err != nil {
					return err
				}
				return nil
			}

			// If signing was requested, replace the data with a signed bundle
			return policy.NewSigner().SignPolicyData(data, out)
		},
	}
	opts.AddFlags(compileCmd)
	parentCmd.AddCommand(compileCmd)
}
