// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/policylabs/policy"
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
			set, pcy, grp, err := policy.NewCompiler().CompileFile(opts.policyFile)
			if err != nil {
				return err
			}

			// Marshall the policy to json
			element, err := marshalStable(policy.PolicyOrSetOrGroup(set, pcy, grp).(proto.Message)) //nolint:errcheck,forcetypeassert
			if err != nil {
				return fmt.Errorf("marshaling policy data: %w", err)
			}

			var out io.Writer = os.Stdout
			if !opts.sign {
				if _, err := fmt.Fprintln(out, string(element)); err != nil {
					return err
				}
				return nil
			}

			// If signing was requested, replace the data with a signed bundle
			return policy.NewSigner().SignPolicyData(element, out)
		},
	}
	opts.AddFlags(compileCmd)
	parentCmd.AddCommand(compileCmd)
}

// marshalStable renders a message as indented JSON whose bytes do not
// change between runs. protojson deliberately varies the whitespace of
// its output, which would make every compiled file differ from one
// compile to the next, so the compact form is indented by encoding/json.
func marshalStable(m proto.Message) ([]byte, error) {
	compact, err := protojson.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, fmt.Errorf("indenting policy data: %w", err)
	}
	return out.Bytes(), nil
}
