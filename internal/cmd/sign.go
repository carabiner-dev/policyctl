// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
)

type signOptions struct {
	fileOptions
	outputFile string
}

// Validates the options in context with arguments
func (so *signOptions) Validate() error {
	errs := []error{
		so.fileOptions.Validate(),
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *signOptions) AddFlags(cmd *cobra.Command) {
	so.fileOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&so.outputFile, "out", "o", "", "defaults to original policy filename + .ampel",
	)
}

func addSign(parentCmd *cobra.Command) {
	opts := &signOptions{}
	parseCmd := &cobra.Command{
		Short: "sign a policy or policy set",
		Use:   "sign [flags] policy.json",
		Long: `
sign policies and policy sets

The sign subcommand signs policies and policySets into sigstore bundles. By
default, policies will be signed and to a file next to the original policy but
replacing the .json or .hsjon extensions to .ampel (the reommended extension
for signed ampel policies).

When signing, policyctl uses sigstore to handle ephemeral keys. The signing
operation will be reigsterd in the rekor transparency log. Unless specified,
policyctl will try to read any ambient credentials to obtain an OIDC identity
(eg on GitHub actions) and if it fails, it will launch the fill broser-based
sigstore flow. 

		`,
		Example:           fmt.Sprintf(`%s sign -o policy.ampel policy.json`, appname),
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

			if _, _, err := policy.NewParser().ParsePolicyOrSet(data); err != nil {
				return fmt.Errorf("parsing input: %w", err)
			}

			// The t parses OK. Let's sign it

			// By default, we output to the same file with an .ampel ext
			outName := opts.outputFile
			if opts.outputFile == "" {
				if !strings.HasSuffix(opts.policyFile, ".json") ||
					strings.HasSuffix(opts.policyFile, ".hjson") {
					return errors.New("unable to compute filename, policy is not a .json or .hjson file")
				}

				outName = strings.TrimSuffix(strings.TrimSuffix(opts.policyFile, ".json"), ".hjson") + ".ampel"
			}

			if _, err := os.Stat(outName); err == nil {
				return errors.New("outpath already exists, not overwritting")
			}

			f, err := os.Create(outName)
			if err != nil {
				return fmt.Errorf("opening policy file: %w", err)
			}

			if err := policy.NewSigner().SignPolicyData(data, f); err != nil {
				return fmt.Errorf("signing policy data: %w", err)
			}

			fmt.Fprintf(os.Stderr, "✅ signed policy written to %s", outName)

			return nil
		},
	}
	opts.AddFlags(parseCmd)
	parentCmd.AddCommand(parseCmd)
}
