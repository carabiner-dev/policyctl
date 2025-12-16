// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/policy"
	"github.com/carabiner-dev/policy/options"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	fileOptions
	command.KeyOptions
	ExitCode        bool
	IdentityStrings []string
}

// Validates the options in context with arguments
func (vo *verifyOptions) Validate() error {
	errs := []error{
		vo.fileOptions.Validate(),
		vo.KeyOptions.Validate(),
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (vo *verifyOptions) AddFlags(cmd *cobra.Command) {
	vo.fileOptions.AddFlags(cmd)
	vo.KeyOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringSliceVar(
		&vo.IdentityStrings, "signer", []string{}, "list of accepted signer identities",
	)
	cmd.PersistentFlags().BoolVar(
		&vo.ExitCode, "exit-code", false, "run silent and exit non-zero if verification fails",
	)
}

func addVerify(parentCmd *cobra.Command) {
	opts := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Short: "verify a signed policy or policy set",
		Use:   "verify [flags] policy.ampel",
		Long: `
verify signed policies

The verify subcommand checks the signatures of signed policies. Input can be
a sigstore bundle iwht a policy wrapped in an in-toto statement or a policy 
in a DSSE envelope.


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

			if !opts.ExitCode {
				return verifyAndPrintResult(data, *opts)
			}

			// Handle exit code
			keys, err := opts.ParseKeys()
			if err != nil {
				return fmt.Errorf("parsing keys: %w", err)
			}

			_, _, ver, err := policy.NewParser().ParseVerifyPolicyOrSet(
				data, options.WithPublicKey(keys...),
				options.WithIdentityString(opts.IdentityStrings...),
			)
			if err != nil {
				return fmt.Errorf("parsing and verifying input: %w", err)
			}

			if ver.GetVerified() {
				fmt.Fprintf(os.Stderr, "[POLICY VERIFICATION OK]\n")
				return nil
			}

			fmt.Fprintf(os.Stderr, "[POLICY VERIFICATION FAILED]\n")
			os.Exit(1)
			return nil
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}

func verifyAndPrintResult(data []byte, opts verifyOptions) error {
	keys, err := opts.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	_, _, ver, err := policy.NewParser().ParseVerifyPolicyOrSet(
		data, options.WithPublicKey(keys...),
	)
	if err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	if ver == nil {
		fmt.Println("🚫 Policy is not signed")
		return nil
	}

	policyVer, ok := ver.(*sapi.Verification)
	if !ok {
		return fmt.Errorf("unknown verification result %T", ver)
	}

	var validIds = []*sapi.Identity{}
	for _, str := range opts.IdentityStrings {
		nid, err := sapi.NewIdentityFromSlug(str)
		if err != nil {
			return err
		}
		validIds = append(validIds, nid)
	}

	if policyVer.GetVerified() {
		fmt.Println("✅ Policy signed")
		fmt.Println()

		fmt.Println("Verified signer identities:")
		for _, id := range policyVer.GetSignature().GetIdentities() {
			fmt.Print(" " + id.Slug())
			accepted := false
			for _, aid := range validIds {
				if policyVer.MatchesIdentity(aid) {
					accepted = true
					break
				}
			}

			if len(validIds) > 0 {
				if accepted {
					fmt.Print(" (✔️  valid)")
				} else {
					fmt.Print(" (✖️  invalid)")
				}
			}
			fmt.Println()
		}

		fmt.Println()
	} else {
		fmt.Println("🚫 Policy verification failed")
	}

	return nil
}
