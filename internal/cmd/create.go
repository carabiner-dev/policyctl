// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type createOptions struct {
	outputFile string
}

func (co *createOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&co.outputFile, "output", "o", "", "write output to a file instead of stderr",
	)
}

// write outputs the skeleton to the configured destination: a file if
// --output is set, stderr otherwise.
func (co *createOptions) write(data string) error {
	if co.outputFile != "" {
		if err := os.WriteFile(co.outputFile, []byte(data), 0o600); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Skeleton written to %s\n", co.outputFile)
		return nil
	}
	fmt.Fprint(os.Stderr, data)
	return nil
}

func addCreate(parentCmd *cobra.Command) {
	opts := &createOptions{}
	createCmd := &cobra.Command{
		Short:             "create skeleton policies and policy sets",
		Use:               "create",
		Long:              "Create skeleton HJSON files for policies and policy sets.\n\nThe generated files contain all required sections with blank values\nand all optional fields commented out with descriptions to help you\nget started quickly.",
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	opts.AddFlags(createCmd)
	addCreatePolicy(createCmd, opts)
	addCreateSet(createCmd, opts)
	parentCmd.AddCommand(createCmd)
}

func addCreatePolicy(parentCmd *cobra.Command, opts *createOptions) {
	policyCmd := &cobra.Command{
		Short:         "create a skeleton policy file",
		Use:           "policy",
		Long:          "Create a skeleton HJSON policy file with all available fields documented.",
		Example:       fmt.Sprintf("  %s create policy\n  %s create policy -o my-policy.hjson", appname, appname),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.write(policyTemplate)
		},
	}
	parentCmd.AddCommand(policyCmd)
}

func addCreateSet(parentCmd *cobra.Command, opts *createOptions) {
	setCmd := &cobra.Command{
		Short:         "create a skeleton policy set file",
		Use:           "set",
		Long:          "Create a skeleton HJSON policy set file with all available fields documented.",
		Example:       fmt.Sprintf("  %s create set\n  %s create set -o my-policy-set.hjson", appname, appname),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.write(policySetTemplate)
		},
	}
	parentCmd.AddCommand(setCmd)
}

// policyTemplate is the HJSON skeleton for a single Policy.
const policyTemplate = `{
  // (Required) Policy identifier. A unique string to identify this policy.
  id: ""

  // Metadata about this policy.
  meta: {
    // Runtime and version for evaluating policy code (e.g. "cel/v0").
    runtime: ""

    // Human-readable description of this policy.
    description: ""

    // # assert_mode: ""
    // # Controls whether one tenet or all must pass for the policy to pass.
    // # Valid values: "OR" (any tenet passes) or "AND" (all tenets must pass).
    // # Default: "AND" (set by the compiler if not specified).

    // # version: 0
    // # Integer version number for the policy.

    // # enforce: ""
    // # Controls if a failed policy returns FAIL or SOFTFAIL.
    // # Valid values: "ON" or "OFF".
    // # Default: "ON" (set by the compiler if not specified).

    // # expiration: ""
    // # Expiration timestamp. The policy will fail evaluation after this date.
    // # Format: RFC 3339 (e.g. "2026-12-31T00:00:00Z").

    // # controls: []
    // # Framework control references this policy verifies.
    // # Each entry is an object with the following fields:
    // #   id: ""         Control ID string
    // #   title: ""      Human-readable description
    // #   framework: ""  Framework identifier (e.g. "SLSA", "SSDF")
    // #   class: ""      Control class/family within the framework
    // #   item: ""       Subitem identifier
  }

  // Predicates defines the attestation types this policy evaluates.
  predicates: {
    // List of predicate type URIs this policy accepts.
    types: []

    // # limit: 0
    // # Maximum number of predicates to evaluate. 0 means no limit.
  }

  // (Required) Tenets are the individual assertions this policy checks.
  // Each tenet contains a CEL expression that evaluates the attestation data.
  tenets: [
    {
      // (Required) Unique identifier for this tenet.
      id: ""

      // Human-readable title describing what this tenet checks.
      title: ""

      // (Required) CEL expression to evaluate. Must return a boolean.
      code: ""

      // # runtime: ""
      // # Runtime override for this specific tenet (e.g. "cel/v0").
      // # If not set, inherits from the policy meta.

      // # predicates: {}
      // # Predicate spec override for this tenet.
      // # Same structure as the policy-level predicates.

      // # error: {}
      // # Error details returned when this tenet fails:
      // #   message: ""   Condition that was not met
      // #   guidance: ""  Suggestions to make the policy pass

      // # assessment: {}
      // # Assessment details:
      // #   message: ""   Assessment message

      // # outputs: {}
      // # Named output values computed by this tenet.
      // # Each key maps to an object with:
      // #   code: ""    CEL expression to compute the output value
      // #   value: null  Static value (alternative to code)
    }
  ]

  // # source: {}
  // # Reference to the source of this policy when loaded remotely.
  // #   id: ""         Policy reference ID
  // #   version: 0     Pinned version
  // #   identity: {}   Expected signer identity
  // #   location: {}   Resource descriptor for the source location
  // #     When using HTTPS URLs, at least one hash in digest is required.
  // #     For git+ VCS locators, a digest or commit hash in the URL is required.

  // # context: {}
  // # Context values needed by this policy at evaluation time.
  // # Each key maps to a ContextVal:
  // #   type: ""         (Required if set) Data type: "string", "int", or "bool"
  // #   required: false  If true, policy fails when value is not provided
  // #   value: null      Current value
  // #   default: null    Default when not set
  // #   description: ""  Human-readable description

  // # chain: []
  // # Evidence chain to compute subjects for this policy.
  // # Each entry is a ChainLink with a predicate:
  // #   predicate:
  // #     type: ""       Predicate type URI
  // #     selector: ""   CEL expression to extract the next subject
  // #     runtime: ""    Runtime for the selector
  // #     identities: [] Required signer identities

  // # identities: []
  // # Required signer identities for attestations.
  // # Each entry specifies a signer identity to verify.

  // # transformers: []
  // # Data transformers applied before evaluation.
  // # Each entry has:
  // #   id: ""  Transformer identifier
}
`

// policySetTemplate is the HJSON skeleton for a PolicySet.
const policySetTemplate = `{
  // (Required) PolicySet identifier. A unique string to identify this policy set.
  id: ""

  // Metadata about this policy set.
  meta: {
    // Runtime and version for evaluating policy code (e.g. "cel/v0").
    // Used as default for all policies in the set.
    runtime: ""

    // Human-readable description of this policy set.
    description: ""

    // # version: 0
    // # Integer version number for the policy set.

    // # enforce: ""
    // # Controls if a failed policy returns FAIL or SOFTFAIL.
    // # Valid values: "ON" or "OFF".
    // # Default: "ON" (set by the compiler if not specified).

    // # expiration: ""
    // # Expiration timestamp. The policy set will fail after this date.
    // # Format: RFC 3339 (e.g. "2026-12-31T00:00:00Z").

    // # frameworks: []
    // # Security framework references checked by this policy set.
    // # Each entry binds policy controls to a framework definition:
    // #   id: ""          Framework identifier string
    // #   name: ""        Framework name (e.g. "SLSA", "SSDF")
    // #   definition: {}  Resource descriptor linking to the framework definition
  }

  // Policies in this set. Each policy defines assertions to evaluate
  // against attestation data.
  policies: [
    {
      // (Required) Policy identifier.
      id: ""

      meta: {
        // Runtime and version (e.g. "cel/v0").
        runtime: ""

        // Human-readable description.
        description: ""

        // # assert_mode: ""
        // # "OR" (any tenet passes) or "AND" (all must pass).
        // # Default: "AND" (set by the compiler if not specified).

        // # version: 0

        // # enforce: ""
        // # Default: "ON" (set by the compiler if not specified).

        // # expiration: ""
        // # controls: []
      }

      // Predicate types this policy evaluates.
      predicates: {
        types: []
      }

      // (Required) Tenets are the assertions this policy checks.
      tenets: [
        {
          // (Required) Tenet identifier.
          id: ""

          // Human-readable title.
          title: ""

          // (Required) CEL expression to evaluate. Must return a boolean.
          code: ""

          // # runtime: ""
          // # predicates: {}
          // # error: { message: "", guidance: "" }
          // # assessment: { message: "" }
          // # outputs: {}
        }
      ]

      // # source: {}
      // # context: {}
      // # chain: []
      // # identities: []
      // # transformers: []
    }
  ]

  // # common: {}
  // # Shared data elements inherited by all policies in the set.
  // #   identities: []  Shared signer identities
  // #   references: []  Shared policy references
  // #     Each reference:
  // #       id: ""         Policy reference ID
  // #       version: 0     Pinned version
  // #       identity: {}   Expected signer identity
  // #       location: {}   Resource descriptor for the source
  // #         When using HTTPS URLs, at least one hash in digest is required.
  // #         For git+ VCS locators, a digest or commit hash in the URL is required.
  // #   context: {}     Shared context values
  // #     Each key maps to a ContextVal:
  // #       type: ""         (Required if set) Data type: "string", "int", or "bool"
  // #       required: false  If true, policy fails when value is not provided
  // #       value: null      Current value
  // #       default: null    Default when not set
  // #       description: ""  Human-readable description

  // # chain: []
  // # Evidence chain to compute subjects for all policies in the set.
  // # Each entry is a ChainLink with a predicate:
  // #   predicate:
  // #     type: ""       Predicate type URI
  // #     selector: ""   CEL expression to extract the next subject
  // #     runtime: ""    Runtime for the selector
  // #     identities: [] Required signer identities

  // # groups: []
  // # Policy group definitions for organizing policies.
  // # Each group has:
  // #   id: ""        (Required) Group identifier
  // #   meta: {}      Group metadata:
  // #     description: ""  Human-readable description
  // #     version: 0       Version number
  // #     controls: []     Framework control references
  // #     enforce: ""      "ON" or "OFF". Default: "ON" (set by compiler)
  // #     expiration: ""   Expiration timestamp (RFC 3339)
  // #     runtime: ""      Runtime and version
  // #   common: {}    Shared data for policies in the group
  // #   source: {}    Remote group reference (id, version, identity, location)
  // #   blocks: []    Policy blocks grouping policies:
  // #     Each block:
  // #       id: ""         Block identifier
  // #       meta: {}       Block metadata (description, assert_mode, enforce, controls)
  // #       policies: []   Policies in this block
  // #   chain: []     Evidence chain for the group
}
`
