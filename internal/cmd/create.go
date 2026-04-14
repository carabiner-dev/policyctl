// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	formatHJSON = "hjson"
	formatJSON  = "json"
)

type createOptions struct {
	outputFile string
	format     string
}

func (co *createOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&co.outputFile, "output", "o", "", "write output to a file instead of stderr",
	)
	cmd.PersistentFlags().StringVarP(
		&co.format, "format", "f", formatHJSON, "output format: hjson or json",
	)
}

// write outputs the skeleton to the configured destination and optionally
// prints a companion reference guide for JSON output.
func (co *createOptions) write(hjsonData, jsonData, companion string) error {
	data := hjsonData
	if co.format == formatJSON {
		data = jsonData
	}

	if co.outputFile != "" {
		if err := os.WriteFile(co.outputFile, []byte(data), 0o600); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Skeleton written to %s\n", co.outputFile)
		return nil
	}

	fmt.Fprint(os.Stderr, data)

	// Print companion field reference for JSON when stderr is a terminal
	// (not piped to a file).
	if co.format == formatJSON && isStderrTerminal() {
		fmt.Fprint(os.Stderr, companion)
	}

	return nil
}

// isStderrTerminal reports whether stderr is connected to a terminal.
func isStderrTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func addCreate(parentCmd *cobra.Command) {
	opts := &createOptions{}
	createCmd := &cobra.Command{
		Short: "create skeleton policies and policy sets",
		Use:   "create",
		Long: `Create skeleton files for policies and policy sets.

The generated files contain all required sections with blank values
and all optional fields documented to help you get started quickly.

By default, output is in HJSON format with inline comments. Use
--format json to generate JSON with documentation hints embedded
as _docs_ keys and placeholder values for required fields.`,
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
		Short: "create a skeleton policy file",
		Use:   "policy",
		Long:  "Create a skeleton policy file with all available fields documented.",
		Example: fmt.Sprintf(
			"  %s create policy\n  %s create policy -o my-policy.hjson\n  %s create policy -f json -o my-policy.json",
			appname, appname, appname,
		),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.write(policyHJSONTemplate, policyJSONTemplate, policyCompanionGuide)
		},
	}
	parentCmd.AddCommand(policyCmd)
}

func addCreateSet(parentCmd *cobra.Command, opts *createOptions) {
	setCmd := &cobra.Command{
		Short: "create a skeleton policy set file",
		Use:   "set",
		Long:  "Create a skeleton policy set file with all available fields documented.",
		Example: fmt.Sprintf(
			"  %s create set\n  %s create set -o my-policy-set.hjson\n  %s create set -f json -o my-policy-set.json",
			appname, appname, appname,
		),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return opts.write(policySetHJSONTemplate, policySetJSONTemplate, policySetCompanionGuide)
		},
	}
	parentCmd.AddCommand(setCmd)
}

// ---------------------------------------------------------------------------
// HJSON templates
// ---------------------------------------------------------------------------

// policyHJSONTemplate is the HJSON skeleton for a single Policy.
const policyHJSONTemplate = `{
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

// policySetHJSONTemplate is the HJSON skeleton for a PolicySet.
const policySetHJSONTemplate = `{
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

// ---------------------------------------------------------------------------
// JSON templates
// ---------------------------------------------------------------------------

// policyJSONTemplate is the JSON skeleton for a single Policy.
// Required fields use placeholder hint values. Optional fields are documented
// via _docs_ keys that the compiler ignores.
const policyJSONTemplate = `{
  "id": "<required: unique policy identifier>",
  "meta": {
    "runtime": "<runtime and version, e.g. cel/v0>",
    "description": "<human-readable description of this policy>",
    "_docs_assert_mode": "assert_mode: AND (default) or OR. Controls if one or all tenets must pass.",
    "_docs_version": "version: integer version number for this policy.",
    "_docs_enforce": "enforce: ON (default) or OFF. Controls FAIL vs SOFTFAIL on failure.",
    "_docs_expiration": "expiration: RFC 3339 timestamp (e.g. 2026-12-31T00:00:00Z).",
    "_docs_controls": "controls: [{id, title, framework, class, item}] framework control refs."
  },
  "predicates": {
    "types": [],
    "_docs_limit": "limit: max predicates to evaluate. 0 = no limit."
  },
  "tenets": [
    {
      "id": "<required: unique tenet identifier>",
      "title": "<what this tenet checks>",
      "code": "<required: CEL expression returning boolean>",
      "_docs_runtime": "runtime: override for this tenet (e.g. cel/v0). Inherits from policy meta.",
      "_docs_predicates": "predicates: {types: [], limit: 0} override for this tenet.",
      "_docs_error": "error: {message: '...', guidance: '...'} returned when tenet fails.",
      "_docs_assessment": "assessment: {message: '...'} assessment details.",
      "_docs_outputs": "outputs: {name: {code: '<CEL expr>', value: null}} named output values."
    }
  ],
  "_docs_source": "source: {id, version, identity, location} remote policy reference. HTTPS requires digest; git+ requires commit.",
  "_docs_context": "context: {name: {type: '<string|int|bool> (required if set)', required, value, default, description}}.",
  "_docs_chain": "chain: [{predicate: {type, selector, runtime, identities}}] evidence chain.",
  "_docs_identities": "identities: [] required signer identities for attestation verification.",
  "_docs_transformers": "transformers: [{id: '...'}] data transformers applied before evaluation."
}
`

// policySetJSONTemplate is the JSON skeleton for a PolicySet.
const policySetJSONTemplate = `{
  "id": "<required: unique policy set identifier>",
  "meta": {
    "runtime": "<default runtime for all policies, e.g. cel/v0>",
    "description": "<human-readable description of this policy set>",
    "_docs_version": "version: integer version number for this policy set.",
    "_docs_enforce": "enforce: ON (default) or OFF. Controls FAIL vs SOFTFAIL on failure.",
    "_docs_expiration": "expiration: RFC 3339 timestamp (e.g. 2026-12-31T00:00:00Z).",
    "_docs_frameworks": "frameworks: [{id, name, definition}] security framework references."
  },
  "policies": [
    {
      "id": "<required: unique policy identifier>",
      "meta": {
        "runtime": "<runtime and version, e.g. cel/v0>",
        "description": "<human-readable description>",
        "_docs_assert_mode": "assert_mode: AND (default) or OR.",
        "_docs_version": "version: integer version number.",
        "_docs_enforce": "enforce: ON (default) or OFF.",
        "_docs_expiration": "expiration: RFC 3339 timestamp.",
        "_docs_controls": "controls: [{id, title, framework, class, item}]."
      },
      "predicates": {
        "types": []
      },
      "tenets": [
        {
          "id": "<required: unique tenet identifier>",
          "title": "<what this tenet checks>",
          "code": "<required: CEL expression returning boolean>",
          "_docs_runtime": "runtime: override (inherits from policy meta).",
          "_docs_predicates": "predicates: {types: [], limit: 0}.",
          "_docs_error": "error: {message, guidance}.",
          "_docs_assessment": "assessment: {message}.",
          "_docs_outputs": "outputs: {name: {code, value}}."
        }
      ],
      "_docs_source": "source: {id, version, identity, location} remote policy ref.",
      "_docs_context": "context: {name: {type, required, value, default, description}}.",
      "_docs_chain": "chain: [{predicate: {type, selector, runtime, identities}}].",
      "_docs_identities": "identities: [] required signer identities.",
      "_docs_transformers": "transformers: [{id}] data transformers."
    }
  ],
  "_docs_common": "common: {identities: [], references: [{id, version, identity, location}], context: {...}} shared across all policies.",
  "_docs_chain": "chain: [{predicate: {type, selector, runtime, identities}}] evidence chain for all policies.",
  "_docs_groups": "groups: [{id, meta: {description, version, controls, enforce (default ON), expiration, runtime}, common, source: {id, version, identity, location}, blocks: [{id, meta: {description, assert_mode, enforce, controls}, policies}], chain}]."
}
`

// ---------------------------------------------------------------------------
// Companion reference guides (printed to stderr for JSON output on terminals)
// ---------------------------------------------------------------------------

const policyCompanionGuide = `
 Policy Field Reference
 ══════════════════════════════════════════════════════════════════════

  Fields marked with * are required. Compiler defaults shown in [brackets].
  Keys prefixed with _docs_ are documentation hints ignored by the compiler.
  Replace <placeholder> values with your data before use.

  FIELD                          DESCRIPTION
  ─────────────────────────────  ──────────────────────────────────────────
  * id                           Unique policy identifier
    meta.runtime                 Runtime version (e.g. "cel/v0")
    meta.description             Human-readable description
    meta.assert_mode             "AND" or "OR"                      ["AND"]
    meta.enforce                 "ON" or "OFF"                       ["ON"]
    meta.version                 Integer version number
    meta.expiration              RFC 3339 timestamp
    meta.controls[]              Framework control references
      .id / .title / .framework / .class / .item

  * tenets[]                     Policy assertions (at least one)
  *   .id                        Tenet identifier
  *   .code                      CEL expression (must return bool)
      .title                     Human-readable title
      .runtime                   Runtime override (inherits from meta)
      .predicates                Predicate spec override
      .error                     {message, guidance} on failure
      .assessment                {message} assessment details
      .outputs                   {name: {code, value}} named outputs

    predicates.types[]           Accepted predicate type URIs
    predicates.limit             Max predicates to evaluate (0=unlimited)

    source                       Remote policy reference
    context                      Runtime context values
      .type                      "string", "int", or "bool" (required if set)
      .required / .value / .default / .description
    chain[]                      Evidence chain links
    identities[]                 Required signer identities
    transformers[]               Data transformers

`

const policySetCompanionGuide = `
 PolicySet Field Reference
 ══════════════════════════════════════════════════════════════════════

  Fields marked with * are required. Compiler defaults shown in [brackets].
  Keys prefixed with _docs_ are documentation hints ignored by the compiler.
  Replace <placeholder> values with your data before use.

  FIELD                          DESCRIPTION
  ─────────────────────────────  ──────────────────────────────────────────
  * id                           Unique policy set identifier
    meta.runtime                 Default runtime for policies (e.g. "cel/v0")
    meta.description             Human-readable description
    meta.enforce                 "ON" or "OFF"                       ["ON"]
    meta.version                 Integer version number
    meta.expiration              RFC 3339 timestamp
    meta.frameworks[]            Security framework references
      .id / .name / .definition

    policies[]                   List of policies in this set
  *   .id                        Policy identifier
      .meta                      Policy metadata (see policy reference)
        .assert_mode             "AND" or "OR"                      ["AND"]
        .enforce                 "ON" or "OFF"                       ["ON"]
  *   .tenets[]                  Policy assertions
  *     .id / .code              Tenet identifier and CEL expression
      .predicates.types[]        Accepted predicate type URIs
      .source / .context / .chain / .identities / .transformers

    common                       Shared data for all policies
      .identities[]              Shared signer identities
      .references[]              Shared policy references
      .context                   Shared context values
    chain[]                      Evidence chain for all policies
    groups[]                     Policy group definitions
      .id / .meta / .common / .source / .blocks[] / .chain

`
