// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	papi "github.com/carabiner-dev/policy/api/v1"
)

// Diagrammer renders diagrams of policy elements as markdown fragments that
// Generate inlines in the document, such as a fenced mermaid block. An
// implementation for another diagram language, or one that renders images,
// only has to return markdown that embeds its output.
type Diagrammer interface {
	// Policy diagrams a policy: the inputs feeding it (attestation types,
	// context values and chain links) and how its tenets combine, all of
	// them required under AND or any one sufficient under OR.
	Policy(p *papi.Policy) string

	// PolicyGroup diagrams the blocks of a group and the policy alternatives
	// each block offers, with the assert mode combining them at each level.
	PolicyGroup(pg *papi.PolicyGroup) string

	// PolicySet diagrams the composition of a set: its policies and groups.
	PolicySet(ps *papi.PolicySet) string
}

// Options control document generation. Build them with Option functions.
type Options struct {
	// Diagrammer renders the diagrams embedded in the document. A nil
	// Diagrammer omits every diagram.
	Diagrammer Diagrammer

	// PolicyDetails adds each embedded policy's own diagram to set and group
	// documents. Standalone policy documents always carry theirs.
	PolicyDetails bool
}

// Option adjusts the generation Options.
type Option func(*Options)

// WithDiagrammer selects the Diagrammer rendering the embedded diagrams.
func WithDiagrammer(d Diagrammer) Option {
	return func(o *Options) { o.Diagrammer = d }
}

// WithoutDiagrams omits every diagram from the document.
func WithoutDiagrams() Option {
	return WithDiagrammer(nil)
}

// WithPolicyDetails controls whether policies embedded in sets and groups
// get their own diagram.
func WithPolicyDetails(enabled bool) Option {
	return func(o *Options) { o.PolicyDetails = enabled }
}

// defaultOptions returns the options Generate starts from: mermaid diagrams
// for every element, without diagrams for embedded policies.
func defaultOptions() Options {
	return Options{Diagrammer: Mermaid{}}
}
