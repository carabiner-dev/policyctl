// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Mermaid renders diagrams as mermaid flowcharts wrapped in a fenced code
// block, which markdown viewers with mermaid support and the HTML output
// render inline.
type Mermaid struct{}

var _ Diagrammer = Mermaid{}

// Policy diagrams the inputs feeding the policy and how its tenets combine.
func (Mermaid) Policy(p *papi.Policy) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")

	hasInputs := writeMermaidInputs(&b, p)
	fmt.Fprintf(&b, "    P[\"🛡️ %s\"]\n", mermaidLabel(policyLabel(p)))
	if hasInputs {
		fmt.Fprintln(&b, "    inputs --> P")
	}
	writeMermaidTenets(&b, p, "P")

	return mermaidFence(b.String())
}

// PolicyGroup diagrams the blocks of the group and the alternatives in each.
func (Mermaid) PolicyGroup(pg *papi.PolicyGroup) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")
	fmt.Fprintf(&b, "    G[\"📂 %s\"]\n", mermaidLabel(pg.GetId()))
	writeMermaidBlocks(&b, pg, "G")
	return mermaidFence(b.String())
}

// PolicySet diagrams the policies and groups composing the set.
func (Mermaid) PolicySet(ps *papi.PolicySet) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")
	fmt.Fprintf(&b, "    S[\"📦 %s\"]\n", mermaidLabel(ps.GetId()))

	for i, p := range ps.GetPolicies() {
		id := fmt.Sprintf("P%d", i)
		fmt.Fprintf(&b, "    S --> %s[\"🛡️ %s\"]\n", id, mermaidLabel(policyLabel(p)))
		writeMermaidTenets(&b, p, id)
	}

	for i, grp := range ps.GetGroups() {
		id := fmt.Sprintf("G%d", i)
		fmt.Fprintf(&b, "    S --> %s[\"📂 %s\"]\n", id, mermaidLabel(grp.GetId()))
		writeMermaidBlocks(&b, grp, id)
	}

	return mermaidFence(b.String())
}

// writeMermaidInputs writes the "inputs" subgraph listing the attestation
// types, context values and chain links the policy consumes. It reports
// whether the policy declares any input.
func writeMermaidInputs(b *strings.Builder, p *papi.Policy) bool {
	types := policyInputTypes(p)
	ctxNames := slices.Sorted(maps.Keys(p.GetContext()))
	chain := p.GetChain()
	if len(types)+len(ctxNames)+len(chain) == 0 {
		return false
	}

	fmt.Fprintln(b, "    subgraph inputs[\"Inputs\"]")
	for i, t := range types {
		fmt.Fprintf(b, "        A%d[\"📄 %s\"]\n", i, mermaidLabel(t))
	}
	for i, name := range ctxNames {
		fmt.Fprintf(b, "        C%d[\"⚙️ %s\"]\n", i, mermaidLabel(contextLabel(name, p.GetContext()[name])))
	}
	for i, link := range chain {
		cp := link.GetPredicate()
		if cp == nil {
			continue
		}
		label := mermaidLabel(cp.GetType()) + "<br/>" + mermaidLabel(truncate(cp.GetSelector(), 80))
		fmt.Fprintf(b, "        L%d[\"⛓️ %s\"]\n", i, label)
	}
	fmt.Fprintln(b, "    end")
	return true
}

// writeMermaidTenets writes the tenet nodes hanging from the policy node
// named prefix. Several tenets go through a decision node stating the assert
// mode; a single tenet connects directly.
func writeMermaidTenets(b *strings.Builder, p *papi.Policy, prefix string) {
	tenets := p.GetTenets()
	switch len(tenets) {
	case 0:
		return
	case 1:
		fmt.Fprintf(b, "    %s --> %s_T0[\"📋 %s\"]\n", prefix, prefix, tenetLabel(tenets[0], 0))
	default:
		mode := prefix + "_M"
		fmt.Fprintf(b, "    %s --> %s{\"%s\"}\n", prefix, mode, assertLabel(p.GetMeta().GetAssertMode(), "tenet", "tenets"))
		for i, t := range tenets {
			fmt.Fprintf(b, "    %s --> %s_T%d[\"📋 %s\"]\n", mode, prefix, i, tenetLabel(t, i))
		}
	}
}

// writeMermaidBlocks writes the blocks of a group hanging from the group node
// named prefix, and the policies in each block. Several blocks go through a
// decision node stating the group assert mode; a block with several policies
// is itself a decision node stating its own.
func writeMermaidBlocks(b *strings.Builder, pg *papi.PolicyGroup, prefix string) {
	blocks := pg.GetBlocks()
	parent := prefix
	if len(blocks) > 1 {
		parent = prefix + "_M"
		fmt.Fprintf(b, "    %s --> %s{\"%s\"}\n", prefix, parent, assertLabel(pg.GetMeta().GetAssertMode(), "block", "blocks"))
	}

	for i, block := range blocks {
		id := fmt.Sprintf("%s_B%d", prefix, i)
		label := block.GetId()
		if label == "" {
			label = fmt.Sprintf("Block %d", i+1)
		}
		policies := block.GetPolicies()
		if len(policies) > 1 {
			mode := assertLabel(block.GetMeta().GetAssertMode(), "policy", "policies")
			fmt.Fprintf(b, "    %s --> %s{\"⚡ %s<br/>%s\"}\n", parent, id, mermaidLabel(label), mode)
		} else {
			fmt.Fprintf(b, "    %s --> %s[\"⚡ %s\"]\n", parent, id, mermaidLabel(label))
		}

		for j, p := range policies {
			pid := fmt.Sprintf("%s_P%d", id, j)
			if src := p.GetSource(); src != nil && src.GetLocation() != nil {
				fmt.Fprintf(b, "    %s --> %s[\"🔗 %s\"]\n", id, pid, mermaidLabel(policyRefLabel(p)))
			} else {
				fmt.Fprintf(b, "    %s --> %s[\"🛡️ %s\"]\n", id, pid, mermaidLabel(policyLabel(p)))
			}
		}
	}
}

// policyInputTypes returns the attestation types a policy consumes: the
// policy level predicate types plus any declared by its tenets, sorted and
// without duplicates.
func policyInputTypes(p *papi.Policy) []string {
	seen := map[string]struct{}{}
	for _, t := range p.GetPredicates().GetTypes() {
		seen[t] = struct{}{}
	}
	for _, tenet := range p.GetTenets() {
		for _, t := range tenet.GetPredicates().GetTypes() {
			seen[t] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// assertLabel describes an assert mode: under AND (the default) all items
// must pass, under OR any one passing suffices. Unknown modes are shown as
// declared.
func assertLabel(mode, singular, plural string) string {
	switch mode {
	case "", defaultAssertMode:
		return "ALL " + plural + " must pass"
	case "OR":
		return "ANY " + singular + " passing suffices"
	default:
		return mermaidLabel(mode)
	}
}

// policyLabel names a policy in a diagram: its name, else its ID, else an
// inline placeholder.
func policyLabel(p *papi.Policy) string {
	if name := p.GetMeta().GetName(); name != "" {
		return name
	}
	return policyID(p)
}

// contextLabel describes a context value: "name: type", marked required or
// carrying its default when it has one. String defaults are quoted so an
// empty default stays visible.
func contextLabel(name string, cv *papi.ContextVal) string {
	label := name
	if t := cv.GetType(); t != "" {
		label += ": " + t
	}
	if cv.GetRequired() {
		label += " (required)"
	}
	if dv := cv.GetDefault(); dv != nil {
		value := formatValue(dv)
		if _, isString := dv.GetKind().(*structpb.Value_StringValue); isString {
			value = fmt.Sprintf("%q", value)
		}
		label += " = " + value
	}
	return label
}

// tenetLabel names a tenet: its title, else its ID, else its position; with
// the attestation types it declares on a second line.
func tenetLabel(t *papi.Tenet, index int) string {
	label := t.GetTitle()
	if label == "" {
		label = tenetID(t, index)
	}
	label = mermaidLabel(label)
	if types := t.GetPredicates().GetTypes(); len(types) > 0 {
		short := make([]string, 0, len(types))
		for _, pt := range types {
			short = append(short, mermaidLabel(shortType(pt)))
		}
		label += "<br/>" + strings.Join(short, ", ")
	}
	return label
}

// shortType abbreviates a predicate type URI for a node label by dropping
// the scheme, keeping the host and path that identify it (for example
// "slsa.dev/provenance/v1").
func shortType(predicateType string) string {
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(predicateType, scheme); ok {
			return rest
		}
	}
	return predicateType
}

func tenetID(t *papi.Tenet, index int) string {
	if t.GetId() != "" {
		return t.GetId()
	}
	return fmt.Sprintf("tenet-%d", index+1)
}

// mermaidLabel makes text safe inside a quoted mermaid node label.
func mermaidLabel(s string) string {
	s = strings.ReplaceAll(s, "\"", "#quot;")
	return strings.Join(strings.Fields(s), " ")
}

// mermaidFence wraps a diagram in the fenced code block markdown viewers
// render as mermaid.
func mermaidFence(diagram string) string {
	return "```mermaid\n" + diagram + "```\n"
}
