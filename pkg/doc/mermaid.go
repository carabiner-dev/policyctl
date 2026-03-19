// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"fmt"
	"strings"

	papi "github.com/carabiner-dev/policy/api/v1"
)

// MermaidPolicy generates a mermaid flowchart for a single policy.
func MermaidPolicy(p *papi.Policy) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")

	id := sanitizeMermaid(p.GetId())
	assertMode := p.GetMeta().GetAssertMode()
	if assertMode == "" {
		assertMode = defaultAssertMode
	}

	fmt.Fprintf(&b, "    P_%s[\"🛡️ %s\"]\n", id, p.GetId())

	if len(p.GetTenets()) > 1 {
		fmt.Fprintf(&b, "    P_%s --> mode_%s{%s}\n", id, id, assertMode)
		for i, t := range p.GetTenets() {
			tID := tenetID(t, i)
			preds := tenetPredicateLabel(t)
			fmt.Fprintf(&b, "    mode_%s --> T_%s_%d[\"📋 %s\\n%s\"]\n", id, id, i, tID, preds)
		}
	} else if len(p.GetTenets()) == 1 {
		t := p.GetTenets()[0]
		tID := tenetID(t, 0)
		preds := tenetPredicateLabel(t)
		fmt.Fprintf(&b, "    P_%s --> T_%s_0[\"📋 %s\\n%s\"]\n", id, id, tID, preds)
	}

	return b.String()
}

// MermaidPolicySet generates a mermaid flowchart for a policy set.
func MermaidPolicySet(ps *papi.PolicySet) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")

	setID := sanitizeMermaid(ps.GetId())
	fmt.Fprintf(&b, "    PS_%s[\"📦 PolicySet: %s\"]\n", setID, ps.GetId())

	for i, p := range ps.GetPolicies() {
		pID := sanitizeMermaid(p.GetId())
		if pID == "" {
			pID = fmt.Sprintf("p%d", i)
		}
		label := p.GetId()
		if label == "" {
			label = fmt.Sprintf("policy-%d", i+1)
		}

		assertMode := p.GetMeta().GetAssertMode()
		if assertMode == "" {
			assertMode = defaultAssertMode
		}

		fmt.Fprintf(&b, "    PS_%s --> P_%s[\"🛡️ %s\"]\n", setID, pID, label)

		if len(p.GetTenets()) > 1 {
			fmt.Fprintf(&b, "    P_%s --> mode_%s{%s}\n", pID, pID, assertMode)
			for j, t := range p.GetTenets() {
				tID := tenetID(t, j)
				preds := tenetPredicateLabel(t)
				fmt.Fprintf(&b, "    mode_%s --> T_%s_%d[\"📋 %s\\n%s\"]\n", pID, pID, j, tID, preds)
			}
		} else if len(p.GetTenets()) == 1 {
			t := p.GetTenets()[0]
			tID := tenetID(t, 0)
			preds := tenetPredicateLabel(t)
			fmt.Fprintf(&b, "    P_%s --> T_%s_0[\"📋 %s\\n%s\"]\n", pID, pID, tID, preds)
		}
	}

	for i, g := range ps.GetGroups() {
		gID := sanitizeMermaid(g.GetId())
		if gID == "" {
			gID = fmt.Sprintf("g%d", i)
		}
		fmt.Fprintf(&b, "    PS_%s --> G_%s[\"📂 Group: %s\"]\n", setID, gID, g.GetId())
		writeMermaidGroupBlocks(&b, g, gID)
	}

	return b.String()
}

// MermaidPolicyGroup generates a mermaid flowchart for a policy group.
func MermaidPolicyGroup(pg *papi.PolicyGroup) string {
	var b strings.Builder
	fmt.Fprintln(&b, "flowchart TD")

	gID := sanitizeMermaid(pg.GetId())
	fmt.Fprintf(&b, "    G_%s[\"📂 PolicyGroup: %s\"]\n", gID, pg.GetId())
	writeMermaidGroupBlocks(&b, pg, gID)

	return b.String()
}

func writeMermaidGroupBlocks(b *strings.Builder, pg *papi.PolicyGroup, gID string) {
	for i, block := range pg.GetBlocks() {
		blockID := sanitizeMermaid(block.GetId())
		if blockID == "" {
			blockID = fmt.Sprintf("blk%d", i)
		}
		assertMode := block.GetMeta().GetAssertMode()
		if assertMode == "" {
			assertMode = defaultAssertMode
		}

		fmt.Fprintf(b, "    G_%s --> B_%s_%s{\"⚡ Block %d\\n(%s)\"}\n", gID, gID, blockID, i+1, assertMode)

		for j, p := range block.GetPolicies() {
			pID := sanitizeMermaid(p.GetId())
			if pID == "" {
				pID = fmt.Sprintf("bp%d_%d", i, j)
			}

			if src := p.GetSource(); src != nil && src.GetLocation() != nil {
				label := policyRefLabel(p)
				fmt.Fprintf(b, "    B_%s_%s --> R_%s_%s[\"🔗 %s\"]\n", gID, blockID, gID, pID, label)
			} else {
				label := p.GetId()
				if label == "" {
					label = "(inline)"
				}
				fmt.Fprintf(b, "    B_%s_%s --> P_%s_%s[\"🛡️ %s\"]\n", gID, blockID, gID, pID, label)
			}
		}
	}
}

func tenetID(t *papi.Tenet, index int) string {
	if t.GetId() != "" {
		return t.GetId()
	}
	return fmt.Sprintf("tenet-%d", index+1)
}

func tenetPredicateLabel(t *papi.Tenet) string {
	if preds := t.GetPredicates(); preds != nil && len(preds.GetTypes()) > 0 {
		short := make([]string, 0, len(preds.GetTypes()))
		for _, pt := range preds.GetTypes() {
			// Show just the last path segment
			parts := strings.Split(pt, "/")
			short = append(short, parts[len(parts)-1])
		}
		return strings.Join(short, ", ")
	}
	return ""
}

func sanitizeMermaid(s string) string {
	r := strings.NewReplacer(
		"-", "_", ".", "_", " ", "_", "/", "_", "@", "_", ":", "_",
	)
	return r.Replace(s)
}
