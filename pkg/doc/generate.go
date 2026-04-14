// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"fmt"
	"strings"

	papi "github.com/carabiner-dev/policy/api/v1"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const defaultAssertMode = "AND"

// Generate produces a markdown document describing the given policy element.
func Generate(element any) (string, error) {
	var b strings.Builder
	switch v := element.(type) {
	case *papi.Policy:
		writePolicy(&b, v, 1)
	case *papi.PolicySet:
		writePolicySet(&b, v)
	case *papi.PolicyGroup:
		writePolicyGroup(&b, v, 1)
	default:
		return "", fmt.Errorf("unsupported element type: %T", element)
	}
	return b.String(), nil
}

func writePolicySet(b *strings.Builder, ps *papi.PolicySet) {
	fmt.Fprintf(b, "# PolicySet: `%s`\n\n", ps.GetId())

	if desc := ps.GetMeta().GetDescription(); desc != "" {
		fmt.Fprintf(b, "%s\n\n", desc)
	}

	section(b, "## Overview")
	fmt.Fprintln(b, "| Property | Value |")
	fmt.Fprintln(b, "|----------|-------|")
	fmt.Fprintln(b, "| **Type** | PolicySet |")
	if v := ps.GetMeta().GetVersion(); v != 0 {
		fmt.Fprintf(b, "| **Version** | %d |\n", v)
	}
	if exp := ps.GetMeta().GetExpiration(); exp != nil {
		fmt.Fprintf(b, "| **Expires** | %s |\n", exp.AsTime().Format("2006-01-02"))
	}
	if enforce := ps.GetMeta().GetEnforce(); enforce != "" {
		fmt.Fprintf(b, "| **Enforce** | %s |\n", enforce)
	}
	fmt.Fprintf(b, "| **Policies** | %d |\n", len(ps.GetPolicies()))
	if len(ps.GetGroups()) > 0 {
		fmt.Fprintf(b, "| **Groups** | %d |\n", len(ps.GetGroups()))
	}
	fmt.Fprintln(b)

	if ctx := ps.GetCommon().GetContext(); len(ctx) > 0 {
		section(b, "## Shared Context")
		writeContextTable(b, ctx)
	}

	if ids := ps.GetCommon().GetIdentities(); len(ids) > 0 {
		section(b, "## Shared Identities")
		writeIdentities(b, ids)
	}

	section(b, "## Structure")
	fmt.Fprintln(b, "```mermaid")
	fmt.Fprint(b, MermaidPolicySet(ps))
	fmt.Fprintln(b, "```")
	fmt.Fprintln(b)

	if len(ps.GetPolicies()) > 0 {
		section(b, "## Policies")
		for _, p := range ps.GetPolicies() {
			writePolicy(b, p, 3)
		}
	}

	for _, g := range ps.GetGroups() {
		writePolicyGroup(b, g, 2)
	}

	writeChangelog(b, ps.GetMeta().GetChangelog(), "## Changelog")
}

func writePolicyGroup(b *strings.Builder, pg *papi.PolicyGroup, headingLevel int) {
	h := strings.Repeat("#", headingLevel)

	fmt.Fprintf(b, "%s PolicyGroup: `%s`\n\n", h, pg.GetId())

	if desc := pg.GetMeta().GetDescription(); desc != "" {
		fmt.Fprintf(b, "%s\n\n", desc)
	}

	section(b, h+"# Overview")
	fmt.Fprintln(b, "| Property | Value |")
	fmt.Fprintln(b, "|----------|-------|")
	fmt.Fprintln(b, "| **Type** | PolicyGroup |")
	fmt.Fprintf(b, "| **Blocks** | %d |\n", len(pg.GetBlocks()))
	if enforce := pg.GetMeta().GetEnforce(); enforce != "" {
		fmt.Fprintf(b, "| **Enforce** | %s |\n", enforce)
	}
	fmt.Fprintln(b)

	section(b, h+"# Structure")
	fmt.Fprintln(b, "```mermaid")
	fmt.Fprint(b, MermaidPolicyGroup(pg))
	fmt.Fprintln(b, "```")
	fmt.Fprintln(b)

	for i, block := range pg.GetBlocks() {
		blockID := block.GetId()
		if blockID == "" {
			blockID = fmt.Sprintf("block-%d", i+1)
		}
		assertMode := block.GetMeta().GetAssertMode()
		if assertMode == "" {
			assertMode = defaultAssertMode
		}

		fmt.Fprintf(b, "%s# Block: `%s` (assert: %s)\n\n", h, blockID, assertMode)

		for _, p := range block.GetPolicies() {
			if src := p.GetSource(); src != nil && src.GetLocation() != nil {
				uri := src.GetLocation().GetUri()
				label := policyRefLabel(p)
				fmt.Fprintf(b, "- **Referenced policy**: [`%s`](%s)\n", label, uri)
			} else {
				writePolicy(b, p, headingLevel+2)
			}
		}
		fmt.Fprintln(b)
	}

	writeChangelog(b, pg.GetMeta().GetChangelog(), h+"# Changelog")
}

func writePolicy(b *strings.Builder, p *papi.Policy, headingLevel int) {
	h := strings.Repeat("#", headingLevel)

	id := p.GetId()
	if id == "" {
		id = "(inline policy)"
	}
	fmt.Fprintf(b, "%s Policy: `%s`\n\n", h, id)

	if desc := p.GetMeta().GetDescription(); desc != "" {
		fmt.Fprintf(b, "%s\n\n", desc)
	}

	assertMode := p.GetMeta().GetAssertMode()
	if assertMode == "" {
		assertMode = defaultAssertMode
	}
	section(b, h+"# Overview")
	fmt.Fprintln(b, "| Property | Value |")
	fmt.Fprintln(b, "|----------|-------|")
	fmt.Fprintln(b, "| **Type** | Policy |")
	fmt.Fprintf(b, "| **Assert mode** | %s |\n", assertMode)
	fmt.Fprintf(b, "| **Tenets** | %d |\n", len(p.GetTenets()))
	if enforce := p.GetMeta().GetEnforce(); enforce != "" {
		fmt.Fprintf(b, "| **Enforce** | %s |\n", enforce)
	}
	fmt.Fprintln(b)

	if ctx := p.GetContext(); len(ctx) > 0 {
		section(b, h+"# Context Values")
		writeContextTable(b, ctx)
	}

	if ids := p.GetIdentities(); len(ids) > 0 {
		section(b, h+"# Identities")
		writeIdentities(b, ids)
	}

	if len(p.GetTenets()) > 0 {
		section(b, h+"# Tenets")
		for i, t := range p.GetTenets() {
			writeTenet(b, t, i, headingLevel+2)
		}
	}

	writeChangelog(b, p.GetMeta().GetChangelog(), h+"# Changelog")
}

func writeChangelog(b *strings.Builder, entries []*papi.ChangeLog, heading string) {
	if len(entries) == 0 {
		return
	}
	section(b, heading)
	fmt.Fprintln(b, "| Version | Date | Change |")
	fmt.Fprintln(b, "|---------|------|--------|")
	for _, e := range entries {
		version := e.GetVersion()
		date := ""
		if d := e.GetDate(); d != nil {
			date = d.AsTime().Format("2006-01-02")
		}
		msg := strings.ReplaceAll(e.GetMessage(), "\n", " ")
		fmt.Fprintf(b, "| %s | %s | %s |\n", version, date, msg)
	}
	fmt.Fprintln(b)
}

func writeTenet(b *strings.Builder, t *papi.Tenet, index, headingLevel int) {
	h := strings.Repeat("#", headingLevel)

	id := t.GetId()
	if id == "" {
		id = fmt.Sprintf("tenet-%d", index+1)
	}
	fmt.Fprintf(b, "%s Tenet: `%s`\n\n", h, id)

	if preds := t.GetPredicates(); preds != nil && len(preds.GetTypes()) > 0 {
		fmt.Fprintln(b, "**Attestation types:**")
		for _, pt := range preds.GetTypes() {
			fmt.Fprintf(b, "- `%s`\n", pt)
		}
		fmt.Fprintln(b)
	}

	if code := t.GetCode(); code != "" {
		fmt.Fprintf(b, "**Evaluation:**\n```cel\n%s\n```\n\n", code)
	}

	if outs := t.GetOutputs(); len(outs) > 0 {
		fmt.Fprintln(b, "**Outputs:**")
		for name, out := range outs {
			fmt.Fprintf(b, "- `%s`: `%s`\n", name, truncate(out.GetCode(), 80))
		}
		fmt.Fprintln(b)
	}

	if msg := t.GetAssessment().GetMessage(); msg != "" {
		fmt.Fprintf(b, "**On pass:** %s\n\n", msg)
	}
	if err := t.GetError(); err != nil {
		if msg := err.GetMessage(); msg != "" {
			fmt.Fprintf(b, "**On fail:** %s\n", msg)
		}
		if g := err.GetGuidance(); g != "" {
			fmt.Fprintf(b, "**Guidance:** %s\n", g)
		}
		fmt.Fprintln(b)
	}
}

func writeContextTable(b *strings.Builder, ctx map[string]*papi.ContextVal) {
	fmt.Fprintln(b, "| Name | Type | Required | Default |")
	fmt.Fprintln(b, "|------|------|----------|---------|")
	for name, cv := range ctx {
		req := "no"
		if cv.GetRequired() {
			req = "**yes**"
		}
		def := ""
		if dv := cv.GetDefault(); dv != nil {
			def = fmt.Sprintf("`%s`", formatValue(dv))
		}
		fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", name, cv.GetType(), req, def)
	}
	fmt.Fprintln(b)
}

func writeIdentities(b *strings.Builder, ids []*sapi.Identity) {
	fmt.Fprintln(b, "| Type | Issuer | Identity |")
	fmt.Fprintln(b, "|------|--------|----------|")
	for _, id := range ids {
		if sig := id.GetSigstore(); sig != nil {
			mode := sig.GetMode()
			if mode == "" {
				mode = "exact"
			}
			fmt.Fprintf(b, "| sigstore (%s) | `%s` | `%s` |\n", mode, sig.GetIssuer(), sig.GetIdentity())
		} else if key := id.GetKey(); key != nil {
			fmt.Fprintf(b, "| key | `%s` | `%s` |\n", key.GetType(), key.GetId())
		}
	}
	fmt.Fprintln(b)
}

// section writes a markdown heading followed by a blank line.
func section(b *strings.Builder, heading string) {
	fmt.Fprintln(b, heading)
	fmt.Fprintln(b)
}

func formatValue(v *structpb.Value) string {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		return k.StringValue
	case *structpb.Value_NumberValue:
		return fmt.Sprintf("%g", k.NumberValue)
	case *structpb.Value_BoolValue:
		return fmt.Sprintf("%t", k.BoolValue)
	case *structpb.Value_NullValue:
		return "null"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func policyRefLabel(p *papi.Policy) string {
	if p.GetId() != "" {
		return p.GetId()
	}
	if src := p.GetSource(); src != nil && src.GetLocation() != nil {
		uri := src.GetLocation().GetUri()
		if idx := strings.LastIndex(uri, "#"); idx >= 0 {
			return uri[idx+1:]
		}
		return uri
	}
	return "(unknown)"
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
