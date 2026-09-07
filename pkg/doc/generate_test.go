// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"strings"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
)

const (
	testPolicyID = "MY-POLICY"
	testSetID    = "MY-SET"
	testGroupID  = "MY-GROUP"

	testPolicyName = "My Policy"
)

// firstLine returns the first line of a document.
func firstLine(t *testing.T, md string) string {
	t.Helper()
	line, _, _ := strings.Cut(md, "\n")
	return line
}

func TestGenerateHeadings(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		element     any
		wantHeading string
		wantRows    []string
	}{
		{
			name:        "named policy uses its name as the title",
			element:     &papi.Policy{Id: testPolicyID, Meta: &papi.Meta{Name: testPolicyName}},
			wantHeading: "# My Policy",
			wantRows:    []string{"| **Type** | Policy |", "| **ID** | `MY-POLICY` |"},
		},
		{
			name:        "unnamed policy keeps the kind and id heading",
			element:     &papi.Policy{Id: testPolicyID},
			wantHeading: "# Policy: `MY-POLICY`",
			wantRows:    []string{"| **ID** | `MY-POLICY` |"},
		},
		{
			name:        "policy set heading is unchanged",
			element:     &papi.PolicySet{Id: testSetID},
			wantHeading: "# PolicySet: `MY-SET`",
		},
		{
			name:        "policy group heading is unchanged",
			element:     &papi.PolicyGroup{Id: testGroupID},
			wantHeading: "# PolicyGroup: `MY-GROUP`",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			md, err := Generate(tt.element)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := firstLine(t, md); got != tt.wantHeading {
				t.Errorf("first line = %q, want %q", got, tt.wantHeading)
			}
			for _, row := range tt.wantRows {
				if !strings.Contains(md, row+"\n") {
					t.Errorf("expected overview row %q in:\n%s", row, md)
				}
			}
		})
	}
}

func TestGenerateNestedPolicyNames(t *testing.T) {
	t.Parallel()
	set := &papi.PolicySet{
		Id: testSetID,
		Policies: []*papi.Policy{
			{Id: "FIRST", Meta: &papi.Meta{Name: "First Policy"}},
			{Id: "SECOND"},
		},
	}
	md, err := Generate(set)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"# PolicySet: `MY-SET`\n",
		"### First Policy\n",
		"### Policy: `SECOND`\n",
		"| **ID** | `FIRST` |\n",
		"| **ID** | `SECOND` |\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("expected %q in:\n%s", want, md)
		}
	}
}

func TestGenerateInlinePolicyHasNoIDRow(t *testing.T) {
	t.Parallel()
	md, err := Generate(&papi.Policy{Meta: &papi.Meta{Name: "Inline"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := firstLine(t, md); got != "# Inline" {
		t.Errorf("first line = %q, want %q", got, "# Inline")
	}
	if strings.Contains(md, "| **ID** |") {
		t.Errorf("expected no ID row for an inline policy in:\n%s", md)
	}
}

func TestTitle(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		element any
		want    string
	}{
		{name: "named policy", element: &papi.Policy{Id: testPolicyID, Meta: &papi.Meta{Name: testPolicyName}}, want: testPolicyName},
		{name: "unnamed policy", element: &papi.Policy{Id: testPolicyID}, want: "Policy: MY-POLICY"},
		{name: "inline unnamed policy", element: &papi.Policy{}, want: "Policy: (inline policy)"},
		{name: "policy set", element: &papi.PolicySet{Id: testSetID}, want: "PolicySet: MY-SET"},
		{name: "policy group", element: &papi.PolicyGroup{Id: testGroupID}, want: "PolicyGroup: MY-GROUP"},
		{name: "unsupported element", element: "not a policy", want: "Policy Documentation"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Title(tt.element); got != tt.want {
				t.Errorf("Title() = %q, want %q", got, tt.want)
			}
		})
	}
}

// nestedSet holds two inline policies and a group with one inline policy.
func nestedSet() *papi.PolicySet {
	return &papi.PolicySet{
		Id:       testSetID,
		Policies: []*papi.Policy{{Id: "P-ONE"}, {Id: "P-TWO"}},
		Groups: []*papi.PolicyGroup{{
			Id:     testGroupID,
			Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "P-THREE"}}}},
		}},
	}
}

func TestGenerateDiagramOptions(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		element  any
		opts     []Option
		wantMerm int // fenced mermaid blocks in the document
	}{
		{name: "policy gets its diagram by default", element: &papi.Policy{Id: testPolicyID}, wantMerm: 1},
		{name: "policy without diagrams", element: &papi.Policy{Id: testPolicyID}, opts: []Option{WithoutDiagrams()}, wantMerm: 0},
		{name: "group gets one structure diagram", element: &papi.PolicyGroup{Id: testGroupID, Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "P"}}}}}, wantMerm: 1},
		{name: "group with policy details", element: &papi.PolicyGroup{Id: testGroupID, Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "P"}}}}}, opts: []Option{WithPolicyDetails(true)}, wantMerm: 2},
		{name: "set and its group get structure diagrams", element: nestedSet(), wantMerm: 2},
		{name: "set with policy details", element: nestedSet(), opts: []Option{WithPolicyDetails(true)}, wantMerm: 5},
		{name: "set without diagrams", element: nestedSet(), opts: []Option{WithoutDiagrams(), WithPolicyDetails(true)}, wantMerm: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			md, err := Generate(tt.element, tt.opts...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.Count(md, "```mermaid\n"); got != tt.wantMerm {
				t.Errorf("found %d mermaid blocks, want %d, in:\n%s", got, tt.wantMerm, md)
			}
			if wantSections := tt.wantMerm; strings.Count(md, "# Structure\n") != wantSections {
				t.Errorf("found %d Structure sections, want %d, in:\n%s", strings.Count(md, "# Structure\n"), wantSections, md)
			}
		})
	}
}

// stubDiagrammer proves Generate embeds whatever markdown a Diagrammer returns.
type stubDiagrammer struct{}

func (stubDiagrammer) Policy(*papi.Policy) string           { return "![policy](policy.svg)\n" }
func (stubDiagrammer) PolicyGroup(*papi.PolicyGroup) string { return "![group](group.svg)\n" }
func (stubDiagrammer) PolicySet(*papi.PolicySet) string     { return "![set](set.svg)\n" }

func TestGenerateCustomDiagrammer(t *testing.T) {
	t.Parallel()
	md, err := Generate(nestedSet(), WithDiagrammer(stubDiagrammer{}), WithPolicyDetails(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"## Structure\n\n![set](set.svg)\n", "![policy](policy.svg)", "![group](group.svg)"} {
		if !strings.Contains(md, want) {
			t.Errorf("expected %q in:\n%s", want, md)
		}
	}
	if strings.Contains(md, "mermaid") {
		t.Errorf("did not expect mermaid output with a custom diagrammer:\n%s", md)
	}
}
