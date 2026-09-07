// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"strings"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	slsaType   = "https://slsa.dev/provenance/v1"
	osvType    = "https://ossf.github.io/osv-schema/results@v1"
	typeString = "string"
)

// fullPolicy declares every kind of input and two tenets.
func fullPolicy(assertMode string) *papi.Policy {
	return &papi.Policy{
		Id:         "FULL",
		Meta:       &papi.Meta{Name: "Full Policy", AssertMode: assertMode},
		Predicates: &papi.PredicateSpec{Types: []string{slsaType}},
		Context: map[string]*papi.ContextVal{
			"zeta":  {Type: "bool", Default: structpb.NewBoolValue(true)},
			"alpha": {Type: typeString, Required: boolPtr(true)},
			"empty": {Type: typeString, Default: structpb.NewStringValue("")},
			"ref":   {Type: typeString, Default: structpb.NewStringValue("main")},
		},
		Chain: []*papi.ChainLink{{
			Source: &papi.ChainLink_Predicate{Predicate: &papi.ChainedPredicate{
				Type:     osvType,
				Selector: "predicate.results[0].source.path",
			}},
		}},
		Tenets: []*papi.Tenet{
			{Id: "t01", Title: "Has provenance"},
			{Id: "t02", Predicates: &papi.PredicateSpec{Types: []string{osvType}}},
		},
	}
}

func boolPtr(b bool) *bool { return &b }

func assertContains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in:\n%s", want, got)
		}
	}
}

func TestMermaidPolicy(t *testing.T) {
	t.Parallel()
	got := Mermaid{}.Policy(fullPolicy("OR"))

	assertContains(t, got,
		"```mermaid\nflowchart TD\n",
		"subgraph inputs[\"Inputs\"]",
		"A0[\"📄 "+osvType+"\"]",
		"A1[\"📄 "+slsaType+"\"]",
		"C0[\"⚙️ alpha: string (required)\"]",
		"C1[\"⚙️ empty: string = #quot;#quot;\"]",
		"C2[\"⚙️ ref: string = #quot;main#quot;\"]",
		"C3[\"⚙️ zeta: bool = true\"]",
		"L0[\"⛓️ "+osvType+"<br/>predicate.results[0].source.path\"]",
		"P[\"🛡️ Full Policy\"]",
		"inputs --> P",
		"P --> P_M{\"ANY tenet passing suffices\"}",
		"P_M --> P_T0[\"📋 Has provenance\"]",
		"P_M --> P_T1[\"📋 t02<br/>ossf.github.io/osv-schema/results@v1\"]",
	)
	if !strings.HasSuffix(got, "```\n") {
		t.Errorf("expected a closed fence, got:\n%s", got)
	}
	// Inputs come sorted so the document is reproducible.
	if strings.Index(got, "alpha") > strings.Index(got, "zeta") {
		t.Errorf("expected context values sorted by name in:\n%s", got)
	}
}

func TestMermaidPolicyAssertModes(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		mode string
		want string
	}{
		{name: "AND requires all tenets", mode: "AND", want: "{\"ALL tenets must pass\"}"},
		{name: "empty mode documents as AND", mode: "", want: "{\"ALL tenets must pass\"}"},
		{name: "OR needs any tenet", mode: "OR", want: "{\"ANY tenet passing suffices\"}"},
		{name: "unknown mode shown as declared", mode: "XOR", want: "{\"XOR\"}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertContains(t, Mermaid{}.Policy(fullPolicy(tt.mode)), tt.want)
		})
	}
}

func TestMermaidPolicyMinimal(t *testing.T) {
	t.Parallel()
	got := Mermaid{}.Policy(&papi.Policy{Id: "MIN", Tenets: []*papi.Tenet{{Id: "only"}}})

	assertContains(t, got, "P[\"🛡️ MIN\"]", "P --> P_T0[\"📋 only\"]")
	for _, unwanted := range []string{"subgraph", "inputs --> P", "P_M"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("did not expect %q in:\n%s", unwanted, got)
		}
	}
}

func TestMermaidLabelEscapesQuotes(t *testing.T) {
	t.Parallel()
	got := Mermaid{}.Policy(&papi.Policy{Id: "Q", Meta: &papi.Meta{Name: "Say \"hi\"\nthere"}})
	assertContains(t, got, "P[\"🛡️ Say #quot;hi#quot; there\"]")
}

func TestMermaidPolicyGroup(t *testing.T) {
	t.Parallel()
	ref := func(uri string) *papi.Policy {
		return &papi.Policy{Source: &papi.PolicyRef{Location: &gointoto.ResourceDescriptor{Uri: uri}}}
	}
	group := &papi.PolicyGroup{
		Id:   "VM-04",
		Meta: &papi.PolicyGroupMeta{AssertMode: "OR"},
		Blocks: []*papi.PolicyBlock{
			{Policies: []*papi.Policy{ref("git+https://example.com/policies#openvex/vexing.json")}},
			{
				Id:   "scanners",
				Meta: &papi.PolicyBlockMeta{AssertMode: "AND"},
				Policies: []*papi.Policy{
					{Id: "GRYPE", Meta: &papi.Meta{Name: "Grype clean"}},
					{Id: "TRIVY"},
				},
			},
		},
	}
	got := Mermaid{}.PolicyGroup(group)

	assertContains(t, got,
		"G[\"📂 VM-04\"]",
		"G --> G_M{\"ANY block passing suffices\"}",
		"G_M --> G_B0[\"⚡ Block 1\"]",
		"G_B0 --> G_B0_P0[\"🔗 openvex/vexing.json\"]",
		"G_M --> G_B1{\"⚡ scanners<br/>ALL policies must pass\"}",
		"G_B1 --> G_B1_P0[\"🛡️ Grype clean\"]",
		"G_B1 --> G_B1_P1[\"🛡️ TRIVY\"]",
	)
}

func TestMermaidPolicyGroupSingleBlock(t *testing.T) {
	t.Parallel()
	group := &papi.PolicyGroup{
		Id:     "ONE",
		Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "A"}, {Id: "B"}}}},
	}
	got := Mermaid{}.PolicyGroup(group)

	assertContains(t, got, "G --> G_B0{\"⚡ Block 1<br/>ALL policies must pass\"}", "G_B0 --> G_B0_P1[\"🛡️ B\"]")
	if strings.Contains(got, "G_M") {
		t.Errorf("did not expect a group decision node for a single block in:\n%s", got)
	}
}

func TestMermaidPolicySet(t *testing.T) {
	t.Parallel()
	set := &papi.PolicySet{
		Id: "SET",
		Policies: []*papi.Policy{
			fullPolicy("AND"),
			{Id: "SINGLE", Tenets: []*papi.Tenet{{Id: "t"}}},
		},
		Groups: []*papi.PolicyGroup{{
			Id:     "GRP",
			Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "IN-GROUP"}}}},
		}},
	}
	got := Mermaid{}.PolicySet(set)

	assertContains(t, got,
		"S[\"📦 SET\"]",
		"S --> P0[\"🛡️ Full Policy\"]",
		"P0 --> P0_M{\"ALL tenets must pass\"}",
		"P0_M --> P0_T1[\"📋 t02<br/>ossf.github.io/osv-schema/results@v1\"]",
		"S --> P1[\"🛡️ SINGLE\"]",
		"P1 --> P1_T0[\"📋 t\"]",
		"S --> G0[\"📂 GRP\"]",
		"G0 --> G0_B0[\"⚡ Block 1\"]",
		"G0_B0 --> G0_B0_P0[\"🛡️ IN-GROUP\"]",
	)
}
