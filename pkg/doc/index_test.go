// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"strings"
	"testing"

	papi "github.com/carabiner-dev/policy/api/v1"
)

const indexTitle = "Policy index"

// sampleIndex returns an index with two policies given out of order, one set
// and one group.
func sampleIndex(t *testing.T) *Index {
	t.Helper()
	idx, err := NewIndex([]IndexEntry{
		{Element: &papi.Policy{
			Id:   "ZETA",
			Meta: &papi.Meta{Name: "Zeta | last"},
			Tenets: []*papi.Tenet{
				{Predicates: &papi.PredicateSpec{Types: []string{slsaType}}},
				{Predicates: &papi.PredicateSpec{Types: []string{osvType, slsaType}}},
			},
		}, Link: "zeta.md"},
		{Element: &papi.Policy{Id: "ALPHA", Predicates: &papi.PredicateSpec{Types: []string{osvType}}}},
		{Element: &papi.PolicySet{
			Id:       "THE-SET",
			Policies: []*papi.Policy{{Id: "IN-SET", Predicates: &papi.PredicateSpec{Types: []string{slsaType}}}},
			Groups: []*papi.PolicyGroup{{
				Id:     "IN-SET-GROUP",
				Blocks: []*papi.PolicyBlock{{Policies: []*papi.Policy{{Id: "DEEP", Predicates: &papi.PredicateSpec{Types: []string{osvType}}}}}},
			}},
		}, Link: "sets/the-set.md"},
		{Element: &papi.PolicyGroup{
			Id: "THE-GROUP",
			Blocks: []*papi.PolicyBlock{
				{Policies: []*papi.Policy{{Id: "A", Predicates: &papi.PredicateSpec{Types: []string{osvType}}}, {Id: "B"}}},
				{Policies: []*papi.Policy{{Id: "C", Predicates: &papi.PredicateSpec{Types: []string{osvType}}}}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return idx
}

func TestNewIndexRejectsUnsupported(t *testing.T) {
	t.Parallel()
	if _, err := NewIndex([]IndexEntry{{Element: "nope"}}); err == nil {
		t.Fatal("expected an error for an unsupported element")
	}
}

func TestIndexRender(t *testing.T) {
	t.Parallel()
	got := sampleIndex(t).Render(indexTitle)

	assertContains(t, got,
		"# Policy index\n\n## Policies\n\n"+IndexMarker("policies", "begin")+"\n| ID | Name | Predicate types |\n",
		"| `ALPHA` |  | `"+osvType+"` |\n| [`ZETA`](zeta.md) | Zeta \\| last | `"+osvType+"`<br>`"+slsaType+"` |\n"+IndexMarker("policies", "end"),
		"## Policy sets\n\n"+IndexMarker("sets", "begin")+"\n| ID | Policies | Groups | Predicate types |\n",
		"| [`THE-SET`](sets/the-set.md) | 1 | 1 | `"+osvType+"`<br>`"+slsaType+"` |",
		"## Policy groups\n\n"+IndexMarker("groups", "begin")+"\n| ID | Blocks | Policies | Predicate types |\n",
		"| `THE-GROUP` | 2 | 3 | `"+osvType+"` |",
	)
}

func TestIndexRenderOmitsEmptySections(t *testing.T) {
	t.Parallel()
	idx, err := NewIndex([]IndexEntry{{Element: &papi.Policy{Id: "ONLY"}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := idx.Render(indexTitle)
	for _, unwanted := range []string{"## Policy sets", "## Policy groups", noEntries} {
		if strings.Contains(got, unwanted) {
			t.Errorf("did not expect %q in:\n%s", unwanted, got)
		}
	}
}

func TestIndexInjectPreservesText(t *testing.T) {
	t.Parallel()
	existing := "# My policies\n\nAn introduction.\n\n## Policies\n\nAbout the policies.\n\n" +
		IndexMarker("policies", "begin") + "\n| stale |\n" + IndexMarker("policies", "end") + "\n\nTrailing notes.\n"

	got, err := sampleIndex(t).Inject(existing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertContains(t, got,
		"# My policies\n\nAn introduction.\n\n## Policies\n\nAbout the policies.\n\n"+IndexMarker("policies", "begin")+"\n| ID | Name | Predicate types |\n",
		IndexMarker("policies", "end")+"\n\nTrailing notes.\n\n## Policy sets\n\n"+IndexMarker("sets", "begin"),
		"## Policy groups\n\n"+IndexMarker("groups", "begin"),
	)
	if strings.Contains(got, "| stale |") {
		t.Errorf("expected the stale table replaced in:\n%s", got)
	}
	if strings.Count(got, "## Policies") != 1 {
		t.Errorf("expected the existing policies heading kept once in:\n%s", got)
	}
}

func TestIndexInjectEmptySectionKeepsMarkers(t *testing.T) {
	t.Parallel()
	idx, err := NewIndex([]IndexEntry{{Element: &papi.Policy{Id: "ONLY"}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	existing := IndexMarker("sets", "begin") + "\n| old set |\n" + IndexMarker("sets", "end") + "\n"

	got, err := idx.Inject(existing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContains(t, got, IndexMarker("sets", "begin")+"\n"+noEntries+"\n"+IndexMarker("sets", "end"))
	if strings.Contains(got, "## Policy groups") {
		t.Errorf("did not expect an empty groups section appended in:\n%s", got)
	}
}

func TestIndexInjectUnbalancedMarkers(t *testing.T) {
	t.Parallel()
	for name, existing := range map[string]string{
		"missing end":   IndexMarker("policies", "begin") + "\n",
		"missing begin": IndexMarker("policies", "end") + "\n",
		"reversed":      IndexMarker("policies", "end") + "\n" + IndexMarker("policies", "begin") + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := sampleIndex(t).Inject(existing); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
