// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package doc

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	papi "github.com/carabiner-dev/policy/api/v1"
)

// IndexEntry is a policy material listed in an index.
type IndexEntry struct {
	// Element is the compiled *papi.Policy, *papi.PolicySet or *papi.PolicyGroup.
	Element any
	// Link is the path of the element's document relative to the index
	// location. Its ID links there when set and stays plain text otherwise.
	Link string
}

// Index lists policy materials by kind as markdown tables: policies with
// their name and the predicate types they consume, sets and groups with
// their composition and the predicate types consumed by everything inside.
//
// Each table is wrapped in marker comments so Inject can refresh a document
// that carries hand written text around and between the tables.
type Index struct {
	policies []IndexEntry
	sets     []IndexEntry
	groups   []IndexEntry
}

// NewIndex classifies entries by kind. It fails on unsupported elements.
func NewIndex(entries []IndexEntry) (*Index, error) {
	idx := &Index{}
	for _, e := range entries {
		switch e.Element.(type) {
		case *papi.Policy:
			idx.policies = append(idx.policies, e)
		case *papi.PolicySet:
			idx.sets = append(idx.sets, e)
		case *papi.PolicyGroup:
			idx.groups = append(idx.groups, e)
		default:
			return nil, fmt.Errorf("unsupported element type: %T", e.Element)
		}
	}
	sortEntries(idx.policies)
	sortEntries(idx.sets)
	sortEntries(idx.groups)
	return idx, nil
}

// indexSection is one generated region of the index.
type indexSection struct {
	name    string // marker name
	heading string // heading written when the section is created
	body    string // the table, or a placeholder when there are no entries
	empty   bool
}

// IndexMarker returns the comment delimiting a generated region of an index:
// section is "policies", "sets" or "groups" and edge is "begin" or "end".
func IndexMarker(section, edge string) string {
	return fmt.Sprintf("<!-- policyctl:index:%s:%s -->", section, edge)
}

// render writes the section as created in a new document: its heading and
// the table between markers.
func (s indexSection) render() string {
	return s.heading + "\n\n" + IndexMarker(s.name, "begin") + "\n" + s.body + "\n" + IndexMarker(s.name, "end") + "\n"
}

// Render produces a complete index document: the title followed by a section
// per kind that has entries.
func (idx *Index) Render(title string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", title)
	for _, s := range idx.sections() {
		if s.empty {
			continue
		}
		b.WriteString("\n")
		b.WriteString(s.render())
	}
	return b.String()
}

// Inject refreshes the marked regions of an existing document with the
// current tables and leaves everything outside the markers untouched, so a
// title, an introduction and per section text survive regeneration. A section
// with entries but no markers is appended at the end. Inject fails when a
// section has only one of its markers or they are out of order.
func (idx *Index) Inject(existing string) (string, error) {
	out := existing
	var missing []indexSection
	for _, s := range idx.sections() {
		begin, end := IndexMarker(s.name, "begin"), IndexMarker(s.name, "end")
		bi, ei := strings.Index(out, begin), strings.Index(out, end)
		switch {
		case bi < 0 && ei < 0:
			if !s.empty {
				missing = append(missing, s)
			}
			continue
		case bi < 0 || ei < 0 || ei < bi:
			return "", fmt.Errorf("unbalanced %s index markers", s.name)
		}
		out = out[:bi+len(begin)] + "\n" + s.body + "\n" + out[ei:]
	}
	for _, s := range missing {
		out = strings.TrimRight(out, "\n") + "\n\n" + s.render()
	}
	return out, nil
}

// sections builds the generated regions in document order.
func (idx *Index) sections() []indexSection {
	return []indexSection{
		{name: "policies", heading: "## Policies", body: idx.policiesTable(), empty: len(idx.policies) == 0},
		{name: "sets", heading: "## Policy sets", body: idx.setsTable(), empty: len(idx.sets) == 0},
		{name: "groups", heading: "## Policy groups", body: idx.groupsTable(), empty: len(idx.groups) == 0},
	}
}

const noEntries = "_None._"

func (idx *Index) policiesTable() string {
	if len(idx.policies) == 0 {
		return noEntries
	}
	var b strings.Builder
	b.WriteString("| ID | Name | Predicate types |\n")
	b.WriteString("|----|------|-----------------|\n")
	for _, e := range idx.policies {
		p, _ := e.Element.(*papi.Policy) //nolint:errcheck // NewIndex classified the element
		fmt.Fprintf(&b, "| %s | %s | %s |\n",
			indexLink(policyID(p), e.Link), tableCell(p.GetMeta().GetName()), typesCell(policyInputTypes(p)))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (idx *Index) setsTable() string {
	if len(idx.sets) == 0 {
		return noEntries
	}
	var b strings.Builder
	b.WriteString("| ID | Policies | Groups | Predicate types |\n")
	b.WriteString("|----|----------|--------|-----------------|\n")
	for _, e := range idx.sets {
		ps, _ := e.Element.(*papi.PolicySet) //nolint:errcheck // NewIndex classified the element
		fmt.Fprintf(&b, "| %s | %d | %d | %s |\n",
			indexLink(ps.GetId(), e.Link), len(ps.GetPolicies()), len(ps.GetGroups()), typesCell(setInputTypes(ps)))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (idx *Index) groupsTable() string {
	if len(idx.groups) == 0 {
		return noEntries
	}
	var b strings.Builder
	b.WriteString("| ID | Blocks | Policies | Predicate types |\n")
	b.WriteString("|----|--------|----------|-----------------|\n")
	for _, e := range idx.groups {
		pg, _ := e.Element.(*papi.PolicyGroup) //nolint:errcheck // NewIndex classified the element
		policies := 0
		for _, block := range pg.GetBlocks() {
			policies += len(block.GetPolicies())
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %s |\n",
			indexLink(pg.GetId(), e.Link), len(pg.GetBlocks()), policies, typesCell(groupInputTypes(pg)))
	}
	return strings.TrimRight(b.String(), "\n")
}

// setInputTypes returns the predicate types consumed by the policies of a
// set and of the groups it contains, sorted and without duplicates.
func setInputTypes(ps *papi.PolicySet) []string {
	seen := map[string]struct{}{}
	for _, p := range ps.GetPolicies() {
		for _, t := range policyInputTypes(p) {
			seen[t] = struct{}{}
		}
	}
	for _, pg := range ps.GetGroups() {
		for _, t := range groupInputTypes(pg) {
			seen[t] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// groupInputTypes returns the predicate types consumed by the policies in
// the blocks of a group, sorted and without duplicates.
func groupInputTypes(pg *papi.PolicyGroup) []string {
	seen := map[string]struct{}{}
	for _, block := range pg.GetBlocks() {
		for _, p := range block.GetPolicies() {
			for _, t := range policyInputTypes(p) {
				seen[t] = struct{}{}
			}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// indexLink renders an ID in code style, linked to its document when known.
func indexLink(id, link string) string {
	cell := "`" + tableCell(id) + "`"
	if link == "" {
		return cell
	}
	return fmt.Sprintf("[%s](%s)", cell, link)
}

// typesCell lists predicate types one per line inside a table cell.
func typesCell(types []string) string {
	if len(types) == 0 {
		return ""
	}
	cells := make([]string, 0, len(types))
	for _, t := range types {
		cells = append(cells, "`"+tableCell(t)+"`")
	}
	return strings.Join(cells, "<br>")
}

// tableCell makes text safe inside a markdown table cell.
func tableCell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

// sortEntries orders entries by element ID so the index is reproducible
// regardless of the order the files were given in.
func sortEntries(entries []IndexEntry) {
	slices.SortStableFunc(entries, func(a, b IndexEntry) int {
		return strings.Compare(elementID(a.Element), elementID(b.Element))
	})
}

func elementID(element any) string {
	switch v := element.(type) {
	case *papi.Policy:
		return policyID(v)
	case *papi.PolicySet:
		return v.GetId()
	case *papi.PolicyGroup:
		return v.GetId()
	default:
		return ""
	}
}
