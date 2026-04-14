// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	outputFormatTable = "table"
	outputFormatJSON  = "json"
)

const (
	defaultTerminalWidth = 100
	shortDigestLen       = 9
)

func addCheckUpdate(parentCmd *cobra.Command) {
	var format string
	cmd := &cobra.Command{
		Short:         "check policy references for available updates",
		Use:           "check-update [flags] <location> [<location>...]",
		Example:       fmt.Sprintf("  %s check-update ./policies", appname),
		SilenceUsage:  false,
		SilenceErrors: true,
		Long: `Check one or more policy source locations for external references
that have updates available.

Each location may be a policy file, a directory containing policies, or a
VCS locator (e.g. git+https://github.com/org/repo@ref#path). Directory
locations are walked and every policy, policy set, or policy group file
discovered is inspected for external references.

For every reference, the upstream repository is queried for its latest
commit. If the referenced policy's content has changed, an entry is
reported showing the old and new commits and digests.`,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("at least one location is required")
			}
			cmd.SilenceUsage = true

			updates, err := policy.NewUpdater().CheckUpdates(args...)
			if err != nil {
				return err
			}

			switch format {
			case outputFormatJSON:
				return writeUpdatesJSON(os.Stdout, updates)
			case outputFormatTable, "":
				if len(updates) == 0 {
					fmt.Fprintln(os.Stderr, "no policy references have updates available")
					return nil
				}
				printUpdatesTable(os.Stdout, updates)
				return nil
			default:
				return fmt.Errorf("unknown format %q (use table or json)", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", outputFormatTable, "output format: table, json")
	parentCmd.AddCommand(cmd)
}

// updatePlan is the JSON shape emitted by --format=json. It is intended
// to be stable enough to be re-ingested as a plan for a future apply
// command (similar to terraform plan output).
type updatePlan struct {
	Version int                    `json:"version"`
	Files   map[string][]planEntry `json:"files"`
}

type planEntry struct {
	Old json.RawMessage `json:"old"`
	New json.RawMessage `json:"new"`
}

func writeUpdatesJSON(out io.Writer, updates map[string][]*policy.RefUpdate) error {
	plan := updatePlan{
		Version: 1,
		Files:   map[string][]planEntry{},
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}
	for file, refs := range updates {
		entries := make([]planEntry, 0, len(refs))
		for _, r := range refs {
			oldRaw, err := marshaler.Marshal(r.Old)
			if err != nil {
				return fmt.Errorf("marshaling old ref for %s: %w", file, err)
			}
			newRaw, err := marshaler.Marshal(r.New)
			if err != nil {
				return fmt.Errorf("marshaling new ref for %s: %w", file, err)
			}
			entries = append(entries, planEntry{Old: oldRaw, New: newRaw})
		}
		plan.Files[file] = entries
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(plan)
}

func printUpdatesTable(out io.Writer, updates map[string][]*policy.RefUpdate) {
	files := make([]string, 0, len(updates))
	for f := range updates {
		files = append(files, f)
	}
	sort.Strings(files)

	width := terminalWidth(out)
	// Reserve space for: "| > " (4), " | " between uri and old (3),
	// " | " between old and new (3), " |" trailing (2). Plus one space
	// of padding on each side of each cell (already part of those 3/2
	// separators), so content budget = width - 12.
	const chromeWidth = 12
	const minURIWidth = 20
	uriWidth := width - chromeWidth - 2*shortDigestLen
	if uriWidth < minURIWidth {
		uriWidth = minURIWidth
	}

	rowWidth := chromeWidth + uriWidth + 2*shortDigestLen
	border := strings.Repeat("-", rowWidth)

	p := func(format string, args ...any) {
		fmt.Fprintf(out, format, args...) //nolint:errcheck // stdout write errors are not actionable here
	}
	for i, f := range files {
		if i > 0 {
			p("\n")
		}
		p("%s\n", border)
		p("| %s |\n", padRight(f, rowWidth-4))
		p("%s\n", border)
		for _, u := range updates[f] {
			uri := bareURI(u.Old.GetLocation().GetUri())
			oldDigest := short(u.Old.GetLocation().GetDigest()["sha256"])
			newDigest := short(u.New.GetLocation().GetDigest()["sha256"])
			p("| > %s | %s | %s |\n",
				padRight(trimLeft(uri, uriWidth), uriWidth),
				padRight(oldDigest, shortDigestLen),
				padRight(newDigest, shortDigestLen),
			)
		}
		p("%s\n", border)
	}
}

// bareURI strips the pinned commit from a VCS locator (the "@<rev>" before
// the subpath fragment), so the URI that is displayed identifies the
// policy location rather than the old revision.
func bareURI(uri string) string {
	hashIdx := strings.Index(uri, "#")
	prefix, suffix := uri, ""
	if hashIdx >= 0 {
		prefix = uri[:hashIdx]
		suffix = uri[hashIdx:]
	}
	if at := strings.LastIndex(prefix, "@"); at >= 0 {
		// Only trim when the '@' is part of the revision (i.e. after "://").
		if scheme := strings.Index(prefix, "://"); scheme < 0 || at > scheme+3 {
			prefix = prefix[:at]
		}
	}
	return prefix + suffix
}

func short(s string) string {
	if len(s) > shortDigestLen {
		return s[:shortDigestLen]
	}
	return s
}

// trimLeft shortens s from the left with a leading ellipsis so it fits in
// `width` runes.
func trimLeft(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[len(s)-width:]
	}
	return "..." + s[len(s)-(width-3):]
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func terminalWidth(out io.Writer) int {
	f, ok := out.(*os.File)
	if !ok {
		return defaultTerminalWidth
	}
	w, _, err := term.GetSize(int(f.Fd())) //nolint:gosec // fd values fit in int on all supported platforms
	if err != nil || w <= 0 {
		return defaultTerminalWidth
	}
	return w
}
