// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/carabiner-dev/policy"
	api "github.com/carabiner-dev/policy/api/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

func addUpdate(parentCmd *cobra.Command) {
	var (
		fromJSON string
		force    bool
	)
	updateCmd := &cobra.Command{
		Short: "update policy references to their latest versions",
		Use:   "update [flags] <location> [<location>...]",
		Long: `Resolve each location as a policy file or a directory of policies,
look up updates for every external reference, and patch the matching
policy source files in place.

Only filesystem locations are supported: remote (VCS locator) locations
will be skipped.

By default, the available updates are displayed as a table and the user
is asked to confirm before anything is written. Use --force to skip the
prompt and apply updates directly.

When --from-json is provided, updates are read from the given plan file
instead of being computed from scratch. The plan file is the JSON
document produced by 'policyctl check-update --format=json'; no remote
calls are made in this mode.

The patch rewrites old URIs, download locations, and digest values in
place so that the resulting diff against the original file is limited to
the strings that actually changed.`,
		Example:           fmt.Sprintf(`  %s update ./policies`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			u := policy.NewUpdater()

			var (
				applied map[string][]*policy.RefUpdate
				err     error
			)
			switch {
			case fromJSON != "":
				if len(args) > 0 {
					return fmt.Errorf("--from-json cannot be combined with positional locations")
				}
				applied, err = runFromJSON(u, fromJSON, force)
			default:
				if len(args) == 0 {
					return fmt.Errorf("at least one location is required (or use --from-json)")
				}
				applied, err = runFromLocations(u, args, force)
			}
			if err != nil {
				return err
			}
			reportApplied(applied)
			return nil
		},
	}
	updateCmd.Flags().StringVar(
		&fromJSON, "from-json", "",
		"apply updates from a plan file produced by 'check-update --format=json'",
	)
	updateCmd.Flags().BoolVar(
		&force, "force", false,
		"skip the confirmation prompt and apply updates directly",
	)
	parentCmd.AddCommand(updateCmd)
}

// runFromLocations handles the default path: check for updates, show
// them, ask for confirmation, then apply. When force is set, skips both
// the table and the prompt and delegates to Updater.Update.
func runFromLocations(u *policy.Updater, args []string, force bool) (map[string][]*policy.RefUpdate, error) {
	if force {
		return u.Update(args...)
	}

	updates, err := u.CheckUpdates(args...)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		fmt.Fprintln(os.Stderr, "no policy references have updates available")
		return nil, nil
	}
	printUpdatesTable(os.Stdout, updates)
	if !confirm("Apply these updates?") {
		fmt.Fprintln(os.Stderr, "aborted; no files were modified")
		return nil, nil
	}
	return u.ApplyUpdates(updates)
}

// runFromJSON handles the --from-json path: decode the plan, show it,
// optionally prompt, then apply.
func runFromJSON(u *policy.Updater, path string, force bool) (map[string][]*policy.RefUpdate, error) {
	updates, err := loadPlanFile(path)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		fmt.Fprintln(os.Stderr, "plan file contains no updates to apply")
		return nil, nil
	}
	if !force {
		printUpdatesTable(os.Stdout, updates)
		if !confirm("Apply these updates?") {
			fmt.Fprintln(os.Stderr, "aborted; no files were modified")
			return nil, nil
		}
	}
	return u.ApplyUpdates(updates)
}

func reportApplied(applied map[string][]*policy.RefUpdate) {
	if len(applied) == 0 {
		fmt.Fprintln(os.Stderr, "no policy references needed updating")
		return
	}
	files := make([]string, 0, len(applied))
	for f := range applied {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		fmt.Fprintf(os.Stdout, "updated %s (%d reference(s))\n", f, len(applied[f])) //nolint:errcheck // stdout write errors are not actionable here
		for _, r := range applied[f] {
			fmt.Fprintf(os.Stdout, "  - %s\n", r.Old.GetLocation().GetUri()) //nolint:errcheck // stdout write errors are not actionable here
		}
	}
}

func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

// loadPlanFile decodes the JSON plan produced by check-update into the
// map shape accepted by Updater.ApplyUpdates.
func loadPlanFile(path string) (map[string][]*policy.RefUpdate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading plan file: %w", err)
	}

	var plan updatePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("decoding plan file: %w", err)
	}

	out := map[string][]*policy.RefUpdate{}
	for file, entries := range plan.Files {
		refs := make([]*policy.RefUpdate, 0, len(entries))
		for i, e := range entries {
			oldRef := &api.PolicyRef{}
			if err := protojson.Unmarshal(e.Old, oldRef); err != nil {
				return nil, fmt.Errorf("decoding old ref %d for %s: %w", i, file, err)
			}
			newRef := &api.PolicyRef{}
			if err := protojson.Unmarshal(e.New, newRef); err != nil {
				return nil, fmt.Errorf("decoding new ref %d for %s: %w", i, file, err)
			}
			refs = append(refs, &policy.RefUpdate{Old: oldRef, New: newRef})
		}
		out[file] = refs
	}
	return out, nil
}
