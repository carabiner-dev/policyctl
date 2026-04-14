// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/carabiner-dev/policy/api/v1"
)

func addUpdate(parentCmd *cobra.Command) {
	var fromJSON string
	updateCmd := &cobra.Command{
		Short: "update policy references to their latest versions",
		Use:   "update [flags] <location> [<location>...]",
		Long: `Resolve each location as a policy file or a directory of policies,
look up updates for every external reference, and patch the matching
policy source files in place.

Only filesystem locations are supported: remote (VCS locator) locations
will be skipped.

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
				updates, lerr := loadPlanFile(fromJSON)
				if lerr != nil {
					return lerr
				}
				applied, err = u.ApplyUpdates(updates)
			default:
				if len(args) == 0 {
					return fmt.Errorf("at least one location is required (or use --from-json)")
				}
				applied, err = u.Update(args...)
			}
			if err != nil {
				return err
			}

			if len(applied) == 0 {
				fmt.Fprintln(os.Stderr, "no policy references needed updating")
				return nil
			}

			files := make([]string, 0, len(applied))
			for f := range applied {
				files = append(files, f)
			}
			sort.Strings(files)
			for _, f := range files {
				fmt.Fprintf(os.Stdout, "updated %s (%d reference(s))\n", f, len(applied[f]))
			}
			return nil
		},
	}
	updateCmd.Flags().StringVar(
		&fromJSON, "from-json", "",
		"apply updates from a plan file produced by 'check-update --format=json'",
	)
	parentCmd.AddCommand(updateCmd)
}

// loadPlanFile decodes the JSON plan produced by check-update into the
// map shape accepted by Updater.ApplyUpdates.
func loadPlanFile(path string) (map[string][]*policy.RefUpdate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path provided by the user on the command line
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
