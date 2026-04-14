// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
)

func addCheckUpdate(parentCmd *cobra.Command) {
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

			if len(updates) == 0 {
				fmt.Fprintln(os.Stderr, "no policy references have updates available")
				return nil
			}

			printUpdatesTable(os.Stdout, updates)
			return nil
		},
	}
	parentCmd.AddCommand(cmd)
}

func printUpdatesTable(out *os.File, updates map[string][]*policy.RefUpdate) {
	files := make([]string, 0, len(updates))
	for f := range updates {
		files = append(files, f)
	}
	sort.Strings(files)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tREFERENCE\tOLD URI\tNEW URI\tOLD DIGEST\tNEW DIGEST")
	for _, f := range files {
		for _, u := range updates[f] {
			name := u.Old.GetId()
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				f, name,
				u.Old.GetLocation().GetUri(),
				u.New.GetLocation().GetUri(),
				short(u.Old.GetLocation().GetDigest()["sha256"]),
				short(u.New.GetLocation().GetDigest()["sha256"]),
			)
		}
	}
	_ = tw.Flush()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
