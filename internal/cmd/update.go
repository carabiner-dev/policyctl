// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"sort"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"
)

func addUpdate(parentCmd *cobra.Command) {
	updateCmd := &cobra.Command{
		Short: "update policy references to their latest versions",
		Use:   "update [flags] <location> [<location>...]",
		Long: `Resolve each location as a policy file or a directory of policies,
look up updates for every external reference, and patch the matching
policy source files in place.

Only filesystem locations are supported: remote (VCS locator) locations
will be skipped.

The patch rewrites old URIs, download locations, and digest values in
place so that the resulting diff against the original file is limited to
the strings that actually changed.`,
		Example:           fmt.Sprintf(`  %s update ./policies`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("at least one location is required")
			}
			cmd.SilenceUsage = true

			applied, err := policy.NewUpdater().Update(args...)
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
	parentCmd.AddCommand(updateCmd)
}
