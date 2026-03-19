// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/policyctl/pkg/tester"
)

type testOptions struct {
	configFile string
	verbose    bool
	dir        string
}

func (to *testOptions) Validate() error {
	if to.dir == "" {
		return errors.New("test directory is required")
	}
	return nil
}

func (to *testOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&to.configFile, "config", ".ptests.yaml", "test config file name",
	)
	cmd.PersistentFlags().BoolVarP(
		&to.verbose, "verbose", "v", false, "verbose output",
	)
}

func addTest(parentCmd *cobra.Command) {
	opts := &testOptions{}
	testCmd := &cobra.Command{
		Short:             "run policy tests from a config file",
		Use:               "test [flags] <directory>",
		Example:           fmt.Sprintf(`%s test slsa/`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.dir = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			configPath := filepath.Join(opts.dir, opts.configFile)
			suite, err := tester.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("loading test config: %w", err)
			}

			runner := tester.NewRunner(opts.dir)
			result := runner.RunSuite(context.Background(), suite)

			// Print results
			for _, tr := range result.Results {
				fmt.Printf("=== RUN   %s\n", tr.Name)
				dur := tr.Duration.Round(10 * time.Millisecond)
				switch {
				case tr.Error != nil:
					fmt.Printf("--- ERROR %s (%s)\n", tr.Name, dur)
					fmt.Printf("    %v\n", tr.Error)
				case tr.Passed:
					fmt.Printf("--- PASS  %s (%s)\n", tr.Name, dur)
				default:
					fmt.Printf("--- FAIL  %s (%s)\n", tr.Name, dur)
					fmt.Printf("    expected %s, got %s\n", tr.Expected, tr.Actual)
				}
			}

			fmt.Printf("\nRESULTS: %d passed, %d failed, %d errors\n",
				result.Passed, result.Failed, result.Errors)

			if result.Failed > 0 || result.Errors > 0 {
				fmt.Println("FAIL")
				os.Exit(1)
			}

			fmt.Println("ok")
			return nil
		},
	}
	opts.AddFlags(testCmd)
	parentCmd.AddCommand(testCmd)
}
