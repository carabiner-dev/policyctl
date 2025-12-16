// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "policyctl"

var rootCmd = &cobra.Command{
	Short:             "A tool to manange ampel policies",
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

// New returns the cobra construct for the CLI tool
func New() *cobra.Command {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level",
		"info",
		fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)
	addCompile(rootCmd)
	addParse(rootCmd)
	addSign(rootCmd)
	addKeys(rootCmd)
	addUpdate(rootCmd)
	addVerify(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))
	return rootCmd
}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

// Execute builds the command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}
