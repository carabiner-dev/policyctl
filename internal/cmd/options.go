// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

type fileOptions struct {
	policyFile string
}

// Validates the options in context with arguments
func (fo *fileOptions) Validate() error {
	errs := []error{}
	if fo.policyFile == "" {
		errs = append(errs, errors.New("no policy file specified"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (fo *fileOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&fo.policyFile, "policy", "p", "", "path to policy file",
	)
}
