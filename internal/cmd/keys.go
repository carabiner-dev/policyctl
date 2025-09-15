// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

type keyOptions struct {
	command.KeyOptions
}

func (ko *keyOptions) Validate() error {
	errs := []error{
		ko.KeyOptions.Validate(),
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ko *keyOptions) AddFlags(cmd *cobra.Command) {}

func addKeys(parentCmd *cobra.Command) {
	opts := keyOptions{}
	keysCmd := &cobra.Command{
		Short:             "tools to work with signing keys",
		Use:               "keys",
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for _, path := range args {
				if !slices.Contains(opts.PublicKeyPaths, path) {
					opts.PublicKeyPaths = append(opts.PublicKeyPaths, path)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true
			if len(opts.PublicKeyPaths) > 0 {
				return showKeyDetails(opts.KeyOptions)
			}
			cmd.Help()
			return nil
		},
	}
	opts.AddFlags(keysCmd)
	addKeysShow(keysCmd)
	parentCmd.AddCommand(keysCmd)
}

type keyShowOptions struct {
	command.KeyOptions
}

func (ko *keyShowOptions) Validate() error {
	errs := []error{
		ko.KeyOptions.Validate(),
	}

	if len(ko.PublicKeyPaths) == 0 {
		errs = append(errs, errors.New("at least one key needs to be specified"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ko *keyShowOptions) AddFlags(cmd *cobra.Command) {
	ko.KeyOptions.AddFlags(cmd)
}

func addKeysShow(parentCmd *cobra.Command) {
	opts := &keyShowOptions{}
	keysShowCmd := &cobra.Command{
		Short:             "show details about public keys",
		Use:               "show",
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for _, path := range args {
				if !slices.Contains(opts.PublicKeyPaths, path) {
					opts.PublicKeyPaths = append(opts.PublicKeyPaths, path)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			return showKeyDetails(opts.KeyOptions)
		},
	}
	opts.AddFlags(keysShowCmd)
	parentCmd.AddCommand(keysShowCmd)
}

func showKeyDetails(opts command.KeyOptions) error {
	keys, err := opts.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	for _, k := range keys {
		pub, err := k.PublicKey()
		fmt.Println()
		fmt.Println("🔑 Key Details")
		fmt.Println("==============")
		if err != nil {
			fmt.Printf("Error reading key: %s\n", err.Error())
			continue
		}
		fmt.Println("ID:         " + pub.ID())
		fmt.Println("Scheme:     " + pub.Scheme)
		fmt.Println("Type:       " + pub.Type)
		fmt.Println("Key data:")
		fmt.Println(strings.TrimSpace(pub.Data) + "\n")
	}
	return nil
}
