// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDocDiagramFlags(t *testing.T) {
	t.Parallel()
	root := &cobra.Command{Use: "root"}
	addDoc(root)

	var docCmd *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "doc" {
			docCmd = c
		}
	}
	if docCmd == nil {
		t.Fatal("doc command not registered")
	}

	for name, want := range map[string]string{
		"diagram":        "true",
		"policy-details": "false",
	} {
		f := docCmd.PersistentFlags().Lookup(name)
		if f == nil {
			t.Errorf("flag --%s not registered", name)
			continue
		}
		if f.DefValue != want {
			t.Errorf("flag --%s defaults to %q, want %q", name, f.DefValue, want)
		}
	}
}
