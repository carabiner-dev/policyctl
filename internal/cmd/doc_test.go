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
		f := docCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("flag --%s not registered", name)
			continue
		}
		if f.DefValue != want {
			t.Errorf("flag --%s defaults to %q, want %q", name, f.DefValue, want)
		}
	}
}

func TestDocIndexFlags(t *testing.T) {
	t.Parallel()
	root := &cobra.Command{Use: "root"}
	addDoc(root)

	var indexCmd *cobra.Command
	for _, c := range root.Commands() {
		for _, sub := range c.Commands() {
			if c.Name() == "doc" && sub.Name() == "index" {
				indexCmd = sub
			}
		}
	}
	if indexCmd == nil {
		t.Fatal("doc index command not registered")
	}

	for name, want := range map[string]string{
		"output": "",
		"format": "",
		"title":  defaultIndexTitle,
	} {
		f := indexCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("flag --%s not registered", name)
			continue
		}
		if f.DefValue != want {
			t.Errorf("flag --%s defaults to %q, want %q", name, f.DefValue, want)
		}
	}

	// The doc command's own flags must not leak into the subcommand.
	for _, name := range []string{"diagram", "policy-details", "policy"} {
		if indexCmd.InheritedFlags().Lookup(name) != nil {
			t.Errorf("flag --%s leaked from doc into doc index", name)
		}
	}
}

func TestDocLink(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		policyFile string
		outputFile string
		want       string
	}{
		{name: "stdout keeps the source path", policyFile: "slsa/build.hjson", outputFile: "", want: "slsa/build.md"},
		{name: "index next to the policy", policyFile: "slsa/build.hjson", outputFile: "slsa/README.md", want: "build.md"},
		{name: "index above the policy", policyFile: "slsa/build.json", outputFile: "README.md", want: "slsa/build.md"},
		{name: "index in a sibling directory", policyFile: "slsa/build.json", outputFile: "docs/index.md", want: "../slsa/build.md"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := docLink(tt.policyFile, tt.outputFile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("docLink(%q, %q) = %q, want %q", tt.policyFile, tt.outputFile, got, tt.want)
			}
		})
	}
}
