// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/policy"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/policyctl/pkg/doc"
)

const defaultIndexTitle = "Policy index"

type docIndexOptions struct {
	outputFile string
	format     string // "markdown" or "html"
	title      string
}

func (o *docIndexOptions) Validate() error {
	switch o.format {
	case formatMarkdown, "md", formatHTML:
	case "":
		switch strings.ToLower(filepath.Ext(o.outputFile)) {
		case ".html", ".htm":
			o.format = formatHTML
		default:
			o.format = formatMarkdown
		}
	default:
		return fmt.Errorf("unknown format %q (use markdown or html)", o.format)
	}
	if o.title == "" {
		return errors.New("title cannot be empty")
	}
	return nil
}

func (o *docIndexOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&o.outputFile, "output", "o", "", "output file (default: stdout)",
	)
	cmd.Flags().StringVarP(
		&o.format, "format", "f", "", "output format: markdown, html (default: from the output extension, else markdown)",
	)
	cmd.Flags().StringVar(
		&o.title, "title", defaultIndexTitle, "document title, used when creating the index",
	)
}

func addDocIndex(parentCmd *cobra.Command) {
	opts := &docIndexOptions{}
	indexCmd := &cobra.Command{
		Short: "generate an index of policy materials",
		Use:   "index [flags] policy.json...",
		Long: `Generate an index of policies, policy sets and policy groups.

The index lists the given policy materials in a table per kind: policies with
their name and the predicate types they consume, sets and groups with their
composition and the predicate types consumed by everything they contain. Each
ID links to the material's own document, expected next to its source file
with the .md extension (as written by "doc -o").

Each table sits between marker comments. When the markdown output file
already exists, only the marked regions are replaced and everything else is
kept, so a title, an introduction and text within each section survive
regeneration. Sections without markers are appended. HTML output is always
rendered from scratch.
`,
		Example: fmt.Sprintf(`  %s doc index -o slsa/README.md slsa/*.hjson`, appname),
		Args:    cobra.MinimumNArgs(1),
		// Silence errors: the root command prints them
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			entries, err := indexEntries(args, opts.outputFile)
			if err != nil {
				return err
			}
			idx, err := doc.NewIndex(entries)
			if err != nil {
				return err
			}

			var output string
			switch opts.format {
			case formatHTML:
				output, err = renderHTML(idx.Render(opts.title), opts.title)
				if err != nil {
					return fmt.Errorf("rendering html: %w", err)
				}
			default:
				output, err = markdownIndex(idx, opts.outputFile, opts.title)
				if err != nil {
					return err
				}
			}

			if opts.outputFile == "" {
				fmt.Print(output)
				return nil
			}
			if err := os.WriteFile(opts.outputFile, []byte(output), 0o600); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
			return nil
		},
	}
	opts.AddFlags(indexCmd)
	parentCmd.AddCommand(indexCmd)
}

// indexEntries compiles each policy file and pairs it with the path of its
// document, relative to the index output location (or the working directory
// when writing to stdout).
func indexEntries(files []string, outputFile string) ([]doc.IndexEntry, error) {
	entries := make([]doc.IndexEntry, 0, len(files))
	for _, f := range files {
		set, pcy, grp, err := policy.NewCompiler().CompileFile(f)
		if err != nil {
			return nil, fmt.Errorf("compiling %s: %w", f, err)
		}
		link, err := docLink(f, outputFile)
		if err != nil {
			return nil, err
		}
		entries = append(entries, doc.IndexEntry{
			Element: policy.PolicyOrSetOrGroup(set, pcy, grp),
			Link:    link,
		})
	}
	return entries, nil
}

// docLink returns the path of the document of a policy file (its source path
// with the .md extension) relative to the directory of the index output file.
func docLink(policyFile, outputFile string) (string, error) {
	docPath := strings.TrimSuffix(policyFile, filepath.Ext(policyFile)) + ".md"
	if outputFile == "" {
		return filepath.ToSlash(docPath), nil
	}
	absDoc, err := filepath.Abs(docPath)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", docPath, err)
	}
	absOut, err := filepath.Abs(filepath.Dir(outputFile))
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", outputFile, err)
	}
	rel, err := filepath.Rel(absOut, absDoc)
	if err != nil {
		return "", fmt.Errorf("relating %s to %s: %w", docPath, outputFile, err)
	}
	return filepath.ToSlash(rel), nil
}

// markdownIndex renders the index as markdown: refreshing the marked regions
// of an existing output file, or as a new document titled title.
func markdownIndex(idx *doc.Index, outputFile, title string) (string, error) {
	if outputFile == "" {
		return idx.Render(title), nil
	}
	existing, err := os.ReadFile(outputFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return idx.Render(title), nil
	case err != nil:
		return "", fmt.Errorf("reading existing index: %w", err)
	}
	updated, err := idx.Inject(string(existing))
	if err != nil {
		return "", fmt.Errorf("updating %s: %w", outputFile, err)
	}
	return updated, nil
}
