// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/policy"
	"github.com/charmbracelet/glamour"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/policyctl/pkg/doc"
)

const (
	formatTerminal = "terminal"
	formatMarkdown = "markdown"
	formatHTML     = "html"
)

type docOptions struct {
	fileOptions
	outputFile string
	format     string // "terminal", "markdown", "html"
}

func (do *docOptions) Validate() error {
	errs := []error{
		do.fileOptions.Validate(),
	}

	switch do.format {
	case formatTerminal, formatMarkdown, "md", formatHTML:
	case "":
		// Default: terminal if no output file, else infer from extension
		if do.outputFile != "" {
			switch strings.ToLower(filepath.Ext(do.outputFile)) {
			case ".html", ".htm":
				do.format = formatHTML
			default:
				do.format = formatMarkdown
			}
		} else {
			do.format = formatTerminal
		}
	default:
		errs = append(errs, fmt.Errorf("unknown format %q (use terminal, markdown, or html)", do.format))
	}

	return errors.Join(errs...)
}

func (do *docOptions) AddFlags(cmd *cobra.Command) {
	do.fileOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&do.outputFile, "output", "o", "", "output file (default: stdout)",
	)
	cmd.PersistentFlags().StringVarP(
		&do.format, "format", "f", "", "output format: terminal, markdown, html (default: auto-detect)",
	)
}

func addDoc(parentCmd *cobra.Command) {
	opts := &docOptions{}
	docCmd := &cobra.Command{
		Short: "generate documentation for a policy",
		Use:   "doc [flags] policy.json",
		Long: `Generate documentation for a policy, policy set, or policy group.

The doc subcommand reads a policy file (JSON or HJSON) and generates
human-readable documentation including a technical overview, context
values, identity requirements, and a mermaid structure diagram.

Output formats:
  terminal   Rendered markdown for the terminal (default)
  markdown   Raw markdown
  html       HTML document
`,
		Example:           fmt.Sprintf(`  %s doc slsa/slsa-build-point.hjson`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.policyFile == "" {
					opts.policyFile = args[0]
				}
				if args[0] != opts.policyFile {
					return fmt.Errorf("policy path specified twice (as argument and flag)")
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true

			// Compile the policy
			set, pcy, grp, err := policy.NewCompiler().CompileFile(opts.policyFile)
			if err != nil {
				return fmt.Errorf("compiling policy: %w", err)
			}
			element := policy.PolicyOrSetOrGroup(set, pcy, grp)

			// Generate the markdown document
			md, err := doc.Generate(element)
			if err != nil {
				return fmt.Errorf("generating documentation: %w", err)
			}

			// Render to the requested format
			var output string
			switch opts.format {
			case formatTerminal:
				renderer, err := glamour.NewTermRenderer(
					glamour.WithAutoStyle(),
					glamour.WithWordWrap(100),
				)
				if err != nil {
					return fmt.Errorf("creating terminal renderer: %w", err)
				}
				output, err = renderer.Render(md)
				if err != nil {
					return fmt.Errorf("rendering terminal output: %w", err)
				}
			case formatMarkdown, "md":
				output = md
			case formatHTML:
				output, err = renderHTML(md)
				if err != nil {
					return fmt.Errorf("rendering html: %w", err)
				}
			}

			if opts.outputFile != "" {
				if err := os.WriteFile(opts.outputFile, []byte(output), 0o600); err != nil {
					return fmt.Errorf("writing output: %w", err)
				}
			} else {
				fmt.Print(output)
			}

			return nil
		},
	}
	opts.AddFlags(docCmd)
	parentCmd.AddCommand(docCmd)
}

func renderHTML(md string) (string, error) {
	// Use glamour's HTML rendering
	body, err := glamour.RenderBytes([]byte(md), "ascii")
	if err != nil {
		return "", err
	}

	// For a proper HTML doc, we'd wrap it. But glamour doesn't render to HTML directly.
	// Use a simple markdown-to-html approach via goldmark which glamour depends on.
	return renderHTMLWithGoldmark(md, body)
}

func renderHTMLWithGoldmark(md string, _ []byte) (string, error) {
	// glamour uses goldmark internally; let's use it directly for HTML
	var buf strings.Builder

	// Simple HTML wrapper with mermaid.js support
	buf.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Policy Documentation</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.6; color: #24292f; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #d0d7de; padding: 6px 13px; text-align: left; }
  th { background: #f6f8fa; font-weight: 600; }
  code { background: #f6f8fa; padding: 0.2em 0.4em; border-radius: 6px; font-size: 85%; }
  pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }
  pre code { background: none; padding: 0; }
  h1, h2, h3, h4 { margin-top: 1.5em; border-bottom: 1px solid #d0d7de; padding-bottom: 0.3em; }
  .mermaid { text-align: center; margin: 1rem 0; }
</style>
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({ startOnLoad: true, theme: 'neutral' });
</script>
</head>
<body>
`)

	// Convert markdown to HTML using goldmark
	if err := goldmarkRender(&buf, md); err != nil {
		return "", err
	}

	buf.WriteString("\n</body>\n</html>\n")
	return buf.String(), nil
}
