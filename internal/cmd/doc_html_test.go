// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"
)

func TestRenderHTMLTitle(t *testing.T) {
	t.Parallel()
	out, err := renderHTML("# Heading\n\nbody\n", `Fish & "Chips" <policy>`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		`<title>Fish &amp; &#34;Chips&#34; &lt;policy&gt;</title>`,
		"<h1>Heading</h1>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in:\n%s", want, out)
		}
	}
}

func TestRenderHTMLConvertsOnlyMermaidBlocks(t *testing.T) {
	t.Parallel()
	md := "# Doc\n\n```mermaid\nflowchart TD\n    A --> B\n```\n\n```cel\nsize(x) > 0\n```\n\n```mermaid\nflowchart LR\n    C --> D\n```\n"
	out, err := renderHTML(md, "Doc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := strings.Count(out, `<div class="mermaid">`); got != 2 {
		t.Errorf("expected 2 mermaid divs, got %d in:\n%s", got, out)
	}
	if got := strings.Count(out, "</div>"); got != 2 {
		t.Errorf("expected 2 closing divs, got %d in:\n%s", got, out)
	}
	for _, want := range []string{
		`<pre><code class="language-cel">size(x) &gt; 0`,
		"</code></pre>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the cel block intact with %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "language-mermaid") {
		t.Errorf("expected no mermaid code blocks left in:\n%s", out)
	}
}
