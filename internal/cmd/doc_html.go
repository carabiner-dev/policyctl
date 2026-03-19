// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldhtml "github.com/yuin/goldmark/renderer/html"
)

func goldmarkRender(buf *strings.Builder, md string) error {
	gm := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(goldhtml.WithUnsafe()),
	)

	// Convert mermaid code blocks to <div class="mermaid"> for mermaid.js
	// goldmark renders them as <pre><code class="language-mermaid">...
	// We need to post-process.
	var htmlBuf strings.Builder
	if err := gm.Convert([]byte(md), &htmlBuf); err != nil {
		return err
	}

	// Replace <pre><code class="language-mermaid">...</code></pre> with <div class="mermaid">...</div>
	html := htmlBuf.String()
	html = strings.ReplaceAll(html, `<pre><code class="language-mermaid">`, `<div class="mermaid">`)
	html = strings.ReplaceAll(html, "</code></pre>", "</div>")

	buf.WriteString(html)
	return nil
}
