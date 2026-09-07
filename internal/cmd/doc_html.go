// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	goldhtml "github.com/yuin/goldmark/renderer/html"
)

// mermaidBlock matches a fenced mermaid block as goldmark renders it, so it
// can be turned into the <div class="mermaid"> element mermaid.js renders.
// Other code blocks are left untouched.
var mermaidBlock = regexp.MustCompile(`(?s)<pre><code class="language-mermaid">(.*?)</code></pre>`)

func goldmarkRender(buf *strings.Builder, md string) error {
	gm := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(goldhtml.WithUnsafe()),
	)

	var htmlBuf strings.Builder
	if err := gm.Convert([]byte(md), &htmlBuf); err != nil {
		return err
	}

	buf.WriteString(mermaidBlock.ReplaceAllString(htmlBuf.String(), `<div class="mermaid">$1</div>`))
	return nil
}
