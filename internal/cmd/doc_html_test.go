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
