// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/policyctl/internal/cmd"
)

func main() {
	cmdline := cmd.New()
	if err := cmdline.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Exec error: %v\n", err)
		os.Exit(1)
	}
}
