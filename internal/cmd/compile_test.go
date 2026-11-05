// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	api "github.com/policylabs/policy/api/v1"
	"github.com/stretchr/testify/require"
)

// Compiled output must be byte-identical from one run to the next, which
// protojson's randomized spacing does not give, and indented with two
// spaces and a single space after the colon.
func TestMarshalStable(t *testing.T) {
	t.Parallel()
	p := &api.Policy{Id: "stable", Meta: &api.Meta{Name: "Stable", Description: "A policy"}}

	first, err := marshalStable(p)
	require.NoError(t, err)
	for range 20 {
		again, err := marshalStable(p)
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}

	require.True(t, json.Valid(first))
	require.Contains(t, string(first), "\n  \"id\": \"stable\"")
	require.NotContains(t, string(first), ":  ")
	require.Equal(t, "{", strings.SplitN(string(first), "\n", 2)[0])
}
