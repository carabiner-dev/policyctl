// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tester

import (
	"strings"
	"testing"
)

const (
	floor     = "v1.3.7"
	bareFloor = "1.3.7"
)

func validTestCase() TestCase {
	return TestCase{
		Name:         "case",
		Policy:       "policy.json",
		Expect:       "pass",
		Attestations: []string{"att.json"},
	}
}

func TestValidateAmpelVersion(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		version string
		want    string
		wantErr string
	}{
		{name: "empty means any version", version: "", want: ""},
		{name: "keeps v prefix", version: floor, want: floor},
		{name: "adds missing v prefix", version: bareFloor, want: floor},
		{name: "accepts prerelease", version: "v1.4.0-rc.1", want: "v1.4.0-rc.1"},
		{name: "rejects garbage", version: "latest", wantErr: `ampel-version must be a semantic version, got "latest"`},
		{name: "rejects partial version", version: "v1.3.x", wantErr: `ampel-version must be a semantic version, got "v1.3.x"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := validTestCase()
			tc.AmpelVersion = tt.version
			suite := &TestSuite{Tests: []TestCase{tc}}

			err := suite.Validate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := suite.Tests[0].AmpelVersion; got != tt.want {
				t.Fatalf("expected normalized version %q, got %q", tt.want, got)
			}
		})
	}
}

func TestRunsOn(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		floor  string
		engine string
		want   bool
	}{
		{name: "no floor runs anywhere", floor: "", engine: "v1.0.0", want: true},
		{name: "no floor and unknown engine", floor: "", engine: "", want: true},
		{name: "older engine is skipped", floor: floor, engine: "v1.3.6", want: false},
		{name: "equal engine runs", floor: floor, engine: floor, want: true},
		{name: "newer engine runs", floor: floor, engine: "v1.4.0", want: true},
		{name: "engine without v prefix", floor: floor, engine: bareFloor, want: true},
		{name: "floor without v prefix", floor: bareFloor, engine: "v1.3.6", want: false},
		{name: "pseudo-version before floor is skipped", floor: floor, engine: "v1.3.2-0.20260711022321-f6654bd33361", want: false},
		{name: "pseudo-version ahead of floor runs", floor: floor, engine: "v1.3.8-0.20260905000000-abcdef123456", want: true},
		{name: "pseudo-version just before floor tag is skipped", floor: floor, engine: "v1.3.7-0.20260831000000-abcdef123456", want: false},
		{name: "unknown engine runs", floor: floor, engine: "", want: true},
		{name: "devel engine runs", floor: floor, engine: "(devel)", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := &TestCase{AmpelVersion: tt.floor}
			if got := tc.RunsOn(tt.engine); got != tt.want {
				t.Fatalf("RunsOn(%q) with floor %q = %v, want %v", tt.engine, tt.floor, got, tt.want)
			}
		})
	}
}
