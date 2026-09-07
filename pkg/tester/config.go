// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tester

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

// TestSuite holds all test cases loaded from a config file.
type TestSuite struct {
	Tests []TestCase `yaml:"tests"`
}

// TestCase defines a single policy test.
type TestCase struct {
	Name         string   `yaml:"name"`
	Policy       string   `yaml:"policy"`
	Expect       string   `yaml:"expect"` // "PASS" or "FAIL"
	Subject      string   `yaml:"subject"`
	Attestations []string `yaml:"attestations"`
	// Collectors lists attestation collector init strings (e.g.
	// "fs:testdata/bundle"). Filesystem-backed collectors ("fs:") resolve
	// their path relative to the test file's directory. Collectors are an
	// alternative evidence source to Attestations and are required to test
	// policies whose evidence must be synthesized (e.g. signature
	// attestations built from bundles or detached signatures).
	Collectors []string `yaml:"collectors"`
	// Signers lists the accepted signer identities (identity slugs, e.g.
	// "sigstore::<issuer>::<identity>") passed to the verifier, equivalent to
	// the --signer flag. Required to exercise policies that gate on the signer.
	Signers      []string       `yaml:"signers"`
	Context      []ContextValue `yaml:"context"`
	ContextFiles []ContextFile  `yaml:"context-files"`
	// AmpelVersion is the minimum ampel version (semver, e.g. "v1.3.7") the
	// test needs. Harnesses that run tests against several ampel versions
	// skip the test on engines older than this (see RunsOn). Empty means the
	// test runs on any version.
	AmpelVersion string `yaml:"ampel-version"`
}

// ContextValue is an inline context key-value pair.
type ContextValue struct {
	Name  string `yaml:"name"`
	Value any    `yaml:"value"`
}

// ContextFile references an external JSON or YAML file for context.
type ContextFile struct {
	Path string `yaml:"path"`
}

// LoadConfig reads, parses, and validates a test config file.
func LoadConfig(configPath string) (*TestSuite, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var suite TestSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := suite.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &suite, nil
}

// Validate checks that the suite has valid test cases.
func (s *TestSuite) Validate() error {
	if len(s.Tests) == 0 {
		return errors.New("no tests defined")
	}

	var errs []error
	for i := range s.Tests {
		tc := &s.Tests[i]
		if tc.Name == "" {
			errs = append(errs, fmt.Errorf("test %d: name is required", i))
		}
		if tc.Policy == "" {
			errs = append(errs, fmt.Errorf("test %q: policy is required", tc.Name))
		}

		expect := strings.ToUpper(tc.Expect)
		if expect != "PASS" && expect != "FAIL" {
			errs = append(errs, fmt.Errorf("test %q: expect must be PASS or FAIL, got %q", tc.Name, tc.Expect))
		}
		tc.Expect = expect

		if len(tc.Attestations) == 0 && len(tc.Collectors) == 0 {
			errs = append(errs, fmt.Errorf("test %q: at least one attestation or collector is required", tc.Name))
		}

		if tc.AmpelVersion != "" {
			v := canonicalVersion(tc.AmpelVersion)
			if !semver.IsValid(v) {
				errs = append(errs, fmt.Errorf("test %q: ampel-version must be a semantic version, got %q", tc.Name, tc.AmpelVersion))
			}
			tc.AmpelVersion = v
		}
	}

	return errors.Join(errs...)
}

// RunsOn reports whether the test case can run on the given ampel version.
//
// A test without an AmpelVersion floor runs on any engine. When the engine
// version is unknown or not a semantic version (e.g. a development build
// reporting "(devel)"), the test is assumed to run: a development tree is
// expected to carry every feature the tests target. Module pseudo-versions
// compare as semver, so a build of a commit between two tags sorts between
// them and one ahead of the latest tag sorts below the next tag, which skips
// rather than fails tests floored at that next release.
func (tc *TestCase) RunsOn(ampelVersion string) bool {
	if tc.AmpelVersion == "" {
		return true
	}
	v := canonicalVersion(ampelVersion)
	if !semver.IsValid(v) {
		return true
	}
	return semver.Compare(v, canonicalVersion(tc.AmpelVersion)) >= 0
}

// canonicalVersion adds the leading "v" that golang.org/x/mod/semver requires
// when it is missing, so users can write either "1.3.7" or "v1.3.7".
func canonicalVersion(v string) string {
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
