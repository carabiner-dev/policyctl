// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tester

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	ampelctx "github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/verifier"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/policy"
	gointoto "github.com/in-toto/attestation/go/v1"
)

// Runner executes test cases. All relative paths are resolved against baseDir.
type Runner struct {
	baseDir string
}

// NewRunner creates a runner with the given base directory.
func NewRunner(baseDir string) *Runner {
	return &Runner{baseDir: baseDir}
}

// RunSuite runs all tests in a suite and returns a SuiteResult.
func (r *Runner) RunSuite(ctx context.Context, suite *TestSuite) *SuiteResult {
	start := time.Now()
	sr := &SuiteResult{}

	for i := range suite.Tests {
		result := r.RunTest(ctx, &suite.Tests[i])
		sr.Results = append(sr.Results, *result)
		if result.Error != nil {
			sr.Errors++
		} else if result.Passed {
			sr.Passed++
		} else {
			sr.Failed++
		}
	}
	sr.Duration = time.Since(start)
	return sr
}

// RunTest executes a single test case and returns the result.
func (r *Runner) RunTest(ctx context.Context, tc *TestCase) *TestResult {
	start := time.Now()
	result := &TestResult{
		Name:     tc.Name,
		Expected: tc.Expect,
	}

	actual, err := r.executeTest(ctx, tc)
	result.Duration = time.Since(start)
	if err != nil {
		result.Actual = "ERROR"
		result.Error = err
		result.Passed = false
		return result
	}

	result.Actual = actual
	result.Passed = (actual == tc.Expect)
	return result
}

func (r *Runner) executeTest(ctx context.Context, tc *TestCase) (string, error) {
	// Resolve paths relative to baseDir
	policyPath := r.resolve(tc.Policy)
	attPaths := make([]string, len(tc.Attestations))
	for i, a := range tc.Attestations {
		attPaths[i] = r.resolve(a)
	}

	// Determine subject
	subject, err := r.resolveSubject(tc.Subject, attPaths)
	if err != nil {
		return "", fmt.Errorf("resolving subject: %w", err)
	}

	// Compile policy
	set, pcy, grp, err := policy.NewCompiler().CompileFile(policyPath)
	if err != nil {
		return "", fmt.Errorf("compiling policy: %w", err)
	}
	compiled := policy.PolicyOrSetOrGroup(set, pcy, grp)

	// Build context providers
	var ctxProviders []ampelctx.Provider
	if len(tc.Context) > 0 {
		m := ampelctx.MapAnyProvider{}
		for _, cv := range tc.Context {
			m[cv.Name] = cv.Value
		}
		ctxProviders = append(ctxProviders, &m)
	}
	for _, cf := range tc.ContextFiles {
		path := r.resolve(cf.Path)
		var p ampelctx.Provider
		var err error
		switch {
		case strings.HasSuffix(path, ".json"):
			p, err = ampelctx.NewProviderFromJSONFile(path)
		case strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".yml"):
			p, err = ampelctx.NewProviderFromYAMLFile(path)
		default:
			return "", fmt.Errorf("unsupported context file extension: %s", path)
		}
		if err != nil {
			return "", fmt.Errorf("loading context file %s: %w", path, err)
		}
		ctxProviders = append(ctxProviders, p)
	}

	// Build verification options
	opts := verifier.NewVerificationOptions()
	opts.AttestationFiles = attPaths
	opts.ContextProviders = ctxProviders

	// Create verifier and run
	amp, err := verifier.New()
	if err != nil {
		return "", fmt.Errorf("creating verifier: %w", err)
	}

	results, err := amp.Verify(ctx, &opts, compiled, subject)
	if err != nil {
		return "", fmt.Errorf("verification: %w", err)
	}

	return results.GetStatus(), nil
}

func (r *Runner) resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(r.baseDir, path)
}

// resolveSubject parses the subject string or extracts from the first attestation.
func (r *Runner) resolveSubject(subjectStr string, attPaths []string) (*gointoto.ResourceDescriptor, error) {
	if subjectStr != "" {
		return parseSubjectString(subjectStr)
	}

	if len(attPaths) == 0 {
		return nil, fmt.Errorf("no subject specified and no attestations to extract from")
	}

	envs, err := envelope.Parsers.ParseFiles(attPaths[:1])
	if err != nil {
		return nil, fmt.Errorf("parsing attestation for subject: %w", err)
	}

	if len(envs) == 0 {
		return nil, fmt.Errorf("no envelopes parsed from attestation")
	}

	subjects := envs[0].GetStatement().GetSubjects()
	if len(subjects) == 0 {
		return nil, fmt.Errorf("attestation has no subjects")
	}

	s := subjects[0]
	return &gointoto.ResourceDescriptor{
		Name:   s.GetName(),
		Uri:    s.GetUri(),
		Digest: s.GetDigest(),
	}, nil
}

// parseSubjectString parses "algo:hex" into a ResourceDescriptor.
func parseSubjectString(s string) (*gointoto.ResourceDescriptor, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("subject must be in algo:hex format, got %q", s)
	}
	return &gointoto.ResourceDescriptor{
		Digest: map[string]string{parts[0]: parts[1]},
	}, nil
}
