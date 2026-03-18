// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package tester

import "time"

// TestResult captures the outcome of a single test case.
type TestResult struct {
	Name     string
	Expected string // "PASS" or "FAIL"
	Actual   string // "PASS", "FAIL", "SOFTFAIL", "ERROR"
	Passed   bool
	Error    error
	Duration time.Duration
}

// SuiteResult captures the outcome of an entire test suite.
type SuiteResult struct {
	Results  []TestResult
	Passed   int
	Failed   int
	Errors   int
	Duration time.Duration
}
