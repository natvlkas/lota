// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestComputeExpectedRuntimeMeasure_RealBinary measures the running test
// binary (a real ELF) and confirms the verifier-side parser succeeds and
// is deterministic on a genuine executable.
func TestComputeExpectedRuntimeMeasure_RealBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	a, err := computeExpectedRuntimeMeasure(self)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	b, err := computeExpectedRuntimeMeasure(self)
	if err != nil {
		t.Fatalf("measure (second): %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %x != %x", a, b)
	}
	var zero [32]byte
	if a == zero {
		t.Fatalf("measurement is all-zero")
	}
}

// TestComputeExpectedRuntimeMeasure_RejectsNonELF confirms the parser
// fails closed on a file that is not an ELF object.
func TestComputeExpectedRuntimeMeasure_RejectsNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-elf.bin")
	if err := os.WriteFile(path, []byte("definitely not an ELF\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := computeExpectedRuntimeMeasure(path); err == nil {
		t.Fatalf("expected error on non-ELF input")
	}
}

// TestComputeExpectedRuntimeMeasure_RejectsMissing confirms a missing
// path returns an error rather than a silent zero measurement.
func TestComputeExpectedRuntimeMeasure_RejectsMissing(t *testing.T) {
	if _, err := computeExpectedRuntimeMeasure(
		filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatalf("expected error on missing path")
	}
}
