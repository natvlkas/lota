// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR14 boot-commitment derivation and TOFU tests

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// referenceBootCommitmentPCR14 reproduces the PCR14 derivation by hand
// so any drift between the helper and the wire spec gets caught.
func referenceBootCommitmentPCR14(agentHash [types.HashSize]byte, reset, restart uint32) [types.HashSize]byte {
	const tag = "LOTA-PCR14-BOOT-COMMITMENT-v1"
	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], reset)
	binary.BigEndian.PutUint32(counters[4:8], restart)

	commit := sha256.New()
	commit.Write([]byte(tag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	d := commit.Sum(nil)

	var zero [types.HashSize]byte
	final := sha256.New()
	final.Write(zero[:])
	final.Write(d)
	var out [types.HashSize]byte
	copy(out[:], final.Sum(nil))
	return out
}

func TestDeriveBootCommitmentPCR14_StableForSameInputs(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = byte(i)
	}

	a := DeriveBootCommitmentPCR14(agentHash, 5, 1)
	b := DeriveBootCommitmentPCR14(agentHash, 5, 1)
	if a != b {
		t.Fatal("derivation must be deterministic")
	}

	want := referenceBootCommitmentPCR14(agentHash, 5, 1)
	if a != want {
		t.Fatalf("derivation diverged from reference: got %x want %x", a, want)
	}
}

func TestDeriveBootCommitmentPCR14_ResetCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x42
	}

	old := DeriveBootCommitmentPCR14(agentHash, 7, 0)
	rebooted := DeriveBootCommitmentPCR14(agentHash, 8, 0)
	if old == rebooted {
		t.Fatal("PCR14 must change when resetCount advances")
	}
}

func TestDeriveBootCommitmentPCR14_RestartCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0xAB
	}

	a := DeriveBootCommitmentPCR14(agentHash, 7, 0)
	b := DeriveBootCommitmentPCR14(agentHash, 7, 1)
	if a == b {
		t.Fatal("PCR14 must change when restartCount advances")
	}
}

func TestAgentHashStore_MemoryFirstUseAndMatch(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x11
	}
	for i := range agentHash {
		agentHash[i] = 0x22
	}

	res, b := bs.CheckAndUpdateAgentHash("client-1", pcr14, agentHash)
	if res != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse, got %v", res)
	}
	if b.AgentHash != agentHash {
		t.Fatalf("snapshot must hold pinned agent_hash, got %x", b.AgentHash)
	}

	res, _ = bs.CheckAndUpdateAgentHash("client-1", pcr14, agentHash)
	if res != TOFUMatch {
		t.Fatalf("expected TOFUMatch, got %v", res)
	}

	var tampered [types.HashSize]byte
	tampered[0] = 0xFF
	res, snap := bs.CheckAndUpdateAgentHash("client-1", pcr14, tampered)
	if res != TOFUMismatch {
		t.Fatalf("expected TOFUMismatch on agent_hash drift, got %v", res)
	}
	if snap.AgentHash != agentHash {
		t.Fatalf("mismatch snapshot must expose stored value, got %x", snap.AgentHash)
	}
}

func TestAgentHashStore_MemoryBackfillsLegacyRow(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x33
	}
	for i := range agentHash {
		agentHash[i] = 0x44
	}

	// simulate a legacy row created by CheckAndUpdate() with no AgentHash
	bs.CheckAndUpdate("legacy", pcr14)

	res, snap := bs.CheckAndUpdateAgentHash("legacy", pcr14, agentHash)
	if res != TOFUMatch {
		t.Fatalf("legacy row must accept first agent_hash as TOFUMatch, got %v", res)
	}
	if snap.AgentHash != agentHash {
		t.Fatalf("backfilled agent_hash mismatch: got %x", snap.AgentHash)
	}
}
