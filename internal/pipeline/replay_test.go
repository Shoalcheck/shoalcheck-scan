package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// replay_test.go — the claim's cross-process half, as far as one test process can carry it.
//
// The in-process guard in determinism_test.go evaluates one inventory twice and compares. That is worth
// having and it is not the claim: a customer replaying a capture would go through a FILE, and the file is
// where the two struct-keyed maps and the reading clock could quietly be lost. This test puts the inventory
// through the file and compares the findings on the other side.
//
// It still runs in one process, so it does not prove anything about a different build of the engine. What it
// proves is the property the file has to have: nothing a rule reads is dropped, reordered or re-dated by the
// round-trip.

func TestReplay_ACapturedInventoryYieldsTheSameFindings(t *testing.T) {
	inv := determinismInventory(t)
	ropts := rules.Options{}

	before := idsOf(evaluateOnce(inv, ropts))
	if len(before) < 5 {
		t.Fatalf("only %d finding(s) before the round-trip; there is not enough here to compare", len(before))
	}

	path := filepath.Join(t.TempDir(), "capture.json")
	if err := collect.SaveCapture(path, inv); err != nil {
		t.Fatalf("save: %v", err)
	}
	replayed, err := collect.LoadCapture(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// The reading clock first, because every clock-anchored finding depends on it and a mismatch here would
	// show up below as an unexplained difference in a title rather than as the cause.
	if !replayed.Meta.StartedAt.Equal(inv.Meta.StartedAt) {
		t.Fatalf("the replayed reading clock is %s, want %s", replayed.Meta.StartedAt, inv.Meta.StartedAt)
	}

	after := idsOf(evaluateOnce(replayed, ropts))
	if len(after) != len(before) {
		t.Fatalf("%d finding(s) after the round-trip against %d before", len(after), len(before))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Errorf("finding %d differs after the round-trip: %s vs %s", i, after[i], before[i])
		}
	}

	// The analyzers are the half that reads the struct-keyed StackObjects map, so assert at least one of their
	// findings survived — otherwise a capture that dropped that field entirely would pass this test.
	stack := 0
	for _, f := range evaluateOnce(replayed, ropts) {
		if len(f.RuleID) > 6 && f.RuleID[:6] == "stack." {
			stack++
		}
	}
	if stack == 0 {
		t.Error("no analyzer finding survived the round-trip; StackObjects may not have travelled at all")
	}
	t.Logf("%d findings identical through a capture file, %d of them from stack analyzers", len(after), stack)
}
