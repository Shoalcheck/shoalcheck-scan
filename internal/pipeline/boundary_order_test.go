package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE ORDER A READER SEES IS THE ORDER SOMEBODY WROTE, NOT THE ORDER OF THE ALPHABET.
//
// The merge sorted the lines with sort.Strings, for determinism — two readings of one cluster have to
// produce the same bytes, which is the property internal/collect/capture.go exists to protect. It bought
// that property at a price nobody chose: the first sentence a reader sees was whichever one started with
// the earliest letter.
//
// Measured on a real finding, stack.hpa.no-headroom, in `shoalcheck explain`:
//
//	A range with no room in it is not by itself a mistake…      ← the alphabet put this first
//	No load was measured…
//	This is arithmetic on the numbers the object states…        ← the author put THIS first
//	Whether this object is where a change belongs…
//
// The sentence that says what KIND of claim this is came third. An author writing four sentences in careful
// order had that order silently discarded, and nothing said so.
//
// DECLARATION ORDER IS EQUALLY DETERMINISTIC. Families are a slice, their lines are a slice, and Go iterates
// both in order. So the sort was never the only way to get reproducible bytes — it was one way, and the one
// that threw the authored order away.
//
// AND A CONDITIONAL BOUNDARY COMES FIRST, because it is the more valuable half. A family line is true on
// every cluster; a conditional line is what THIS reading could not establish — "three of these pods matched
// no endpoint entry" — and it is the one the reader has not already seen on nine other findings.
func TestClaimBoundaries_KeepTheirAuthoredOrder(t *testing.T) {
	const conditional = "In this reading three of these pods matched no endpoint entry."

	// A rule whose family declares more than two lines, so order is observable.
	var ruleID string
	var want []string
	for _, f := range boundaries.Families {
		if len(f.Lines) >= 3 && len(f.Rules) > 0 {
			ruleID, want = f.Rules[0], f.Lines
			break
		}
	}
	if ruleID == "" {
		t.Fatal("no family declares three lines, so this test cannot observe an order")
	}

	fs := []types.Finding{{
		ID: "f-1", RuleID: ruleID,
		// Already on the finding when the merge runs, exactly as a rule appends it at Evaluate time.
		ClaimBoundaries: []string{conditional},
	}}
	attachClaimBoundaries(fs)
	got := fs[0].ClaimBoundaries

	if len(got) == 0 {
		t.Fatalf("%s carries no boundaries at all", ruleID)
	}
	if got[0] != conditional {
		t.Errorf("the first line is %q; the conditional boundary the rule appended for THIS run should lead,\n"+
			"because it is the one the reader has not seen on every other finding of this family", got[0])
	}
	if len(got) != len(want)+1 {
		t.Fatalf("merged to %d lines, want %d (one conditional plus the family's %d)", len(got), len(want)+1, len(want))
	}
	for i, line := range want {
		if got[i+1] != line {
			t.Errorf("family line %d of %s is %q in the output and %q in the declaration:\n"+
				"the order an author wrote is the order a reader gets, and the alphabet is not that order",
				i+1, ruleID, got[i+1], line)
		}
	}

	// DETERMINISM, which is what the sort was for. Twice over the same input, byte for byte.
	twice := []types.Finding{{ID: "f-1", RuleID: ruleID, ClaimBoundaries: []string{conditional}}}
	attachClaimBoundaries(twice)
	if strings.Join(twice[0].ClaimBoundaries, "\x00") != strings.Join(got, "\x00") {
		t.Errorf("two merges of one finding produced different orders:\n%v\nand\n%v", got, twice[0].ClaimBoundaries)
	}

	// AND STILL DE-DUPLICATED: a rule in two families, or a conditional line a family also declares, appears
	// once. This is the half the sort was NOT doing and that has to survive its removal.
	dup := []types.Finding{{ID: "f-1", RuleID: ruleID, ClaimBoundaries: []string{want[1], want[1]}}}
	attachClaimBoundaries(dup)
	seen := map[string]int{}
	for _, l := range dup[0].ClaimBoundaries {
		seen[l]++
	}
	for l, n := range seen {
		if n > 1 {
			t.Errorf("%q appears %d times: the same sentence twice reads as two separate limits", l, n)
		}
	}
}

// boundaries.For KEEPS DECLARATION ORDER TOO, because the merge cannot restore an order its input has
// already lost. shoalcheck-mcp reads it directly for readings that predate the field, so this is not only the
// pipeline's concern.
func TestBoundariesFor_KeepsDeclarationOrder(t *testing.T) {
	for _, f := range boundaries.Families {
		if len(f.Lines) < 3 || len(f.Rules) == 0 {
			continue
		}
		got := boundaries.For(f.Rules[0])
		// A rule may belong to more than one family, so the family's lines must be a PREFIX or a contiguous
		// run rather than the whole answer — what matters is that they are in their declared order.
		idx := make([]int, 0, len(f.Lines))
		for _, want := range f.Lines {
			at := -1
			for i, g := range got {
				if g == want {
					at = i
					break
				}
			}
			if at < 0 {
				t.Fatalf("For(%q) does not carry its own family's line %q", f.Rules[0], want)
			}
			idx = append(idx, at)
		}
		for i := 1; i < len(idx); i++ {
			if idx[i] < idx[i-1] {
				t.Errorf("For(%q) returns family %q's lines out of their declared order (positions %v)",
					f.Rules[0], f.Name, idx)
				break
			}
		}
		return
	}
	t.Fatal("no family declares three lines, so this test cannot observe an order")
}
