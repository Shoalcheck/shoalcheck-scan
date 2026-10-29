package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// EVERY FINDING A RUN PRODUCES CARRIES WHAT IT DOES NOT ESTABLISH. A finding without one is a claim shipped
// without its limit, and the only way that happens is a new rule whose author did not think about it — which
// rules.TestEveryRuleCarriesABoundary catches at the registry, while this catches it at the reading.
func TestRun_EveryFindingCarriesItsClaimBoundaries(t *testing.T) {
	col := collect.NewWithClient(fakeClientsetWithWorkloads(t))
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "test", Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(ar.Findings) == 0 {
		t.Fatal("the run produced no finding, so this gate would pass vacuously")
	}
	without := map[string]bool{}
	for _, f := range ar.Findings {
		if len(f.ClaimBoundaries) == 0 {
			without[f.RuleID] = true
		}
	}
	if len(without) > 0 {
		var ids []string
		for id := range without {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("%d rule(s) produced a finding with no claim boundary: %s", len(ids), strings.Join(ids, ", "))
	}
	t.Logf("%d finding(s), every one carrying its limits", len(ar.Findings))
}

// THE MERGE IS A UNION, AND GETTING THAT BACKWARDS WOULD DROP THE MORE VALUABLE HALF. A conditional boundary
// is written by a rule about THIS run — what this particular reading could not establish — and it is on the
// finding before the family ones are merged in. An assignment rather than a union would silently discard it.
func TestAttachClaimBoundaries_KeepsWhatTheRuleAppended(t *testing.T) {
	const conditional = "three of these pods matched no endpoint entry in this reading"
	// A real rule id, so the family lookup returns something and the union has two sides to merge.
	const ruleID = "k8s.reliability.node-drain-budget"
	if len(boundaries.For(ruleID)) == 0 {
		t.Fatalf("%s carries no family boundary, so this test would not be testing a union", ruleID)
	}

	fs := []types.Finding{{RuleID: ruleID, ClaimBoundaries: []string{conditional}}}
	attachClaimBoundaries(fs)

	got := fs[0].ClaimBoundaries
	if len(got) <= 1 {
		t.Fatalf("the merge produced %d line(s); a union of a conditional and a family should have more", len(got))
	}
	var kept bool
	for _, l := range got {
		if l == conditional {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the rule's own conditional boundary was dropped by the merge:\n  %v", got)
	}
	for _, want := range boundaries.For(ruleID) {
		var found bool
		for _, l := range got {
			if l == want {
				found = true
			}
		}
		if !found {
			t.Errorf("a family boundary is missing after the merge: %q", want)
		}
	}
	// DETERMINISTIC AND DE-DUPLICATED, so two readings of one cluster produce the same bytes. This used to
	// assert sort.StringsAreSorted, which was one way to get that property and the way that threw away the
	// order somebody wrote — see TestClaimBoundaries_KeepTheirAuthoredOrder, which owns the ordering
	// contract now. Determinism here is asserted the way it is actually needed: the same input twice.
	again := []types.Finding{{RuleID: ruleID, ClaimBoundaries: []string{conditional}}}
	attachClaimBoundaries(again)
	if strings.Join(again[0].ClaimBoundaries, "\x00") != strings.Join(got, "\x00") {
		t.Errorf("two merges of one finding produced different bytes:\n%v\nand\n%v", got, again[0].ClaimBoundaries)
	}
	twice := []types.Finding{{RuleID: ruleID, ClaimBoundaries: []string{conditional, conditional}}}
	attachClaimBoundaries(twice)
	if len(twice[0].ClaimBoundaries) != len(got) {
		t.Errorf("a repeated conditional produced %d lines against %d", len(twice[0].ClaimBoundaries), len(got))
	}
}

// A CONDITIONAL BOUNDARY REACHES A FINDING THROUGH THE WHOLE RUN, and this is the assertion that it does.
//
// The unit tests in internal/rules prove the functions produce the right sentences. They cannot prove the
// sentences are attached to a finding, survive the pipeline's merge, and arrive on the document — and a
// conditional that stopped being emitted looks exactly like a reading where the condition did not hold. Those
// two are indistinguishable from the outside, which is why this asserts against the shipped fixture, where
// the condition is known to hold: the persona has no EndpointSlices, so every drain finding must carry the
// sentence that says so.
func TestGolden_ADrainFindingCarriesItsConditionalBoundary(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatalf("read the golden: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse the golden: %v", err)
	}

	var drain, withConditional int
	for _, f := range ar.Findings {
		if f.RuleID != "k8s.reliability.node-drain-budget" {
			continue
		}
		drain++
		var family, conditional int
		for _, l := range f.ClaimBoundaries {
			// The conditional ones are about THIS reading's endpoint slices; the family ones are true
			// everywhere and say nothing about what was read.
			if strings.Contains(l, "EndpointSlice") {
				conditional++
			} else {
				family++
			}
		}
		if family == 0 {
			t.Errorf("%s carries no family boundary", f.ID)
		}
		if conditional > 0 {
			withConditional++
		}
	}
	if drain == 0 {
		t.Fatal("the golden fires no drain finding, so this gate measures nothing")
	}
	if withConditional != drain {
		t.Errorf("%d of %d drain findings carry a conditional boundary; the persona reads no EndpointSlices, "+
			"so every one of them should say so", withConditional, drain)
	}
	t.Logf("%d drain finding(s), each carrying its family boundaries and what this reading could not establish", drain)
}
