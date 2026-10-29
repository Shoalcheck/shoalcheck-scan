package verdict

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// This file is EPIC 1's QA gate (T1.7): inputs chosen to break the layer rather than to
// demonstrate it. Every case here is a shape a real cluster can produce — the AKS dev cluster
// alone supplies 2061 findings of which not one carries a dollar figure, which is precisely the
// case a "$-ranked" layer is most likely to get wrong.
//
// Per the QA doctrine, honesty failures rank above crashes: a panic is visible, and a podium that
// quietly disagrees with its own totals is not.

// TestAdversarial_AllFindingsIdentical — 2000 copies of one finding. A collapse that mishandles
// this either shows 2000 cards or claims a rest count that does not add up.
func TestAdversarial_AllFindingsIdentical(t *testing.T) {
	findings := make([]types.Finding, 2000)
	for i := range findings {
		f := base()
		f.ID = fmt.Sprintf("f-%04d", i)
		f.DollarImpactMonthly = 1
		findings[i] = f
	}
	sel := Select(findings, 3)

	if len(sel.Top) != 1 {
		t.Errorf("Top = %d, want 1 — 2000 instances of one rule is one observation", len(sel.Top))
	}
	if sel.Top[0].CollapsedFrom != 2000 {
		t.Errorf("CollapsedFrom = %d, want 2000", sel.Top[0].CollapsedFrom)
	}
	if sel.RestCount != 0 {
		t.Errorf("RestCount = %d, want 0 — everything collapsed into the single leader", sel.RestCount)
	}
	if sel.TotalDollars != 2000 {
		t.Errorf("TotalDollars = %.2f, want 2000", sel.TotalDollars)
	}
	if shown := sel.Top[0].Finding.DollarImpactMonthly; shown+sel.RestDollars != sel.TotalDollars {
		t.Errorf("shown %.2f + rest %.2f != total %.2f", shown, sel.RestDollars, sel.TotalDollars)
	}
}

// TestAdversarial_EverythingSameSeverityAndNoMoney is the real AKS shape: thousands of findings,
// uniform severity, no cost model anywhere. The ranking must still be a total order rather than
// collapsing to arrival order.
func TestAdversarial_EverythingSameSeverityAndNoMoney(t *testing.T) {
	var findings []types.Finding
	for i := 0; i < 50; i++ {
		f := base()
		f.ID = fmt.Sprintf("f-%02d", i)
		f.RuleID = fmt.Sprintf("rule.%02d", i)
		f.Severity = types.SeverityMedium
		f.DollarImpactMonthly = 0
		findings = append(findings, f)
	}
	first := Select(findings, 3)
	if len(first.Top) != 3 {
		t.Fatalf("Top = %d, want 3", len(first.Top))
	}
	// Reversing the input must not change the podium: with nothing to separate them, only the
	// documented tie-break may decide, and it is input-order independent.
	reversed := make([]types.Finding, len(findings))
	for i := range findings {
		reversed[i] = findings[len(findings)-1-i]
	}
	second := Select(reversed, 3)
	for i := range first.Top {
		if first.Top[i].Finding.ID != second.Top[i].Finding.ID {
			t.Errorf("position %d: %q forwards, %q reversed — arrival order leaked into the ranking",
				i, first.Top[i].Finding.ID, second.Top[i].Finding.ID)
		}
	}
}

// TestAdversarial_NegativeAndAbsurdDollars — a rule with a broken cost model must not be able to
// invert the ranking or corrupt the reconciliation.
func TestAdversarial_NegativeAndAbsurdDollars(t *testing.T) {
	neg, huge := base(), base()
	neg.ID, neg.RuleID, neg.DollarImpactMonthly = "f-neg", "r.neg", -100
	huge.ID, huge.RuleID, huge.DollarImpactMonthly = "f-huge", "r.huge", 1e12

	sel := Select([]types.Finding{neg, huge}, 2)
	if want := -100 + 1e12; sel.TotalDollars != want {
		t.Errorf("TotalDollars = %v, want %v — the total must mirror the findings even when a rule is wrong",
			sel.TotalDollars, want)
	}
	var shown float64
	for _, r := range sel.Top {
		shown += r.Finding.DollarImpactMonthly
	}
	if shown+sel.RestDollars != sel.TotalDollars {
		t.Errorf("shown %v + rest %v != total %v", shown, sel.RestDollars, sel.TotalDollars)
	}
	// A negative figure must not out-rank a positive one on the money term.
	if score(neg, 1) > score(huge, 1) {
		t.Error("a negative dollar impact outranked a positive one")
	}
}

// TestAdversarial_MissingAndMalformedFields — findings straight out of a half-implemented rule.
// Nothing here may panic, and nothing may produce a rationale that asserts more than it knows.
func TestAdversarial_MissingAndMalformedFields(t *testing.T) {
	cases := []types.Finding{
		{},                // entirely empty
		{ID: "f-only-id"}, // no rule, no severity, no text
		{ID: "f", RuleID: "r", Severity: "bogus"}, // severity outside the enum
		{ID: "f", RuleID: "r", WhyItMatters: "."}, // a lone terminator
		{ID: "f", RuleID: "r", WhyItMatters: strings.Repeat("very long ", 5000)},
		{ID: "f", RuleID: "r", Title: "emoji 🚀 and ünïcode", WhyItMatters: "Ends without a terminator"},
		{ID: "f", RuleID: "r", AffectedResources: []types.ResourceRef{{Kind: "Node", Name: "n1"}}}, // cluster-scoped, no namespace
	}
	for i, f := range cases {
		sel := Select([]types.Finding{f}, 3)
		if len(sel.Top) != 1 {
			t.Fatalf("case %d: Top = %d, want 1", i, len(sel.Top))
		}
		r := sel.Top[0]
		// A cluster-scoped resource has no namespace, so the rationale must not claim namespaces.
		if strings.Contains(r.Rationale, "namespaces") && len(f.AffectedResources) < 2 {
			t.Errorf("case %d: rationale claims namespaces from %d resource(s): %q",
				i, len(f.AffectedResources), r.Rationale)
		}
		if strings.Contains(r.Rationale, "$") {
			t.Errorf("case %d: rationale formats currency: %q", i, r.Rationale)
		}
	}
}

// TestAdversarial_EveryFindingHedged — a cluster where every finding admits it may not apply. The
// podium must still exist (these are real observations) and must offer no safe starting point,
// rather than promoting a hedged item to fill the slot.
func TestAdversarial_EveryFindingHedged(t *testing.T) {
	var findings []types.Finding
	for i := 0; i < 5; i++ {
		f := netpol(fmt.Sprintf("ns-%d", i))
		f.RuleID = fmt.Sprintf("hedged.%d", i) // distinct rules, so no collapsing
		findings = append(findings, f)
	}
	sel := Select(findings, 3)
	if len(sel.Top) != 3 {
		t.Errorf("Top = %d, want 3 — hedged findings are still findings", len(sel.Top))
	}
	if sel.StartHere != nil {
		t.Errorf("StartHere = %q — a hedged finding may never be the safe starting point",
			sel.StartHere.Finding.ID)
	}
	for _, r := range sel.Top {
		if r.Safety == SafeNow {
			t.Errorf("%q is hedged yet classified safe-now", r.Finding.ID)
		}
	}
}

// TestAdversarial_NRequestedOutOfRange — callers asking for nonsense must get a coherent
// Selection, and the totals must survive it.
func TestAdversarial_NRequestedOutOfRange(t *testing.T) {
	findings := []types.Finding{idleHog(), criticalNoMoney(), limitRange()}
	total := 0.0
	for _, f := range findings {
		total += f.DollarImpactMonthly
	}
	for _, n := range []int{-5, 0, 1, 3, 99, 1 << 20} {
		sel := Select(findings, n)
		if len(sel.Top) > len(findings) {
			t.Errorf("n=%d: Top = %d, more leaders than findings", n, len(sel.Top))
		}
		if sel.TotalDollars != total {
			t.Errorf("n=%d: TotalDollars = %.2f, want %.2f", n, sel.TotalDollars, total)
		}
		var shown float64
		for _, r := range sel.Top {
			shown += r.Finding.DollarImpactMonthly
		}
		if shown+sel.RestDollars != sel.TotalDollars {
			t.Errorf("n=%d: shown %.2f + rest %.2f != total %.2f", n, shown, sel.RestDollars, sel.TotalDollars)
		}
		// n<=0 asks for no podium; it must not silently produce one.
		if n <= 0 && len(sel.Top) != 0 {
			t.Errorf("n=%d produced %d leaders", n, len(sel.Top))
		}
	}
}

// TestAdversarial_SelectDoesNotMutateItsInput — Select is called by both the report renderer and
// the pipeline's event emitter over the SAME slice. If it edited a finding in place, the report
// and the stream would start disagreeing, and the collapse (which sums dollars into a
// representative) is exactly the kind of code that does that by accident.
func TestAdversarial_SelectDoesNotMutateItsInput(t *testing.T) {
	findings := []types.Finding{idleHog(), idleHog(), criticalNoMoney()}
	findings[1].ID = "f-idlehog-2"

	before := make([]types.Finding, len(findings))
	copy(before, findings)

	_ = Select(findings, 3)
	_ = Select(findings, 1)

	for i := range findings {
		if findings[i].DollarImpactMonthly != before[i].DollarImpactMonthly {
			t.Errorf("finding %d: dollars changed from %.2f to %.2f — Select mutated its input",
				i, before[i].DollarImpactMonthly, findings[i].DollarImpactMonthly)
		}
		if len(findings[i].AffectedResources) != len(before[i].AffectedResources) {
			t.Errorf("finding %d: affected resources grew from %d to %d — the collapse leaked into the input",
				i, len(before[i].AffectedResources), len(findings[i].AffectedResources))
		}
	}
}

// TestAdversarial_RepeatedSelectIsStable — calling Select twice on the same slice must give the
// same answer. Combined with the no-mutation test above, this catches accumulation bugs where the
// second call sees dollars summed by the first.
func TestAdversarial_RepeatedSelectIsStable(t *testing.T) {
	findings := []types.Finding{idleHog(), idleHog(), criticalNoMoney(), limitRange()}
	findings[1].ID = "f-idlehog-2"

	first := Select(findings, 3)
	for i := 0; i < 10; i++ {
		again := Select(findings, 3)
		if again.TotalDollars != first.TotalDollars {
			t.Fatalf("call %d: TotalDollars drifted from %.2f to %.2f",
				i, first.TotalDollars, again.TotalDollars)
		}
		for j := range first.Top {
			if first.Top[j].Finding.DollarImpactMonthly != again.Top[j].Finding.DollarImpactMonthly {
				t.Fatalf("call %d position %d: leader dollars drifted from %.2f to %.2f",
					i, j, first.Top[j].Finding.DollarImpactMonthly, again.Top[j].Finding.DollarImpactMonthly)
			}
		}
	}
}
