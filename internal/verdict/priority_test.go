package verdict

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The tests in this file are PROPERTY tests over the weighting, not assertions about specific
// scores. The weights themselves are a product decision and are expected to be retuned; these
// pin the relationships that must survive any retuning, so a future weight change that breaks
// the product's character fails loudly instead of quietly reordering podiums.

// base is a deliberately unremarkable finding: no money, no remediation, one resource, medium.
func base() types.Finding {
	return types.Finding{
		ID:           "f-base",
		RuleID:       "r.base",
		Title:        "A finding",
		WhyItMatters: "It matters for a reason the rule states plainly",
		Severity:     types.SeverityMedium,
		Confidence:   1,
		AffectedResources: []types.ResourceRef{
			{Kind: "Deployment", Namespace: "ns", Name: "x"},
		},
	}
}

func score(f types.Finding, collapsed int) float64 {
	return Priority(f, Classify(f), collapsed)
}

// TestPriority_SeverityDominatesMoney is the product's character in one assertion: an audit that
// tells a client to chase savings while a critical hole is open has spent its credibility. Money
// orders findings within a severity band; it may not jump one.
func TestPriority_SeverityDominatesMoney(t *testing.T) {
	poorButCritical := base()
	poorButCritical.Severity = types.SeverityCritical

	richButLow := base()
	richButLow.Severity = types.SeverityLow
	richButLow.DollarImpactMonthly = 500000 // absurd on purpose

	if score(poorButCritical, 1) <= score(richButLow, 1) {
		t.Errorf("a $0 critical (%.1f) must outrank a $500k low (%.1f) — severity is not for sale",
			score(poorButCritical, 1), score(richButLow, 1))
	}
}

// TestPriority_MoneyOrdersWithinASeverityBand — the other half of the same rule.
func TestPriority_MoneyOrdersWithinASeverityBand(t *testing.T) {
	cheap, dear := base(), base()
	cheap.DollarImpactMonthly = 10
	dear.DollarImpactMonthly = 900

	if score(dear, 1) <= score(cheap, 1) {
		t.Errorf("within one severity, $900 (%.1f) must outrank $10 (%.1f)",
			score(dear, 1), score(cheap, 1))
	}
}

// TestPriority_MoneyIsMonotonicAndSaturating — more money never lowers a score, and the curve
// flattens so a single enormous figure cannot dominate the whole ranking.
func TestPriority_MoneyIsMonotonicAndSaturating(t *testing.T) {
	amounts := []float64{0, 1, 10, 100, 250, 1000, 10000, 1000000}
	var prev float64 = -1
	for _, a := range amounts {
		f := base()
		f.DollarImpactMonthly = a
		s := score(f, 1)
		if s < prev {
			t.Errorf("score fell from %.2f to %.2f as money rose to $%.0f — more waste must never rank lower",
				prev, s, a)
		}
		prev = s
	}
	// Saturation, stated correctly: EQUAL MULTIPLICATIVE steps must add diminishing amounts.
	// An earlier version of this test compared $10→$100 (×10) against $100→$100k (×1000) and
	// "failed" simply because the second step was a hundred times larger — the test was wrong,
	// not the curve.
	step := func(from, to float64) float64 {
		a, b := base(), base()
		a.DollarImpactMonthly, b.DollarImpactMonthly = from, to
		return score(b, 1) - score(a, 1)
	}
	firstDecade := step(10, 100)
	laterDecade := step(1000, 10000)
	if laterDecade >= firstDecade {
		t.Errorf("money is not saturating: ×10 from $10 added %.2f, the same ×10 from $1,000 added %.2f",
			firstDecade, laterDecade)
	}

	// And the money TERM must be bounded below one severity band (100 points), so no figure, however
	// large, can promote a finding out of its severity within its band. Both figures sit above the knee,
	// so both are in the money band: reaching that band is tier.go's decision, and it is the only place
	// money can move a finding across severities.
	richest, poorest := base(), base()
	richest.DollarImpactMonthly = 1e9
	poorest.DollarImpactMonthly = dollarKnee
	if delta := score(richest, 1) - score(poorest, 1); delta >= 100 {
		t.Errorf("$1bn added %.1f over $%.0f — enough to cross a severity band, so money is unbounded",
			delta, dollarKnee)
	}
}

// TestPriority_HedgeIsAbsolute — a finding whose own text admits it may not apply cannot lead,
// no matter how severe, expensive or widespread it is. The penalty must dominate every bonus,
// because "we are not sure this applies" and "do this first" cannot both be true.
func TestPriority_HedgeIsAbsolute(t *testing.T) {
	best := base()
	best.Severity = types.SeverityCritical
	best.DollarImpactMonthly = 100000
	best.EstimatedEffort = types.EffortLow
	best.RemediationYAML = "kind: LimitRange\n"

	hedged := best
	hedged.ID = "f-hedged"
	hedged.WhyItMatters = "This is a problem if its CNI enforces policy"

	if score(hedged, 50) >= score(best, 1) {
		t.Errorf("a hedged finding scored %.1f against %.1f for the same finding unhedged — the "+
			"hedge penalty must outweigh every bonus combined", score(hedged, 50), score(best, 1))
	}
	// And it must sit below even the most unremarkable unhedged finding.
	if score(hedged, 50) >= score(base(), 1) {
		t.Errorf("hedged best-case (%.1f) outranks an ordinary unhedged finding (%.1f)",
			score(hedged, 50), score(base(), 1))
	}
}

// TestPriority_ActionabilityBreaksTiesButDoesNotOutrankSeverity — being easy to apply is worth
// something, because "start here" has to mean something; it is not worth a severity band.
func TestPriority_ActionabilityBreaksTiesButDoesNotOutrankSeverity(t *testing.T) {
	easyMedium := base()
	easyMedium.EstimatedEffort = types.EffortLow
	easyMedium.RemediationYAML = "kind: ResourceQuota\n"

	hardHigh := base()
	hardHigh.Severity = types.SeverityHigh
	hardHigh.EstimatedEffort = types.EffortHigh

	if score(easyMedium, 1) >= score(hardHigh, 1) {
		t.Errorf("an easy medium (%.1f) outranked a hard high (%.1f) — actionability is a tiebreak, not a promotion",
			score(easyMedium, 1), score(hardHigh, 1))
	}

	// Against an identical peer, though, the actionable one wins.
	plainMedium := base()
	if score(easyMedium, 1) <= score(plainMedium, 1) {
		t.Errorf("actionability bought nothing: %.1f vs %.1f", score(easyMedium, 1), score(plainMedium, 1))
	}
}

// TestPriority_BreadthIsANudgeNotAMultiplier — a blanket observation repeated across sixty
// namespaces is evidence of something systemic, not sixty times as urgent.
func TestPriority_BreadthIsANudgeNotAMultiplier(t *testing.T) {
	narrow := base()
	wide := base()

	if score(wide, 60) <= score(narrow, 1) {
		t.Error("breadth bought nothing at all — it is weak evidence, but it is evidence")
	}
	// One severity band is 100 points; breadth must never cross that on its own.
	if delta := score(wide, 60) - score(narrow, 1); delta >= 100 {
		t.Errorf("breadth added %.1f — enough to jump a severity band, which makes it a multiplier", delta)
	}
}

// TestPriority_LowConfidenceCannotBeatCertainty — problem-certainty scales the whole score, so a
// rule that is unsure of itself does not lead over an equivalent finding it is sure about. This
// is the ONLY legitimate use of Confidence in this package; see safety.go for why.
func TestPriority_LowConfidenceCannotBeatCertainty(t *testing.T) {
	sure, unsure := base(), base()
	sure.Confidence = 1
	unsure.Confidence = 0.3

	if score(unsure, 1) >= score(sure, 1) {
		t.Errorf("an unsure finding (%.1f) matched or beat a certain one (%.1f)",
			score(unsure, 1), score(sure, 1))
	}
	// Confidence must scale, not annihilate: doubt should not push a critical below a medium.
	unsureCritical := unsure
	unsureCritical.Severity = types.SeverityCritical
	if score(unsureCritical, 1) <= score(sure, 1) {
		t.Errorf("doubt demoted a critical (%.1f) below a certain medium (%.1f) — Confidence scales, it does not veto",
			score(unsureCritical, 1), score(sure, 1))
	}
}

// TestPriority_InfoNeverLeads — an informational note is not a call to action, whatever else it
// carries.
func TestPriority_InfoNeverLeads(t *testing.T) {
	info := base()
	info.Severity = types.SeverityInfo
	info.DollarImpactMonthly = 5000
	info.EstimatedEffort = types.EffortLow
	info.RemediationYAML = "kind: LimitRange\n"

	low := base()
	low.Severity = types.SeverityLow

	if score(info, 1) >= score(low, 1) {
		t.Errorf("an info note (%.1f) outranked a low finding (%.1f)", score(info, 1), score(low, 1))
	}
}

// TestPriority_IsPure — the same finding must always score the same. A ranking that drifts
// between calls cannot be defended to anyone.
func TestPriority_IsPure(t *testing.T) {
	f := base()
	f.DollarImpactMonthly = 123.45
	first := score(f, 4)
	for i := 0; i < 100; i++ {
		if got := score(f, 4); got != first {
			t.Fatalf("call %d returned %v, first call returned %v", i, got, first)
		}
	}
}

// A FIX-FIRST ROW SAYS WHY IN THE FINDING'S OWN WORDS, ON ONE LINE. The podium's cards printed the ranking's prose
// ("true now · 8 resources across 8 namespaces · no mechanical remediation — needs a person · …"); the row under
// a title is the first sentence of why the finding matters, at most 120 characters, cut at a word.
func TestSummaryLine_IsTheFindingsOwnFirstSentenceOnOneLine(t *testing.T) {
	f := types.Finding{WhyItMatters: "A pod that runs as root can write to its node's filesystem.  Escapes start there."}
	if got := SummaryLine(f, 120); got != "A pod that runs as root can write to its node's filesystem" {
		t.Errorf("SummaryLine = %q, want the first sentence", got)
	}
	long := types.Finding{WhyItMatters: strings.Repeat("every replica of this workload sits on one node ", 6) + "."}
	got := SummaryLine(long, 120)
	if n := len([]rune(got)); n > 120 || !strings.HasSuffix(got, "…") || strings.HasSuffix(strings.TrimSuffix(got, "…"), " ") {
		t.Errorf("a long reason is %d runes, %q: want at most 120, cut at a word, with an ellipsis", n, got)
	}
	if got := SummaryLine(types.Finding{Description: "Falls back to the description."}, 120); got != "Falls back to the description." {
		t.Errorf("with no WhyItMatters, SummaryLine = %q", got)
	}
}
