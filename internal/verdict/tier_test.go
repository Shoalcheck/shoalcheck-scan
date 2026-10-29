package verdict

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE FIRST ROW IS THE PRODUCT'S FIRST SENTENCE. On the 839-finding AKS production reading the list opened on
// "ClusterRole system:prometheus permits the nodes/proxy subresource" — how Prometheus scrapes a kubelet —
// while a Service with no ready address sat seventh and the Deployment behind it, 0 of 1 ready, sat
// twenty-first. These pin the bands that fix that, as relationships rather than scores, the same way the
// rest of this package's property tests do.

func groundTruth(sev types.Severity) types.Finding {
	f := base()
	f.ID, f.RuleID = "f-now", "k8s.reliability.service-no-ready-endpoints"
	f.Title = "No ready address is published for shop/orders-api-v3"
	f.Severity, f.Pillar = sev, types.PillarGroundTruth
	return f
}

func posture(sev types.Severity) types.Finding {
	f := base()
	f.ID, f.RuleID = "f-posture", "k8s.rbac.dangerous-grant"
	f.Title = "ClusterRole system:prometheus permits the nodes/proxy subresource"
	f.Severity = sev
	return f
}

func leader(t *testing.T, fs ...types.Finding) types.Finding {
	t.Helper()
	ranked := RankAll(fs, nil)
	if len(ranked) == 0 {
		t.Fatal("RankAll returned nothing")
	}
	return ranked[0].Finding
}

func TestTier_WhatIsWrongNowLeadsAHighThatIsOnlyPosture(t *testing.T) {
	now, high := groundTruth(types.SeverityMedium), posture(types.SeverityHigh)
	// A wide posture finding is the real shape: the dangerous-grant rule fired 110 times on that reading,
	// and breadth is exactly the nudge that put it first.
	var many []types.Finding
	for i := 0; i < 110; i++ {
		g := high
		g.ID = "f-posture-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		many = append(many, g)
	}
	if got := leader(t, append(many, now)...); got.ID != now.ID {
		t.Errorf("the list opened on %q (%s, %d of them) above %q (%s, Ground Truth): what is wrong right now "+
			"must lead what is only posture, whatever their severities", got.Title, got.Severity, len(many),
			now.Title, now.Severity)
	}
}

func TestTier_TheNextChangeLeadsMoneyAndMoneyLeadsPosture(t *testing.T) {
	next := base()
	next.ID, next.RuleID, next.Pillar = "f-next", "k8s.reliability.zone-loss-feasibility", types.PillarChangePreflight
	next.Severity = types.SeverityMedium

	money := base()
	money.ID, money.RuleID = "f-money", "k8s.cost.overprovisioned-resources"
	money.DollarImpactMonthly = 1310

	high := posture(types.SeverityHigh)

	ranked := RankAll([]types.Finding{high, money, next}, nil)
	got := []string{ranked[0].Finding.ID, ranked[1].Finding.ID, ranked[2].Finding.ID}
	want := []string{"f-next", "f-money", "f-posture"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v: next change, then money, then posture", got, want)
		}
	}
}

// SEVERITY IS STILL NOT FOR SALE AT THE TOP. A critical leads whatever band the rest are in — the bands
// reorder what severity confused, they never bury a critical hole under a present-tense medium.
func TestTier_ACriticalLeadsEveryBand(t *testing.T) {
	crit := posture(types.SeverityCritical)
	if got := leader(t, groundTruth(types.SeverityHigh), crit); got.ID != crit.ID {
		t.Errorf("a Ground Truth high led a critical: %q", got.Title)
	}
	if TierOf(crit) != TierCritical {
		t.Errorf("a critical finding is in band %q", TierOf(crit).Label())
	}
}

// Money below the knee is not a reason to lead: $18 for an idle load balancer is posture, ordered by
// severity like the rest of posture.
func TestTier_MoneyBelowTheKneeIsPosture(t *testing.T) {
	cheap := base()
	cheap.DollarImpactMonthly = 18
	if TierOf(cheap) != TierPosture {
		t.Errorf("$18/mo is in band %q; below the knee money does not lead", TierOf(cheap).Label())
	}
}

// A HEDGED FINDING NEVER LEADS, AND A BAND IS A PLACE TO LEAD FROM. Priority has always sunk a finding whose
// own text says it may not apply; a Ground Truth band above everything would hand it the first row anyway.
// It is the last band, below posture, under its own name.
func TestTier_AHedgedFindingIsConditionalWhateverItsPillar(t *testing.T) {
	f := groundTruth(types.SeverityHigh)
	f.WhyItMatters = "Add a default-deny if its CNI enforces policy"
	if !isHedged(f) {
		t.Skip("the hedge markers changed; pick a phrase isHedged recognises")
	}
	if TierOf(f) != TierConditional {
		t.Errorf("a hedged Ground Truth finding is in band %q", TierOf(f).Label())
	}
	if got := leader(t, f, posture(types.SeverityInfo)); got.ID == f.ID {
		t.Errorf("a hedged high led an info posture note")
	}
}

// THE GAP HOLDS FOR EVERY COMBINATION. The best a band can score — critical-free, maximal money, SafeNow, low
// effort, maximal breadth — must stay below the worst the band above it can score.
func TestTier_NoWithinBandTermCarriesAFindingAcrossABand(t *testing.T) {
	best := base()
	best.Severity = types.SeverityHigh
	best.DollarImpactMonthly = 1e9
	best.EstimatedEffort = types.EffortLow
	bestScore := Priority(best, SafeNow, 1000)

	worst := base()
	worst.Severity = types.SeverityInfo
	worst.Confidence = 0.01
	worstScore := Priority(worst, Manual, 1)

	if bestScore-tierWeight(TierOf(best)) >= 1000 {
		t.Errorf("a within-band score of %.1f reaches the next band", bestScore-tierWeight(TierOf(best)))
	}
	if worstScore-tierWeight(TierOf(worst)) < 0 {
		t.Errorf("an unhedged within-band score of %.1f falls below its band", worstScore-tierWeight(TierOf(worst)))
	}
}
