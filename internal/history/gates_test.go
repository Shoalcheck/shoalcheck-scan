package history

import (
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// allKinds is what a run that read everything records. The rule in these fixtures is "k8s.test.rule",
// and testDeps says it rests on deployments.
var allKinds = []string{"deployments", "namespaces", "services"}

func testDeps() map[string]Deps {
	return map[string]Deps{"k8s.test.rule": {Kinds: []string{"deployments"}}}
}

// withBasis gives a report the machine-readable record of what it was a reading OF. Without it no
// comparison is allowed, which is the point of the first gate.
func withBasis(ar *types.AuditReport, uid string, collected, denied []string, usage string) *types.AuditReport {
	ar.Methodology.CollectedKinds = collected
	ar.Methodology.DeniedKinds = denied
	ar.Methodology.RunBasis = &types.RunBasis{
		ClusterUID:    uid,
		UsageSource:   usage,
		EngineVersion: "0.1.0",
	}
	return ar
}

func full(cluster, uid string, fs ...types.Finding) *types.AuditReport {
	return withBasis(mkReport(cluster, fs...), uid, allKinds, nil, "none")
}

// ---- Gate 0: is a comparison possible at all? ----

func TestCompute_TwoDifferentClustersAreNotComparable(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-B", mkFinding("f-b", types.SeverityHigh, 100))

	d := Compute(prev, cur, testDeps())
	if d.Comparable.OK {
		t.Fatal("compared two readings of different clusters — a context name can be renamed or reused")
	}
	if !strings.Contains(strings.ToLower(d.Comparable.Reason), "cluster") {
		t.Errorf("reason %q does not say which gate refused", d.Comparable.Reason)
	}
	if len(d.NewInSet) != 0 || len(d.NoLongerInSet) != 0 || d.FindingsDelta != 0 {
		t.Error("an incomparable pair still produced buckets and deltas — those numbers mean nothing")
	}
	if d.ToTrendDelta() != nil {
		t.Error("ToTrendDelta returned a delta for an incomparable pair; the strip would render a claim")
	}
}

func TestCompute_ASnapshotThatDoesNotSayWhatItReadIsNotComparable(t *testing.T) {
	prev := mkReport("c", mkFinding("f-a", types.SeverityHigh, 100)) // written before RunBasis existed
	cur := full("c", "uid-A")

	d := Compute(prev, cur, testDeps())
	if d.Comparable.OK {
		t.Fatal("compared against a snapshot with no run basis — nothing may be claimed against it")
	}
}

func TestCompute_AChangeOfScopeIsNotComparable(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A")
	cur.Methodology.RunBasis.IncludeSystem = true // the second run looked in more namespaces

	d := Compute(prev, cur, testDeps())
	if d.Comparable.OK {
		t.Fatal("compared runs with different namespace scope — findings appear and vanish wholesale")
	}
}

func TestCompute_ADifferentEngineIsNotComparable(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A")
	cur.Methodology.RunBasis.EngineVersion = "0.2.0"

	d := Compute(prev, cur, testDeps())
	if d.Comparable.OK {
		t.Fatal("compared readings taken by different engines — an absence may be a rule rewrite")
	}
}

func TestCompute_WithoutDependenciesNothingIsComparable(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A")

	d := Compute(prev, cur, nil)
	if d.Comparable.OK {
		t.Fatal("compared without knowing what each finding rests on — every gate after this one is blind")
	}
}

// ---- Gate 1: could the other run evaluate this finding's producer? ----

func TestCompute_ADeniedListMakesAnAbsenceNotEvaluated(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := withBasis(mkReport("c"), "uid-A", []string{"namespaces", "services"},
		[]string{"deployments"}, "none")

	d := Compute(prev, cur, testDeps())
	if !d.Comparable.OK {
		t.Fatalf("the pair is comparable; a denied list is a per-finding matter: %s", d.Comparable.Reason)
	}
	if len(d.NoLongerInSet) != 0 {
		t.Errorf("reported %d finding(s) as gone from the cluster when this run was refused the list they "+
			"rest on — that is the operator's revoked RBAC reported as their own fix", len(d.NoLongerInSet))
	}
	if len(d.NotEvaluated) != 1 {
		t.Fatalf("NotEvaluated holds %d, want 1", len(d.NotEvaluated))
	}
	if d.NotEvaluated[0].Finding.ID != "f-a" || !strings.Contains(d.NotEvaluated[0].Reason, "deployments") {
		t.Errorf("NotEvaluated entry does not name the finding and the list that was missing: %+v", d.NotEvaluated[0])
	}
}

func TestCompute_AnUnconfirmedListIsNotAnAbsence(t *testing.T) {
	// The kind is in neither slice: the run has no record of having looked. Same discipline as
	// rules.observed — an unlooked-at list is never read as an empty one.
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := withBasis(mkReport("c"), "uid-A", []string{"namespaces", "services"}, nil, "none")

	d := Compute(prev, cur, testDeps())
	if len(d.NoLongerInSet) != 0 || len(d.NotEvaluated) != 1 {
		t.Errorf("NoLongerInSet=%d NotEvaluated=%d — a kind recorded neither way was treated as read",
			len(d.NoLongerInSet), len(d.NotEvaluated))
	}
}

func TestCompute_MissingPrometheusIsNotAFixedCluster(t *testing.T) {
	// Observed live: the same testbed audited with and without Prometheus differs by exactly one
	// rightsizing finding. Reporting that as gone from the cluster would credit the operator for
	// unplugging a connection.
	deps := map[string]Deps{"k8s.cost.overprovisioned-resources": {Kinds: []string{"deployments"}, Usage: true}}
	f := mkFinding("f-rs", types.SeverityMedium, 40)
	f.RuleID = "k8s.cost.overprovisioned-resources"
	prev := withBasis(mkReport("c", f), "uid-A", allKinds, nil, "prometheus")
	cur := full("c", "uid-A")

	d := Compute(prev, cur, deps)
	if len(d.NoLongerInSet) != 0 {
		t.Error("a usage-dependent finding was reported as gone from a run that had no usage source")
	}
	if len(d.NotEvaluated) != 1 || !strings.Contains(strings.ToLower(d.NotEvaluated[0].Reason), "usage") {
		t.Errorf("NotEvaluated does not name the missing usage source: %+v", d.NotEvaluated)
	}
}

func TestCompute_AnUnknownProducerIsNotComparedFinding(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A")

	d := Compute(prev, cur, map[string]Deps{"some.other.rule": {Kinds: []string{"deployments"}}})
	if len(d.NoLongerInSet) != 0 || len(d.NotEvaluated) != 1 {
		t.Errorf("a finding from a producer we cannot describe was classified anyway: NoLongerInSet=%d",
			len(d.NoLongerInSet))
	}
}

func TestCompute_AFindingThePreviousRunCouldNotEvaluateIsNotNew(t *testing.T) {
	// The mirrored direction, equally dishonest: calling it new says the cluster changed, when what
	// changed is that we could finally look.
	prev := withBasis(mkReport("c"), "uid-A", []string{"namespaces", "services"},
		[]string{"deployments"}, "none")
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))

	d := Compute(prev, cur, testDeps())
	if len(d.NewInSet) != 0 {
		t.Errorf("reported %d finding(s) as new when the earlier run was refused the list they rest on",
			len(d.NewInSet))
	}
	if len(d.NotEvaluated) != 1 {
		t.Fatalf("NotEvaluated holds %d, want 1", len(d.NotEvaluated))
	}
	if d.NotEvaluated[0].Side != SideCurrent {
		t.Errorf("the entry does not record which reading it came from: %+v", d.NotEvaluated[0])
	}
}

// ---- Gates 2 and 3: the same ID on both sides ----

func TestCompute_ARuleThatChangedItsOwnLogicIsNotAChangedCluster(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur.Findings[0].RuleVersion = "2.0.0"

	d := Compute(prev, cur, testDeps())
	if d.Present != 0 {
		t.Error("a finding whose rule was rewritten between readings was counted as unchanged")
	}
	if len(d.RuleChanged) != 1 {
		t.Fatalf("RuleChanged holds %d, want 1", len(d.RuleChanged))
	}
}

func TestCompute_SomethingLoadBearingMovingIsChangedNotPresent(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityMedium, 100))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))

	d := Compute(prev, cur, testDeps())
	if d.Present != 0 {
		t.Error("a finding whose severity grew more urgent was counted as unchanged")
	}
	if len(d.Changed) != 1 {
		t.Fatalf("Changed holds %d, want 1", len(d.Changed))
	}
	if len(d.Regressed) != 1 {
		t.Error("a severity that grew more urgent is a regression and was not flagged as one")
	}
	if !strings.Contains(strings.ToLower(d.Changed[0].What), "severity") {
		t.Errorf("the change does not say what moved: %q", d.Changed[0].What)
	}
}

func TestCompute_AGenuineAbsenceIsStillReported(t *testing.T) {
	// The gates must not swallow the real signal: both runs read everything, so an absence is a
	// difference between two sets and may be reported as exactly that.
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-b", types.SeverityLow, 5))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-c", types.SeverityLow, 7))

	d := Compute(prev, cur, testDeps())
	if len(d.NoLongerInSet) != 1 || d.NoLongerInSet[0].ID != "f-b" {
		t.Errorf("NoLongerInSet = %v, want exactly f-b", findingIDs(d.NoLongerInSet))
	}
	if len(d.NewInSet) != 1 || d.NewInSet[0].ID != "f-c" {
		t.Errorf("NewInSet = %v, want exactly f-c", findingIDs(d.NewInSet))
	}
	if d.Present != 1 {
		t.Errorf("Present = %d, want 1", d.Present)
	}
	if len(d.NotEvaluated) != 0 {
		t.Errorf("NotEvaluated = %+v, want none", d.NotEvaluated)
	}
	td := d.ToTrendDelta()
	if td == nil || td.NewCount != 1 || td.NoLongerInSetCount != 1 || td.NotEvaluatedCount != 0 {
		t.Errorf("trend delta = %+v", td)
	}
}

func TestToTrendDelta_CarriesTheCoverageCaveat(t *testing.T) {
	// A strip that prints "1 no longer present" while three findings could not be evaluated is telling
	// half a truth, so the count travels with the delta.
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-b", types.SeverityLow, 5))
	prev.Findings[1].RuleID = "unknown.rule"
	cur := full("c", "uid-A")

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("nil delta")
	}
	if td.NoLongerInSetCount != 1 || td.NotEvaluatedCount != 1 {
		t.Errorf("NoLongerInSetCount=%d NotEvaluatedCount=%d, want 1/1", td.NoLongerInSetCount, td.NotEvaluatedCount)
	}
}

var _ = time.Now

// ---- the dollar delta has its own gate ----
//
// The cost rules fire with or without a price: idle_loadbalancer.go:170 and node_headroom.go:217 both
// wrap the lookup in `if ok`, so an unpriced finding still exists, it just carries no figure. That means
// pricing coverage never changes which findings appear — but it absolutely changes the SUM. A price table
// that gains a region between two runs would make the strip announce "+$1,200/mo identified" when nothing
// about the cluster moved at all.
func TestCompute_APriceTableThatGainedARegionIsNotAChangedCluster(t *testing.T) {
	f := mkFinding("f-lb", types.SeverityLow, 0)
	prev := full("c", "uid-A", f)
	prev.Architecture = &types.Architecture{UnpricedNodeTypes: []string{"Standard_D4as_v5"}}
	prev.Summary.EstimatedSavingsUSD = 0

	priced := mkFinding("f-lb", types.SeverityLow, 18.40)
	cur := full("c", "uid-A", priced)
	cur.Architecture = &types.Architecture{} // the type is priced now
	cur.Summary.EstimatedSavingsUSD = 18.40

	d := Compute(prev, cur, testDeps())
	if !d.Comparable.OK {
		t.Fatalf("the findings are still comparable; only the dollar is in question: %s", d.Comparable.Reason)
	}
	if !d.PricingCoverageChanged {
		t.Error("the two readings priced different node types and the comparison did not notice")
	}
	td := d.ToTrendDelta()
	if td == nil || !td.PricingCoverageChanged {
		t.Fatalf("the caveat did not reach the report: %+v", td)
	}
}

func TestCompute_SamePricingCoverageLeavesTheDollarDeltaAlone(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityLow, 10))
	prev.Architecture = &types.Architecture{UnpricedNodeTypes: []string{"kind-node"}}
	prev.Summary.EstimatedSavingsUSD = 10
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityLow, 40))
	cur.Architecture = &types.Architecture{UnpricedNodeTypes: []string{"kind-node"}}
	cur.Summary.EstimatedSavingsUSD = 40

	d := Compute(prev, cur, testDeps())
	if d.PricingCoverageChanged {
		t.Error("identical unpriced sets were reported as a pricing change, suppressing a real dollar move")
	}
	if d.SavingsDelta != 30 {
		t.Errorf("SavingsDelta = %v, want 30", d.SavingsDelta)
	}
}

// ---- Gate 0: an unstamped engine version is not a confirmed match ----
//
// WHY THIS TEST EXISTS. `comparable` refuses an EMPTY ClusterUID explicitly (diff.go:242-245) on the
// reasoning that a reading which does not say which cluster it is of cannot be claimed against. The
// EngineVersion check two lines below was a bare `!=`, so two readings that BOTH failed to say which engine
// produced them compared cleanly — the one case where the answer is not "the same engine" but "we cannot
// say". The doctrine is already written down two functions away, in pricingCoverageChanged: "an unconfirmed
// equivalence is not an equivalence" (diff.go:261-264). This applies it to the engine stamp.
//
// It is unreachable from a real audit today — pipeline.go:278 always stamps rules.EngineVersion(), and
// RunBasis and EngineVersion landed in the same commit (a5bf11c), so no snapshot on disk has one without the
// other. It is reachable from a hand-built report, a third-party producer, and a future schema in which the
// field becomes optional again, which is exactly when a silent comparison would be worst.
//
// WHAT THIS TEST IS NOT. It is not the engine-version gate working. That gate compares a hand-maintained
// constant (`engineVersion` at internal/rules/rules.go:110) which has not moved since the first rules commit,
// so a rule ADDED between two readings is still reported as a change to the cluster. That defect is recorded
// in docs/qa/bug-ledger.md and in the recurrence spec §4; it cannot be fixed inside this package.
func TestCompute_AnUnstampedEngineVersionIsNotComparable(t *testing.T) {
	unstamped := func(fs ...types.Finding) *types.AuditReport {
		ar := withBasis(mkReport("c", fs...), "uid-A", allKinds, nil, "none")
		ar.Methodology.RunBasis.EngineVersion = ""
		return ar
	}

	// Both sides silent about the engine: equal strings, and equality is not the question.
	d := Compute(unstamped(mkFinding("f-a", types.SeverityHigh, 100)), unstamped(), testDeps())
	if d.Comparable.OK {
		t.Error("compared two readings that do not record which engine produced them — an unconfirmed " +
			"equivalence is not an equivalence, and an absence here may be a rule that did not exist yet")
	}
	if !strings.Contains(strings.ToLower(d.Comparable.Reason), "engine") {
		t.Errorf("reason %q does not name the engine stamp, so a report cannot print why it withheld",
			d.Comparable.Reason)
	}

	// One side silent is the same answer for the same reason.
	half := Compute(unstamped(mkFinding("f-a", types.SeverityHigh, 100)), full("c", "uid-A"), testDeps())
	if half.Comparable.OK {
		t.Error("compared a stamped reading against an unstamped one")
	}

	// NON-VACUITY. The identical fixture with both sides stamped MUST compare, and must produce the real
	// signal. Without this, a `comparable` that refused everything would pass both halves above.
	ok := Compute(full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100)), full("c", "uid-A"), testDeps())
	if !ok.Comparable.OK {
		t.Fatalf("the stamped control pair was refused, so the assertions above prove nothing: %s",
			ok.Comparable.Reason)
	}
	if len(ok.NoLongerInSet) != 1 {
		t.Errorf("the stamped control pair produced %d confirmed absences, want 1 — the fixture is not "+
			"exercising the path this test claims to guard", len(ok.NoLongerInSet))
	}
}

// ---- Gate 0/1 across a release: RunBasis.RuleSet ----

func withRuleSet(ar *types.AuditReport, version string, stamps ...types.RuleStamp) *types.AuditReport {
	ar.Methodology.RunBasis.EngineVersion = version
	ar.Methodology.RunBasis.RuleSet = stamps
	return ar
}

var (
	stampTest = types.RuleStamp{ID: "k8s.test.rule", Version: "1.0.0"}
	stampNew  = types.RuleStamp{ID: "k8s.test.newrule", Version: "1.0.0"}
)

func newRuleFinding(id string) types.Finding {
	f := mkFinding(id, types.SeverityMedium, 0)
	f.RuleID = "k8s.test.newrule"
	return f
}

func depsWithNewRule() map[string]Deps {
	d := testDeps()
	d["k8s.test.newrule"] = Deps{Kinds: []string{"deployments"}}
	return d
}

// THE DEFECT, REPRODUCED: a rule added between two readings must never report its findings as new in the
// cluster. Before this gate, Gate 0 passed (same engine string or, after the digest, refused everything) and
// Gate 1 only asked whether the kinds were read — they were — so the finding landed in NewInSet, a bucket
// documented as "absence CONFIRMED". The absence was not confirmed; the earlier build was not looking.
func TestCompute_ARuleAddedBetweenReadingsIsNotEvaluatedNotNew(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A"), "0.18.0", stampTest)
	cur := withRuleSet(full("c", "uid-A", newRuleFinding("f-new")), "0.19.0", stampTest, stampNew)

	d := Compute(prev, cur, depsWithNewRule())
	if !d.Comparable.OK {
		t.Fatalf("both readings carry RuleSet, yet Gate 0 refused: %s", d.Comparable.Reason)
	}
	if len(d.NewInSet) != 0 {
		t.Fatalf("a finding of a rule the earlier build did not have landed in NewInSet: %v", findingIDs(d.NewInSet))
	}
	if len(d.NotEvaluated) != 1 || d.NotEvaluated[0].Side != SideCurrent {
		t.Fatalf("want exactly one current-side NotEvaluated entry, got %+v", d.NotEvaluated)
	}
	want := "rule k8s.test.newrule was not part of the " + prev.GeneratedAt.Format("2 Jan 2006") + " reading's build"
	if d.NotEvaluated[0].Reason != want {
		t.Errorf("reason %q, want %q", d.NotEvaluated[0].Reason, want)
	}
}

// The non-vacuity half: the SAME pair with the rule present in both stamps must land in NewInSet, proving the
// previous test distinguishes "the build lacked the rule" from "the cluster gained the finding".
func TestCompute_ARuleInBothBuildsCanStillProduceANewFinding(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A"), "0.19.0", stampTest, stampNew)
	cur := withRuleSet(full("c", "uid-A", newRuleFinding("f-new")), "0.19.0", stampTest, stampNew)

	d := Compute(prev, cur, depsWithNewRule())
	if len(d.NewInSet) != 1 || len(d.NotEvaluated) != 0 {
		t.Fatalf("want 1 NewInSet and 0 NotEvaluated, got %d and %d", len(d.NewInSet), len(d.NotEvaluated))
	}
}

// A rule whose VERSION changed between the builds, for a finding present on one side only, is withheld with
// both versions named. (Findings present on both sides already go to RuleChanged via Gate 2.)
func TestCompute_ARuleReversionedBetweenBuildsWithholdsItsOneSidedFinding(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A"), "0.18.0", types.RuleStamp{ID: "k8s.test.rule", Version: "1.0.0"})
	cur := withRuleSet(full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10)), "0.19.0",
		types.RuleStamp{ID: "k8s.test.rule", Version: "2.0.0"})
	cur.Findings[0].RuleVersion = "2.0.0"

	d := Compute(prev, cur, testDeps())
	if len(d.NotEvaluated) != 1 || d.NotEvaluated[0].Reason != "rule k8s.test.rule changed from 1.0.0 to 2.0.0 between the readings" {
		t.Fatalf("got %+v", d.NotEvaluated)
	}
}

// Legacy: a snapshot without RuleSet cannot be asked the sharp question, so the engine-version refusal stays
// exactly as it is today.
func TestCompute_EngineMismatchWithoutRuleSetStillRefusesWholesale(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A"), "0.18.0")           // no stamps: a pre-2026-09-02 snapshot
	cur := withRuleSet(full("c", "uid-A"), "0.19.0", stampTest) // today's build

	d := Compute(prev, cur, testDeps())
	if d.Comparable.OK {
		t.Fatal("a legacy snapshot was compared across an engine change; it cannot say what rules it had")
	}
	if !strings.Contains(d.Comparable.Reason, "different versions of the engine (0.18.0 and 0.19.0)") {
		t.Errorf("reason lost the two versions: %q", d.Comparable.Reason)
	}
}

// Both sides stamped, engine moved, no rule churn touching the findings: comparable, and the engine move is
// a NOTE the strip can print, not a refusal.
func TestCompute_EngineMismatchWithRuleSetsIsComparableWithANote(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10)), "0.18.0", stampTest)
	cur := withRuleSet(full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10)), "0.19.0", stampTest)

	d := Compute(prev, cur, testDeps())
	if !d.Comparable.OK {
		t.Fatalf("refused: %s", d.Comparable.Reason)
	}
	if !strings.Contains(d.Comparable.Note, "0.18.0") || !strings.Contains(d.Comparable.Note, "0.19.0") {
		t.Errorf("note does not name both engine versions: %q", d.Comparable.Note)
	}
	if d.Present != 1 {
		t.Errorf("the unchanged finding should be Present, got Present=%d", d.Present)
	}
}

// Spec 2026-08-28 §5 defect 2: a --redact snapshot and a plain one of the SAME cluster carry different
// ClusterUIDs (one is a token), and Gate 0 said "two different clusters" — a false sentence about the
// customer's estate, printed verbatim. The refusal stands; the reason now says what happened.
func TestCompute_RedactMixedPairIsRefusedForTheRightReason(t *testing.T) {
	plain := full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10))
	redacted := full("c", "uid-token-7f3a", mkFinding("f-1", types.SeverityHigh, 10))
	redacted.Methodology.RunBasis.Redacted = true

	d := Compute(plain, redacted, testDeps())
	if d.Comparable.OK {
		t.Fatal("a redacted and a plain reading were compared; their identities cannot be matched")
	}
	if strings.Contains(d.Comparable.Reason, "two different clusters") {
		t.Errorf("the reason still asserts two clusters: %q", d.Comparable.Reason)
	}
	if !strings.Contains(d.Comparable.Reason, "redacted") {
		t.Errorf("the reason does not say what happened: %q", d.Comparable.Reason)
	}
	// Two redacted readings of one cluster tokenise the UID the same way and stay comparable.
	r2 := full("c", "uid-token-7f3a", mkFinding("f-1", types.SeverityHigh, 10))
	r2.Methodology.RunBasis.Redacted = true
	if !Compute(redacted, r2, testDeps()).Comparable.OK {
		t.Error("two redacted readings of one cluster must compare")
	}
}

// Spec §7 test 7: the exported wrapper and the diff's own gate agree, on a case that blocks and one that does not.
func TestBlocked_IsTheSameFunctionTheDiffUses(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	sees := full("c", "uid-A")
	blind := withBasis(mkReport("c"), "uid-A", nil, []string{"deployments"}, "none")
	for _, tc := range []struct {
		name  string
		other *types.AuditReport
		want  bool
	}{{"kinds read", sees, false}, {"kind denied", blind, true}} {
		r1, b1 := Blocked(f, tc.other, testDeps())
		r2, b2 := blockedBy(f, tc.other, testDeps())
		if b1 != tc.want || b1 != b2 || r1 != r2 {
			t.Errorf("%s: Blocked=(%q,%v) blockedBy=(%q,%v), want blocked=%v", tc.name, r1, b1, r2, b2, tc.want)
		}
	}
}
