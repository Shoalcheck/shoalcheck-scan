package history

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// findingIDs extracts the IDs from a finding slice for set comparison.
func findingIDs(fs []types.Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.ID] = true
	}
	return m
}

// TestCompute_NewGoneAndPresent builds prev/cur with overlapping, new, and
// resolved findings and asserts the classification and all deltas.
func TestCompute_NewGoneAndPresent(t *testing.T) {
	prevAt := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)

	// prev: f-a (high, $100), f-b (medium, $50)  -> total savings 150, 2 findings
	prev := full("c", "uid-A",
		mkFinding("f-a", types.SeverityHigh, 100),
		mkFinding("f-b", types.SeverityMedium, 50),
	)
	prev.GeneratedAt = prevAt

	// cur: f-a (high, $100) unchanged, f-c (low, $20) new; f-b resolved
	cur := full("c", "uid-A",
		mkFinding("f-a", types.SeverityHigh, 100),
		mkFinding("f-c", types.SeverityLow, 20),
	)

	d := Compute(prev, cur, testDeps())

	if !d.PrevAt.Equal(prevAt) {
		t.Errorf("PrevAt = %v, want %v", d.PrevAt, prevAt)
	}
	if got := findingIDs(d.NewInSet); len(got) != 1 || !got["f-c"] {
		t.Errorf("New = %v, want {f-c}", got)
	}
	if got := findingIDs(d.NoLongerInSet); len(got) != 1 || !got["f-b"] {
		t.Errorf("Resolved = %v, want {f-b}", got)
	}
	if d.Present != 1 {
		t.Errorf("Present = %d, want 1 (f-a)", d.Present)
	}
	// savings: cur 120 - prev 150 = -30
	if d.SavingsDelta != -30 {
		t.Errorf("SavingsDelta = %v, want -30", d.SavingsDelta)
	}
	// findings: 2 - 2 = 0
	if d.FindingsDelta != 0 {
		t.Errorf("FindingsDelta = %d, want 0", d.FindingsDelta)
	}
	// severity deltas: high unchanged (drop), medium -1 (f-b gone), low +1 (f-c new)
	if d.BySeverityDelta[types.SeverityMedium] != -1 {
		t.Errorf("BySeverityDelta[medium] = %d, want -1", d.BySeverityDelta[types.SeverityMedium])
	}
	if d.BySeverityDelta[types.SeverityLow] != 1 {
		t.Errorf("BySeverityDelta[low] = %d, want 1", d.BySeverityDelta[types.SeverityLow])
	}
	if _, present := d.BySeverityDelta[types.SeverityHigh]; present {
		t.Errorf("BySeverityDelta should omit unchanged severities, but high present = %d", d.BySeverityDelta[types.SeverityHigh])
	}
}

// TestCompute_IdenticalReportsEmptyDiff proves two identical reports diff to an
// empty Diff: no New/Resolved/Regressed, zero deltas, all unchanged.
func TestCompute_IdenticalReportsEmptyDiff(t *testing.T) {
	r := full("c", "uid-A",
		mkFinding("f-a", types.SeverityHigh, 100),
		mkFinding("f-b", types.SeverityMedium, 50),
	)
	d := Compute(r, r, testDeps())
	if len(d.NewInSet) != 0 || len(d.NoLongerInSet) != 0 || len(d.Regressed) != 0 {
		t.Errorf("identical reports: New=%d Resolved=%d Regressed=%d, want all 0",
			len(d.NewInSet), len(d.NoLongerInSet), len(d.Regressed))
	}
	if d.Present != 2 {
		t.Errorf("Present = %d, want 2", d.Present)
	}
	if d.SavingsDelta != 0 || d.FindingsDelta != 0 {
		t.Errorf("identical reports must have zero deltas, got savings=%v findings=%d", d.SavingsDelta, d.FindingsDelta)
	}
	if len(d.BySeverityDelta) != 0 {
		t.Errorf("identical reports must have empty BySeverityDelta, got %v", d.BySeverityDelta)
	}
}

// TestCompute_RegressedSeverity proves a finding kept by ID whose severity got
// MORE urgent lands in Regressed (and still counts as Unchanged).
func TestCompute_RegressedSeverity(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityMedium, 0))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 0))
	d := Compute(prev, cur, testDeps())
	if got := findingIDs(d.Regressed); len(got) != 1 || !got["f-a"] {
		t.Errorf("Regressed = %v, want {f-a}", got)
	}
	if d.InBoth != 1 {
		t.Errorf("InBoth = %d, want 1 (a regressed finding is still present in both readings)", d.InBoth)
	}
	if len(d.NewInSet) != 0 || len(d.NoLongerInSet) != 0 {
		t.Errorf("severity change must not be New/Resolved: New=%d Resolved=%d", len(d.NewInSet), len(d.NoLongerInSet))
	}
}

// TestCompute_AllNewFromEmptyPrev proves the first-ever-vs-empty case: everything
// in cur is New when prev had no findings.
func TestCompute_AllNewFromEmptyPrev(t *testing.T) {
	prev := full("c", "uid-A")
	cur := full("c", "uid-A",
		mkFinding("f-a", types.SeverityHigh, 100),
		mkFinding("f-b", types.SeverityLow, 5),
	)
	d := Compute(prev, cur, testDeps())
	if len(d.NewInSet) != 2 || len(d.NoLongerInSet) != 0 || d.Present != 0 {
		t.Errorf("all-new: New=%d Resolved=%d Unchanged=%d, want 2/0/0", len(d.NewInSet), len(d.NoLongerInSet), d.Present)
	}
	if d.FindingsDelta != 2 || d.SavingsDelta != 105 {
		t.Errorf("all-new deltas: findings=%d savings=%v, want 2/105", d.FindingsDelta, d.SavingsDelta)
	}
}

// TestDiff_ToTrendDelta proves the projection into types.TrendDelta carries the
// summary numbers the renderer needs.
func TestDiff_ToTrendDelta(t *testing.T) {
	prevAt := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-b", types.SeverityMedium, 50))
	prev.GeneratedAt = prevAt
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-c", types.SeverityLow, 20))

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("ToTrendDelta returned nil")
	}
	if !td.PreviousAt.Equal(prevAt) {
		t.Errorf("PreviousAt = %v, want %v", td.PreviousAt, prevAt)
	}
	if td.NewCount != 1 || td.NoLongerInSetCount != 1 {
		t.Errorf("NewCount=%d ResolvedCount=%d, want 1/1", td.NewCount, td.NoLongerInSetCount)
	}
	if td.FindingsDelta != 0 || td.SavingsDelta != -30 {
		t.Errorf("FindingsDelta=%d SavingsDelta=%v, want 0/-30", td.FindingsDelta, td.SavingsDelta)
	}
}

// A COUNT A READER CANNOT OPEN. The instrument printed "13 new in this reading" over a real comparison and
// nothing on the page said which thirteen: the delta carried the number and dropped the set it counted.
// The ids travel now, sorted, so the same two readings always name the same findings in the same order.
func TestDiff_ToTrendDelta_NamesTheNewFindings(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100),
		mkFinding("f-z", types.SeverityLow, 5), mkFinding("f-m", types.SeverityMedium, 20))

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("ToTrendDelta returned nil")
	}
	if got, want := strings.Join(td.NewIDs, ","), "f-m,f-z"; got != want {
		t.Errorf("NewIDs = %q, want %q — the ids of exactly the findings NewCount counts, sorted", got, want)
	}
	if td.NewCount != len(td.NewIDs) {
		t.Errorf("NewCount %d and %d NewIDs: the count and the set it counts disagree", td.NewCount, len(td.NewIDs))
	}

	same := Compute(prev, prev, testDeps()).ToTrendDelta()
	if same == nil || same.NewIDs != nil {
		t.Errorf("a reading compared with itself names new findings: %v", same)
	}
}

// WHICH FINDINGS LEFT, not only how many. "1 no longer in the set" named nothing, and unlike a new finding the one
// that left cannot be looked up in this reading: it exists only in the earlier one (D50 product review). The delta
// carries what the earlier reading said about each — id, rule, severity and title — sorted by id, so the same two
// readings name the same findings in the same order.
func TestDiff_ToTrendDelta_NamesTheFindingsThatLeft(t *testing.T) {
	prev := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-q", types.SeverityMedium, 50),
		mkFinding("f-b", types.SeverityCritical, 0))
	cur := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("ToTrendDelta returned nil")
	}
	if len(td.NoLongerInSet) != td.NoLongerInSetCount {
		t.Fatalf("%d named for NoLongerInSetCount %d: the count and the set it counts disagree", len(td.NoLongerInSet), td.NoLongerInSetCount)
	}
	want := []types.TrendFinding{
		{ID: "f-b", RuleID: "k8s.test.rule", Severity: types.SeverityCritical, Title: "t f-b"},
		{ID: "f-q", RuleID: "k8s.test.rule", Severity: types.SeverityMedium, Title: "t f-q"},
	}
	if !reflect.DeepEqual(td.NoLongerInSet, want) {
		t.Errorf("NoLongerInSet = %+v, want %+v", td.NoLongerInSet, want)
	}

	same := Compute(prev, prev, testDeps()).ToTrendDelta()
	if same == nil || same.NoLongerInSet != nil {
		t.Errorf("a reading compared with itself names findings that left: %v", same)
	}
}

// The savings delta is a difference between two sums, so any drift in the sums is doubled here.
//
// ToTrendDelta was only ever exercised against round numbers, where float64 addition happens to be
// exact. Real reports are not round: node-headroom lands on values like 441.13 and an idle load
// balancer on 18.40, and a hundred of those accumulate an error that the headline's own
// reconciliation would catch on ONE reading while saying nothing about the difference between two.
//
// The tolerance is half a cent, because a figure printed to the cent has to be right to the cent.
func TestDiff_TheSavingsDeltaIsExactToTheCent(t *testing.T) {
	// Values chosen because none is representable exactly in binary floating point.
	cents := []float64{441.13, 18.40, 0.07, 1234.56, 99.99, 3.33, 7.77, 0.01, 812.45, 66.66}

	var prevFs, curFs []types.Finding
	var prevSum, curSum float64
	for i, v := range cents {
		prevFs = append(prevFs, mkFinding(fmt.Sprintf("f-p%02d", i), types.SeverityMedium, v))
		prevSum += v
		// The current reading keeps every other finding and re-prices the rest a cent higher, so the
		// delta is a genuine difference rather than a whole sum cancelling out.
		if i%2 == 0 {
			curFs = append(curFs, mkFinding(fmt.Sprintf("f-p%02d", i), types.SeverityMedium, v+0.01))
			curSum += v + 0.01
		}
	}
	prev := full("c", "uid-A", prevFs...)
	prev.GeneratedAt = time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	cur := full("c", "uid-A", curFs...)

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("ToTrendDelta returned nil on a comparable pair")
	}
	want := curSum - prevSum
	if diff := td.SavingsDelta - want; diff > 0.005 || diff < -0.005 {
		t.Errorf("SavingsDelta = %.6f, want %.6f (out by %.6f) — this figure is printed to the cent, so it\n"+
			"    has to be right to the cent, and it is the difference of two sums rather than one",
			td.SavingsDelta, want, diff)
	}
	// And the rounded presentation must agree with the arithmetic, not merely be close to it.
	if got, exp := math.Round(td.SavingsDelta*100)/100, math.Round(want*100)/100; got != exp {
		t.Errorf("rounded to cents: %.2f vs %.2f", got, exp)
	}
}

func TestToTrendDelta_CarriesLabelsCountsAndTheEngineNote(t *testing.T) {
	prev := withRuleSet(full("c", "uid-A", mkFinding("f-1", types.SeverityMedium, 10)), "0.18.0", stampTest)
	prev.Methodology.Label = "before upgrade to 1.32"
	cur := withRuleSet(full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10)), "0.19.0", stampTest)
	cur.Methodology.Label = "after upgrade to 1.32"

	td := Compute(prev, cur, testDeps()).ToTrendDelta()
	if td == nil {
		t.Fatal("comparable pair produced no delta")
	}
	if td.PreviousLabel != "before upgrade to 1.32" || td.Label != "after upgrade to 1.32" {
		t.Errorf("labels not carried: prev=%q cur=%q", td.PreviousLabel, td.Label)
	}
	if td.RegressedCount != 1 || td.ChangedCount != 1 {
		t.Errorf("medium→high is one change and one regression, got changed=%d regressed=%d", td.ChangedCount, td.RegressedCount)
	}
	if td.EngineNote == "" {
		t.Error("engine moved 0.18.0→0.19.0 with both stamps present; the note is empty")
	}
	if td.NotCompared != nil {
		t.Error("a comparison that was made must not carry a refusal")
	}
}

// A prior that exists but could not be compared is a fact the cover must state. ToTrendDelta stays nil for
// an incomparable pair (its callers and tests rely on that); Refusal is the explicit second constructor.
func TestRefusal_NamesThePriorAndTheGateThatRefused(t *testing.T) {
	prev := full("c", "uid-A")
	cur := full("c", "uid-B")
	d := Compute(prev, cur, testDeps())
	if d.ToTrendDelta() != nil {
		t.Fatal("ToTrendDelta must stay nil for an incomparable pair")
	}
	r := d.Refusal()
	if r == nil || r.NotCompared == nil {
		t.Fatal("Refusal returned nothing for an incomparable pair")
	}
	if !r.PreviousAt.Equal(prev.GeneratedAt) || r.NotCompared.Reason != d.Comparable.Reason {
		t.Errorf("refusal does not name the prior and the reason: %+v", r.NotCompared)
	}
	if r.NewCount != 0 || r.NoLongerInSetCount != 0 || r.FindingsDelta != 0 {
		t.Error("a refusal carries no counts — every number here would be a claim")
	}
	if Compute(prev, full("c", "uid-A"), testDeps()).Refusal() != nil {
		t.Error("Refusal must be nil when the comparison was made")
	}
}

// Spec §5.3: a label is copy, never a run fact. Mutating it changes nothing about comparability.
func TestCompute_TheLabelNeverAffectsComparability(t *testing.T) {
	mk := func(label string) *types.AuditReport {
		ar := full("c", "uid-A", mkFinding("f-1", types.SeverityHigh, 10))
		ar.Methodology.Label = label
		return ar
	}
	a := Compute(mk(""), mk(""), testDeps()).Comparable
	b := Compute(mk("before upgrade"), mk("a completely different label"), testDeps()).Comparable
	if !reflect.DeepEqual(a, b) {
		t.Errorf("label changed Comparability: %+v vs %+v", a, b)
	}
}

// A DELTA BETWEEN TWO FIGURES THAT ARE NOT MEASUREMENTS IS NOT A MEASUREMENT.
//
// Found by running the product on this machine:
//
//	shoalcheck diff
//	  savings:  +0.00 USD/mo (Δ)
//
// against kind-assay-e2e, where 93 of 94 findings are not-cost, one is unpriced, and the reading carries no
// savings figure at all. "+0.00 USD/mo (Δ)" reads as "the savings did not move". Nothing moved because
// nothing was ever priced, and those are opposite news.
//
// PricingCoverageChanged already guards the case where the two readings could price DIFFERENT sets — a sum
// moving for a reason that has nothing to do with the cluster. It cannot see this one: when neither reading
// priced anything, the coverage did not change and the delta is a difference of two non-measurements.
func TestCompute_ADeltaBetweenTwoUnpricedReadingsIsNotAFigure(t *testing.T) {
	unpriced := func(id string) types.Finding {
		f := mkFinding(id, types.SeverityHigh, 0)
		f.PriceBasis = types.PriceUnpriced
		return f
	}
	priced := func(id string, usd float64) types.Finding {
		f := mkFinding(id, types.SeverityHigh, usd)
		f.PriceBasis = types.PricePriced
		return f
	}

	// Neither side priced anything.
	prev := full("c", "uid-A", unpriced("f-a"))
	cur := full("c", "uid-A", unpriced("f-a"))
	if d := Compute(prev, cur, testDeps()); d.SavingsPriced {
		t.Error("a delta between two readings that priced nothing reports as a measurement, so a surface " +
			"prints +0.00 USD/mo and a reader takes it for a cluster that did not move")
	}

	// One side priced. The delta then mixes a figure with a non-figure and is still not one.
	if d := Compute(full("c", "uid-A", unpriced("f-a")), full("c", "uid-A", priced("f-a", 400)), testDeps()); d.SavingsPriced {
		t.Error("a delta from an unpriced reading to a priced one reports as a measurement; the difference " +
			"is between a number and an absence")
	}

	// AND THE OVER-REACH THE SAME FIX MUST NOT COMMIT: two priced readings still have a delta.
	d := Compute(full("c", "uid-A", priced("f-a", 100)), full("c", "uid-A", priced("f-a", 400)), testDeps())
	if !d.SavingsPriced {
		t.Error("a delta between two readings that both priced their findings is withheld, which discards " +
			"a figure the readings carry")
	}
	if d.SavingsDelta != 300 {
		t.Errorf("savings delta %.2f, want 300", d.SavingsDelta)
	}
}
