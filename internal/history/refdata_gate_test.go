package history

import (
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE SIXTH GATE — was this produced from the same reference data?
//
// Two places read a number that came from OUR TABLE and attribute its movement to the CLUSTER: movement()'s
// "the monthly figure moved", and SavingsDelta. The existing guard cannot see the case: pricingCoverageChanged
// compares two SETS (UnpricedNodeTypes, UnpricedStorageClasses), so a table update that changes the price of
// an already-covered instance type leaves both sets identical and the delta renders.
//
// gates_test.go states the doctrine that makes this a defect rather than a nuance: "a price table that gains a
// region between two runs would make the strip announce '+$1,200/mo identified' when nothing about the
// cluster moved at all." Replace "gains a region" with "is refreshed" and it describes the shipped product the
// moment `shoalcheck update` exists.

// SPEC §10 test 4 — a different SOURCE for the same VERSION is still comparable.
//
// The gate compares Version and never Source. The same table read from the embedded snapshot on Monday and
// from a bundle on Friday is the same table, and refusing over provenance would withhold a comparison we are
// entitled to make. This is the one place a lazier implementation — compare the whole struct — passes every
// other test in this file.
func TestCompute_ADifferentSourceForTheSameVersionIsStillComparable(t *testing.T) {
	prev := refdataReport("2026-08", "embedded", 441.13)
	cur := refdataReport("2026-08", "cache", 448.02)

	d := Compute(prev, cur, refdataDeps())
	if !d.Comparable.OK {
		t.Fatalf("Gate 0 refused: %s", d.Comparable.Reason)
	}
	if len(d.ReferenceDataChanged) != 0 {
		t.Errorf("ReferenceDataChanged = %v for the same version read from two sources — the gate is comparing "+
			"provenance instead of the table", d.ReferenceDataChanged)
	}
	if d.SavingsDelta == 0 {
		t.Error("the savings delta was withheld for two readings of the same table version")
	}

	// NON-VACUITY: the same fixture with two different VERSIONS must withhold. Without this, a gate that
	// compares nothing at all passes both halves.
	d2 := Compute(refdataReport("2026-06", "embedded", 441.13), cur, refdataDeps())
	if len(d2.ReferenceDataChanged) == 0 {
		t.Error("two different pricing versions were treated as the same table")
	}
	if d2.SavingsDelta != 0 {
		t.Errorf("SavingsDelta = %.2f across a table refresh — it must be withheld", d2.SavingsDelta)
	}
}

// SPEC §10 test 5 — a refreshed price table is not a changed cluster. THE SPEC SAYS THIS FAILS TODAY.
func TestCompute_ARefreshedPriceTableIsNotAChangedCluster(t *testing.T) {
	prev := refdataReport("2026-06", "embedded", 441.13)
	cur := refdataReport("2026-08", "bundle", 448.02)

	d := Compute(prev, cur, refdataDeps())
	if !d.Comparable.OK {
		t.Fatalf("Gate 0 refused: %s", d.Comparable.Reason)
	}

	// NON-VACUITY, and the load-bearing half: the OLD guard must be silent here. The unpriced sets are
	// identical in this fixture, so if PricingCoverageChanged were true the withholding would prove nothing
	// about the new gate.
	if d.PricingCoverageChanged {
		t.Fatal("PricingCoverageChanged is true, so this fixture cannot show the new gate caught anything — " +
			"the unpriced sets must stay identical")
	}

	for _, c := range d.Changed {
		if strings.Contains(c.What, "monthly figure") {
			t.Errorf("a Change says %q across a table refresh — that attributes our table's movement to the "+
				"customer's cluster", c.What)
		}
	}
	if d.SavingsDelta != 0 {
		t.Errorf("SavingsDelta = %.2f, want 0 (withheld)", d.SavingsDelta)
	}
	if len(d.ReferenceDataChanged) != 1 || d.ReferenceDataChanged[0] != "pricing" {
		t.Errorf("ReferenceDataChanged = %v, want [pricing]", d.ReferenceDataChanged)
	}
	// BOTH VERSIONS NAMED. A caveat without the two values is unfalsifiable.
	if !strings.Contains(d.ReferenceDataReason, "2026-06") || !strings.Contains(d.ReferenceDataReason, "2026-08") {
		t.Errorf("the reason does not name both versions: %q", d.ReferenceDataReason)
	}
	// The founder's phrasing, verbatim, because a surface prints it beside a number it did not compute.
	if !strings.Contains(d.ReferenceDataReason, "our table changed, not your cluster") {
		t.Errorf("the reason does not carry the headline phrasing: %q", d.ReferenceDataReason)
	}
}

// SPEC §10 test 6 — a severity regression survives a withheld figure.
//
// This is the whole argument for the flag over an exclusive bucket: a regression is the one thing a report
// leads with, and a DataVersionChanged bucket mirroring RuleChanged would swallow it.
func TestCompute_ASeverityRegressionSurvivesAWithheldFigure(t *testing.T) {
	prev := refdataReport("2026-06", "embedded", 441.13)
	cur := refdataReport("2026-08", "bundle", 448.02)
	cur.Findings[0].Severity = types.SeverityCritical // was high
	cur.Summary.BySeverity = map[types.Severity]int{types.SeverityCritical: 1}

	d := Compute(prev, cur, refdataDeps())
	if len(d.Changed) != 1 {
		t.Fatalf("%d Change entries, want 1 — the finding was dropped into an exclusive bucket", len(d.Changed))
	}
	c := d.Changed[0]
	if !c.Regressed || len(d.Regressed) != 1 {
		t.Error("the severity regression did not survive the withheld figure")
	}
	if !strings.Contains(c.What, "severity") {
		t.Errorf("What does not name the severity move: %q", c.What)
	}
	if strings.Contains(c.What, "monthly figure") {
		t.Errorf("What names the figure across a table refresh: %q", c.What)
	}
	if len(c.ValueNotCompared) != 1 || c.ValueNotCompared[0] != "pricing" {
		t.Errorf("ValueNotCompared = %v, want [pricing]", c.ValueNotCompared)
	}

	// NON-VACUITY: with EQUAL versions the same fixture must name BOTH, proving the disarm is selective
	// rather than total.
	prevSame := refdataReport("2026-08", "embedded", 441.13)
	d2 := Compute(prevSame, cur, refdataDeps())
	if len(d2.Changed) != 1 {
		t.Fatalf("%d Change entries with equal versions, want 1", len(d2.Changed))
	}
	if !strings.Contains(d2.Changed[0].What, "monthly figure") {
		t.Errorf("with equal versions What must name the figure too: %q", d2.Changed[0].What)
	}
	if len(d2.Changed[0].ValueNotCompared) != 0 {
		t.Errorf("ValueNotCompared = %v with equal versions", d2.Changed[0].ValueNotCompared)
	}
}

// SPEC §10 test 7 — a presence-bearing dataset moves the finding to NotEvaluated.
//
// The Presence split is not decoration. Pricing does not change WHICH findings appear; a Kubernetes
// API-removal table absolutely does — we would stop listing a removal and the finding would vanish with the
// cluster untouched.
func TestCompute_APresenceBearingDatasetMovesToNotEvaluated(t *testing.T) {
	prev := refdataReport("2026-06", "embedded", 441.13)
	cur := refdataReport("2026-08", "bundle", 448.02)
	// A second finding from a presence-bearing producer, present only in the current reading.
	cur.Findings = append(cur.Findings, types.Finding{
		ID: "f-removal", RuleID: "k8s.upgrade.api-removed", RuleVersion: "1.0.0",
		Title: "A workload uses an API removed in the next minor", Severity: types.SeverityHigh,
		Category: types.CategoryConfig, Confidence: 1.0, Description: "Removed.",
		AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "api", Name: "gateway"}},
	})
	cur.Summary.TotalFindings = 2
	cur.Summary.BySeverity = map[types.Severity]int{types.SeverityHigh: 2}

	deps := refdataDeps()
	deps["k8s.upgrade.api-removed"] = Deps{
		Kinds:    []string{"deployments"},
		Datasets: []DatasetDep{{Name: "kubeversions", Presence: true}},
	}
	// Both readings must record the presence dataset, at different versions.
	prev.Methodology.RunBasis.DataVersions["kubeversions"] = types.DataVersion{Version: "2026-06", Source: "embedded"}
	cur.Methodology.RunBasis.DataVersions["kubeversions"] = types.DataVersion{Version: "2026-08", Source: "bundle"}

	d := Compute(prev, cur, deps)
	if len(d.NewInSet) != 0 {
		t.Errorf("NewInSet holds %d finding(s) whose presence rests on a moved table: %+v",
			len(d.NewInSet), d.NewInSet[0].ID)
	}
	var got *Unevaluated
	for i := range d.NotEvaluated {
		if d.NotEvaluated[i].Finding.ID == "f-removal" {
			got = &d.NotEvaluated[i]
		}
	}
	if got == nil {
		t.Fatalf("f-removal is not in NotEvaluated; buckets: new=%d nolonger=%d notEval=%d",
			len(d.NewInSet), len(d.NoLongerInSet), len(d.NotEvaluated))
	}
	if got.Side != SideCurrent {
		t.Errorf("Side = %q, want current", got.Side)
	}
	// NON-VACUITY: the reason must NAME the dataset and both versions, not merely be non-empty — the mistake
	// TestHistory_NotEvaluatedSurvivesToThePayload was written to avoid.
	for _, want := range []string{"kubeversions", "2026-06", "2026-08"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("the reason does not name %q: %q", want, got.Reason)
		}
	}
}

// SPEC §10 test 8 — an absent stamp is not a confirmed match.
//
// Every snapshot already on disk has no DataVersions, so its figures cannot be confirmed to come from the same
// table. pricingCoverageChanged already settles this question for its own case and the reasoning transfers:
// "an unconfirmed equivalence is not an equivalence."
func TestCompute_AnAbsentStampIsNotAConfirmedMatch(t *testing.T) {
	prev := refdataReport("2026-08", "embedded", 441.13)
	prev.Methodology.RunBasis.DataVersions = nil // a pre-versioning snapshot
	cur := refdataReport("2026-08", "bundle", 448.02)

	d := Compute(prev, cur, refdataDeps())
	if !d.Comparable.OK {
		t.Fatalf("Gate 0 refused: %s", d.Comparable.Reason)
	}
	if d.SavingsDelta != 0 {
		t.Errorf("SavingsDelta = %.2f against a snapshot with no data stamp", d.SavingsDelta)
	}
	if len(d.ReferenceDataChanged) == 0 {
		t.Error("an absent stamp was treated as a confirmed match")
	}
	// The reason must say WHICH reading is missing the stamp, not present a bare withheld.
	if !strings.Contains(d.ReferenceDataReason, "does not record") {
		t.Errorf("the absent-stamp reason does not say the earlier reading lacks it: %q", d.ReferenceDataReason)
	}

	// NON-VACUITY: two stamped snapshots with equal versions must render the delta, so "always withholds"
	// fails.
	d2 := Compute(refdataReport("2026-08", "embedded", 441.13), cur, refdataDeps())
	if d2.SavingsDelta == 0 {
		t.Error("two equally-stamped readings also withheld, so this test proves nothing")
	}
}

// THE WORDINGS PASS internal/lexicon. Every string this gate prints is customer-facing prose, and the copy
// policy is not scoped away from it just because it is generated in Go.
func TestRefdataGate_ItsWordingsCarryNoBannedClaim(t *testing.T) {
	d := Compute(refdataReport("2026-06", "embedded", 441.13), refdataReport("2026-08", "bundle", 448.02), refdataDeps())
	blob := strings.ToLower(d.ReferenceDataReason)
	for _, c := range d.Changed {
		blob += "\n" + strings.ToLower(c.What)
	}
	for _, u := range d.NotEvaluated {
		blob += "\n" + strings.ToLower(u.Reason)
	}
	// The comparison-scoped bans, spelled here rather than imported: internal/history is a leaf that
	// internal/lexicon does not depend on, and the report-side scan covers the rendered document. This is the
	// producer-side guard on the strings themselves.
	for _, banned := range []string{"fixed", "resolved", "saved", "realized", "eliminated", "clean bill"} {
		if strings.Contains(blob, banned) {
			t.Errorf("a gate wording contains the banned word %q:\n%s", banned, blob)
		}
	}
	if blob == "" {
		t.Fatal("the gate produced no wording at all, so this scan measured nothing")
	}
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────

// refdataReport is one reading with a single cost finding, a pricing stamp, and IDENTICAL unpriced sets on
// both sides — which is what keeps pricingCoverageChanged false and makes the new gate the only thing that
// can withhold.
func refdataReport(pricingVersion, source string, dollars float64) *types.AuditReport {
	at := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	return &types.AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   at,
		Cluster:       types.ClusterInfo{Name: "acme-prod"},
		Findings: []types.Finding{{
			ID: "f-cost", RuleID: "k8s.cost.node-headroom", RuleVersion: "1.0.0",
			Title: "Nodes carry more capacity than the workloads request", Severity: types.SeverityHigh,
			Category: types.CategoryCost, Confidence: 0.9, Description: "Headroom.",
			Evidence:            []string{"three nodes at 22% requested CPU"},
			AffectedResources:   []types.ResourceRef{{Kind: "Node", Name: "ip-10-0-1-17"}},
			DollarImpactMonthly: dollars,
			PriceBasis:          types.PricePriced,
		}},
		Summary: types.Summary{
			TotalFindings:       1,
			BySeverity:          map[types.Severity]int{types.SeverityHigh: 1},
			ByCategory:          map[types.Category]int{types.CategoryCost: 1},
			EstimatedSavingsUSD: dollars,
		},
		Architecture: &types.Architecture{
			UnpricedNodeTypes:      []string{"m9i.metal"},
			UnpricedStorageClasses: []string{"acme-fast"},
		},
		Methodology: types.Methodology{
			CollectedKinds: []string{"nodes", "deployments"},
			RunBasis: &types.RunBasis{
				ClusterUID:    "5f2c9e18-aaaa-4bbb-8ccc-1d2e3f4a5b6c",
				EngineVersion: "0.3.0",
				DataVersions: map[string]types.DataVersion{
					"pricing": {Version: pricingVersion, Source: source},
				},
			},
		},
	}
}

func refdataDeps() map[string]Deps {
	return map[string]Deps{
		"k8s.cost.node-headroom": {
			Kinds: []string{"nodes"},
			// Pricing supplies a DERIVED VALUE: the finding fires either way, with or without a figure.
			Datasets: []DatasetDep{{Name: "pricing", Presence: false}},
		},
	}
}

// THE CAVEAT MUST SURVIVE INTO THE REPORT. A gate that withholds a number and does not tell the renderer why
// produces a bare blank, which reads as "nothing" rather than "not compared" — the exact failure the whole
// design refuses.
func TestToTrendDelta_CarriesTheWithholdingAndItsReason(t *testing.T) {
	d := Compute(refdataReport("2026-06", "embedded", 441.13), refdataReport("2026-08", "bundle", 448.02), refdataDeps())
	td := d.ToTrendDelta()
	if td == nil {
		t.Fatal("no TrendDelta was projected")
	}
	if len(td.ReferenceDataChanged) != 1 || td.ReferenceDataChanged[0] != "pricing" {
		t.Errorf("TrendDelta.ReferenceDataChanged = %v, want [pricing]", td.ReferenceDataChanged)
	}
	if !strings.Contains(td.ReferenceDataReason, "our table changed, not your cluster") {
		t.Errorf("the reason did not reach the renderer: %q", td.ReferenceDataReason)
	}
	if td.SavingsDelta != 0 {
		t.Errorf("TrendDelta.SavingsDelta = %.2f, want 0 (withheld)", td.SavingsDelta)
	}

	// NON-VACUITY: the zero value must mean "no caveat", so a comparison with equal versions carries neither
	// field. That is the field-polarity discipline — permissive field, restrictive computation.
	clean := Compute(refdataReport("2026-08", "embedded", 441.13), refdataReport("2026-08", "bundle", 448.02), refdataDeps()).ToTrendDelta()
	if clean == nil {
		t.Fatal("no TrendDelta for the clean comparison")
	}
	if len(clean.ReferenceDataChanged) != 0 || clean.ReferenceDataReason != "" {
		t.Errorf("an unmoved table produced a caveat: %v / %q", clean.ReferenceDataChanged, clean.ReferenceDataReason)
	}
	if clean.SavingsDelta == 0 {
		t.Error("the clean comparison also withheld, so this test proves nothing")
	}
}
