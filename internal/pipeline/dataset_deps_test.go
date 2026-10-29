package pipeline

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// EVERY PRODUCER THAT CAN CARRY A DOLLAR MUST DECLARE THE PRICING DATASET.
//
// Gate 3 only fires for a producer whose Deps name the dataset. So a rule that emits a dollar figure and does
// not declare `pricing` gets its figure compared across a table refresh — the defect, intact, for that one
// rule. A hand-maintained table would drift into exactly that, which is this project's most repeated failure
// shape.
//
// So the table is DERIVED FROM THE GOLDEN FIXTURE, not from memory: every rule that produced a
// DollarImpactMonthly in the shipped document must appear. The fixture-drift gate
// (TestFixture_EveryRuleEitherFiresOrIsExcusedByName) keeps that document representative, which is what makes
// this assertion worth anything — the two gates hold each other up.
func TestDatasetDeps_EveryDollarBearingProducerDeclaresPricing(t *testing.T) {
	ar := personaReport(t)
	deps := HistoryDeps()

	var undeclared []string
	dollarBearing := 0
	for _, f := range ar.Findings {
		if f.DollarImpactMonthly == 0 {
			continue
		}
		dollarBearing++
		if !declares(deps[f.RuleID], "pricing") {
			undeclared = append(undeclared, f.RuleID)
		}
	}
	sort.Strings(undeclared)
	undeclared = dedupe(undeclared)

	if len(undeclared) > 0 {
		t.Errorf("%d producer(s) emit a dollar figure and do not declare the pricing dataset:\n  %s\n\n"+
			"Gate 3 only disarms a value comparison for a producer whose Deps name the dataset, so each of "+
			"these has its figure compared across a table refresh — the defect intact, for that rule. Add them "+
			"to datasetDepsByProducer.", len(undeclared), strings.Join(undeclared, "\n  "))
	}

	// NON-VACUITY: the fixture must actually contain dollar-bearing findings, or "none undeclared" is true
	// because there was nothing to declare.
	if dollarBearing == 0 {
		t.Fatal("no finding in the golden fixture carries a dollar figure, so this test measured nothing")
	}
	t.Logf("%d dollar-bearing finding(s) in the fixture, all declared", dollarBearing)
}

// A DATASET NAME MUST BE ONE THE REGISTRY KNOWS. A dep naming "princing" would never match a stamp, so the
// gate would silently never fire for that producer — a typo that reads as working code.
func TestDatasetDeps_EveryDeclaredNameIsInTheRegistry(t *testing.T) {
	known := map[string]bool{}
	for _, n := range refdata.Datasets() {
		known[n] = true
	}
	if len(known) == 0 {
		t.Fatal("the registry is empty")
	}
	declared := 0
	for id, d := range HistoryDeps() {
		for _, dep := range d.Datasets {
			declared++
			if !known[dep.Name] {
				t.Errorf("%s declares the dataset %q, which the registry does not hold. The stamp would never "+
					"match it and Gate 3 would silently never fire for this producer.", id, dep.Name)
			}
		}
	}
	if declared == 0 {
		t.Fatal("no producer declares any dataset, so Gate 3 can never fire and this test measured nothing")
	}
	t.Logf("%d dataset declaration(s) across the registry", declared)
}

// PRICING IS A VALUE DATASET, NOT A PRESENCE ONE, and the difference is provable from the existing tests:
// gates_test.go asserts pricing coverage never changes WHICH findings appear. A Presence:true on pricing would
// move every cost finding to NotEvaluated on the first refresh — withholding the whole comparison to protect
// one number.
func TestDatasetDeps_PricingIsDeclaredAsAValueDataset(t *testing.T) {
	found := false
	for id, d := range HistoryDeps() {
		for _, dep := range d.Datasets {
			if dep.Name != "pricing" {
				continue
			}
			found = true
			if dep.Presence {
				t.Errorf("%s declares pricing as a PRESENCE dataset. A price table does not decide whether a "+
					"finding exists — the finding fires with or without a figure — and Presence:true would move "+
					"every cost finding to NotEvaluated on the first table refresh.", id)
			}
		}
	}
	if !found {
		t.Fatal("no producer declares pricing at all")
	}
}

func declares(d history.Deps, name string) bool {
	for _, dep := range d.Datasets {
		if dep.Name == name {
			return true
		}
	}
	return false
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// THE STATIC HALF: every rule defined in a file that can assign a dollar must declare pricing.
//
// The fixture-derived test above sees only the 25 rules the persona makes fire. Nineteen cannot fire on it —
// k8s.cost.unattached-volume among them, a COST rule — so a fixture-only assertion would have left them
// uncovered while reading as complete.
//
// Coarse on purpose: it asks about the FILE, so a file holding several rules requires all of them. Over-
// declaration disarms a comparison that would never have fired; under-declaration lets a table refresh be
// reported as the customer's change. The coarseness is in the safe direction.
func TestDatasetDeps_EveryRuleThatCanCarryADollarIsListed(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "rules", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rule files found (%v)", err)
	}
	deps := HistoryDeps()
	idRe := regexp.MustCompile(`return "(k8s\.[a-z0-9.-]+)"`)

	scanned, dollarFiles, checked := 0, 0, 0
	var undeclared []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		if !strings.Contains(string(b), "DollarImpactMonthly:") {
			continue
		}
		dollarFiles++
		for _, m := range idRe.FindAllStringSubmatch(string(b), -1) {
			id := m[1]
			if _, ok := deps[id]; !ok {
				continue // not a registered producer (a helper's string, or a rule not in All())
			}
			checked++
			if !declares(deps[id], "pricing") {
				undeclared = append(undeclared, id+"  (defined in "+filepath.Base(f)+")")
			}
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("%d rule(s) live in a file that assigns DollarImpactMonthly and do not declare pricing:\n  %s",
			len(undeclared), strings.Join(dedupe(undeclared), "\n  "))
	}

	// NON-VACUITY, three ways. No files scanned, no dollar-assigning files found, or no registered rule in
	// them would each make "none undeclared" true for a reason that has nothing to do with the property.
	if scanned < 10 {
		t.Fatalf("only %d rule file(s) scanned", scanned)
	}
	if dollarFiles == 0 {
		t.Fatal("no rule file assigns DollarImpactMonthly, so this scan measured nothing")
	}
	if checked == 0 {
		t.Fatal("no registered rule was found in a dollar-assigning file")
	}
	t.Logf("%d rule file(s) scanned, %d can assign a dollar, %d registered rule(s) in them", scanned, dollarFiles, checked)
}

// Deadline-calendar spec §6 test 3. Two readings of one cluster; the version-support finding is present only in
// the second. When the two readings used different versions of the support-window table, the finding is withheld
// as NotEvaluated with a reason naming the table and both versions — never announced as new, because a refreshed
// table can make it appear with the cluster untouched. Equal versions put it in NewInSet, which is what proves the
// gate is selective rather than switched off.
func TestCalendar_ADatasetRefreshDoesNotAnnounceANewDeadline(t *testing.T) {
	mk := func(kubeversionsStamp string, findings []types.Finding) *types.AuditReport {
		ar := &types.AuditReport{
			SchemaVersion: "v1", GeneratedAt: time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC),
			Cluster:  types.ClusterInfo{Name: "Acme Pay / EKS:prod", Provider: "aws"},
			Findings: findings,
			Methodology: types.Methodology{
				CollectedKinds: []string{"nodes"},
				RunBasis: &types.RunBasis{ClusterUID: "uid-1", EngineVersion: "0.19.0", DataVersions: map[string]types.DataVersion{
					"pricing":      {Version: "2026-08", Source: "embedded"},
					"kubeversions": {Version: kubeversionsStamp, Source: "embedded"},
				}},
			},
		}
		ar.Summary = types.DeriveSummary(findings)
		return ar
	}
	f := types.Finding{
		ID: "f-ver", RuleID: "k8s.cost.kubernetes-version-past-standard-support", RuleVersion: "1.0.0",
		Title: "Kubernetes 1.31 is past aws's ordinary support window", Severity: types.SeverityMedium,
		Category: types.CategoryCost, Confidence: 1, EstimatedEffort: types.EffortHigh, Evidence: []string{"e"},
		AffectedResources: []types.ResourceRef{{Kind: "Cluster", Name: "1.31"}}, DollarImpactMonthly: 43.8, PriceBasis: types.PricePriced,
	}

	d := history.Compute(mk("2026-06-30", nil), mk("2026-08-31", []types.Finding{f}), HistoryDeps())
	for _, n := range d.NewInSet {
		if n.ID == "f-ver" {
			t.Fatal("a refreshed support-window table announced the version finding as new")
		}
	}
	var reason string
	for _, u := range d.NotEvaluated {
		if u.Finding.ID == "f-ver" {
			reason = u.Reason
		}
	}
	if reason == "" {
		t.Fatalf("the version finding is not in NotEvaluated; new=%d notEvaluated=%d", len(d.NewInSet), len(d.NotEvaluated))
	}
	for _, want := range []string{"kubeversions", "2026-06-30", "2026-08-31"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the reason does not name %q: %q", want, reason)
		}
	}

	// Non-vacuity: with equal table versions the same finding is genuinely new.
	same := history.Compute(mk("2026-08-31", nil), mk("2026-08-31", []types.Finding{f}), HistoryDeps())
	found := false
	for _, n := range same.NewInSet {
		found = found || n.ID == "f-ver"
	}
	if !found {
		t.Fatalf("with equal table versions the finding is not in NewInSet; the gate is not selective (new=%d notEvaluated=%d)", len(same.NewInSet), len(same.NotEvaluated))
	}
}
