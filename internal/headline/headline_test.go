package headline

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// headline_test.go — the guards. The SELECTION is product judgment and lives in `claims`; these assert the
// properties that must hold whatever that table says.

func at() time.Time { return time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC) }

func f(id, rule string, sev types.Severity, refs ...types.ResourceRef) types.Finding {
	return types.Finding{ID: id, RuleID: rule, RuleVersion: "1.0.0", Title: "t " + id, Severity: sev,
		Category: types.CategoryReliability, Confidence: 1, EstimatedEffort: types.EffortLow,
		Evidence:          []string{"Snapshot taken at 2026-09-04T09:00:00Z.", "the budget allows 0 of 3; nothing else"},
		AffectedResources: refs}
}

func node(name string) types.ResourceRef { return types.ResourceRef{Kind: "Node", Name: name} }

// rich is a reading with something to say in every claim kind — more than five, so the cap is exercised.
func rich() *types.AuditReport {
	ar := &types.AuditReport{
		SchemaVersion: "v1", GeneratedAt: at(),
		Cluster: types.ClusterInfo{Name: "acme-pay-prod"},
		Findings: []types.Finding{
			f("f-drain1", "k8s.reliability.node-drain-budget", types.SeverityHigh, node("node-a")),
			f("f-drain2", "k8s.reliability.node-pinned-volume", types.SeverityHigh, node("node-b")),
			f("f-hpa", "k8s.config.hpa-target-unresolved", types.SeverityMedium,
				types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: "payments", Name: "api"}),
			f("f-ing", "k8s.config.ingress-backend-unresolved", types.SeverityMedium,
				types.ResourceRef{Kind: "Ingress", Namespace: "payments", Name: "web"}),
			func() types.Finding {
				m := f("f-mon", "stack.monitoring.alert-route-receiver-missing", types.SeverityHigh,
					types.ResourceRef{Kind: "Alertmanager", Namespace: "monitoring", Name: "main"})
				m.Pillar = types.PillarObservability
				m.Evidence = []string{"route team=payments names receiver pd-payments, which no receiver defines"}
				return m
			}(),
			func() types.Finding {
				c := f("f-cost", "k8s.cost.idle-loadbalancer", types.SeverityLow,
					types.ResourceRef{Kind: "Service", Namespace: "payments", Name: "lb"})
				c.DollarImpactMonthly = 1647.25
				c.PriceBasis = types.PricePriced
				c.Category = types.CategoryCost
				return c
			}(),
			f("f-other1", "k8s.workload.runs-as-root", types.SeverityLow),
			f("f-other2", "k8s.workload.no-probes", types.SeverityLow),
		},
		Architecture: &types.Architecture{NodePools: []types.NodePoolSummary{{Type: "m6i.xlarge", Count: 12, UnknownCapCount: 12}}},
		Calendar: &types.Calendar{Rows: []types.CalendarRow{
			{Date: "2026-11-26", Kind: types.CalendarRowDataset, Dataset: "kubeversions", DatasetVersion: "2026-08-31",
				DatasetSource: "embedded", Observation: "ordinary support for Kubernetes 1.31 on aws ends 2026-11-26"},
			{Date: "2026-10-01", Kind: types.CalendarRowObject, Field: "status.notAfter",
				Object:      &types.ResourceRef{Kind: "Certificate", Namespace: "payments", Name: "tls"},
				Observation: "Certificate payments/tls reports status.notAfter = 2026-10-01", FindingIDs: []string{"f-cert"}},
		}},
		Methodology: types.Methodology{
			CollectedKinds:   []string{"pods", "nodes"},
			DeniedKinds:      []string{"networkpolicies", "poddisruptionbudgets"},
			SessionTrace:     &types.SessionTrace{Total: 302, ObjectWrites: 0},
			UsageMethodology: &types.UsageMethodology{Source: "prometheus", Window: "7d"},
		},
	}
	ar.Summary = types.DeriveSummary(ar.Findings)
	return ar
}

// At most five claims, each with a basis, then the remainder, then the reading's own cost.
func TestSelect_ShapeAndCap(t *testing.T) {
	h := Select(rich())
	if len(h.Lines) > MaxLines {
		t.Fatalf("%d claims, cap is %d", len(h.Lines), MaxLines)
	}
	if len(h.Lines) != MaxLines {
		t.Fatalf("the fixture has more than five kinds to say; got %d: %v", len(h.Lines), kinds(h))
	}
	for _, l := range h.Lines {
		if strings.TrimSpace(l.Claim) == "" || strings.TrimSpace(l.Basis) == "" {
			t.Errorf("a line with no claim or no basis: %+v", l)
		}
		if l.Kind == "" {
			t.Errorf("a line with no kind: %+v", l)
		}
	}
	if h.Remainder == "" {
		t.Error("findings were left out and the remainder is not stated")
	}
	if !strings.Contains(h.Trace, "302 reads") || !strings.Contains(h.Trace, "0 object writes") || !strings.Contains(h.Trace, "2 lists refused") {
		t.Errorf("the reading's own cost is wrong: %q", h.Trace)
	}
	// The cheapest possible mistake: the remainder counting the findings a claim already accounted for.
	if h.Shown <= 0 || h.Shown > h.Total {
		t.Errorf("shown=%d of total=%d", h.Shown, h.Total)
	}
	if !strings.Contains(h.Remainder, "more in the document") {
		t.Errorf("remainder: %q", h.Remainder)
	}
}

// THE ORDER IS THE PRODUCT'S ARGUMENT. Feasibility leads; money never does, because it is the figure most
// likely to be honestly zero on a first run.
func TestSelect_SpecificityLeadsAndMoneyDoesNot(t *testing.T) {
	h := Select(rich())
	if h.Lines[0].Kind != "drain-feasibility" {
		t.Errorf("the opening is %q; the sentence nothing else in the market makes should lead", h.Lines[0].Kind)
	}
	for i, l := range h.Lines {
		if l.Kind == "identified-dollars" && i == 0 {
			t.Error("money leads the headline")
		}
	}
	// And the table's order is the rendered order.
	var want []string
	for _, c := range claims {
		want = append(want, c.kind)
	}
	var got []string
	for _, l := range h.Lines {
		got = append(got, l.Kind)
	}
	j := 0
	for _, k := range want {
		if j < len(got) && got[j] == k {
			j++
		}
	}
	if j != len(got) {
		t.Errorf("the rendered order %v is not a subsequence of the table's %v", got, want)
	}
}

// NO DOLLAR THE RULES DID NOT BANK, and the money line carries the measurement it rests on.
func TestSelect_MoneyIsTheBankedFigureWithItsBasis(t *testing.T) {
	ar := rich()
	h := Select(ar)
	var money *Line
	for i := range h.Lines {
		if h.Lines[i].Kind == "identified-dollars" {
			money = &h.Lines[i]
		}
	}
	if money == nil {
		t.Skip("the fixture's five kinds crowded money out; the guard below still applies where it appears")
	}
	if !strings.Contains(money.Claim, "1,647") {
		t.Errorf("the figure is not the summary's: %q vs %.2f", money.Claim, ar.Summary.EstimatedSavingsUSD)
	}
	for _, want := range []string{"list price", "upper bound"} {
		if !strings.Contains(money.Basis, want) {
			t.Errorf("the money basis lacks %q: %q", want, money.Basis)
		}
	}
	// The fixture's only dollar is an idle load balancer's — a list price, not a measurement — so the line names
	// no usage window although the reading has one. See TestSelect_TheMoneyBasisIsTheBasisOfTheDollarsInIt.
	if strings.Contains(money.Basis, "prometheus") {
		t.Errorf("a list-price dollar was attributed to the usage source: %q", money.Basis)
	}
	// A reading with no banked dollars prints no money line at all rather than a zero.
	poor := rich()
	for i := range poor.Findings {
		poor.Findings[i].DollarImpactMonthly = 0
	}
	poor.Summary = types.DeriveSummary(poor.Findings)
	for _, l := range Select(poor).Lines {
		if l.Kind == "identified-dollars" {
			t.Errorf("a reading with no banked dollars printed %q", l.Claim)
		}
	}
}

// A claim appears only when the reading supports it. An empty reading says nothing but its own cost.
func TestSelect_SaysNothingItCannotSupport(t *testing.T) {
	empty := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at(),
		Methodology: types.Methodology{SessionTrace: &types.SessionTrace{Total: 8}}}
	empty.Summary = types.DeriveSummary(nil)
	h := Select(empty)
	if len(h.Lines) != 0 {
		t.Errorf("a reading with no findings produced %d claim(s): %v", len(h.Lines), kinds(h))
	}
	if h.Remainder != "" {
		t.Errorf("nothing was left out, yet the remainder says %q", h.Remainder)
	}
	if !strings.Contains(h.Trace, "8 reads") {
		t.Errorf("trace: %q", h.Trace)
	}
	// A reading with no trace says so rather than printing zeroes.
	empty.Methodology.SessionTrace = nil
	if got := Select(empty).Trace; !strings.Contains(got, "no session trace") {
		t.Errorf("a reading without a trace printed %q", got)
	}
}

// A dated obligation must be inside the horizon and must not have passed: a date already behind the reading is
// not an obligation "inside 90 days".
func TestSelect_DatedObligationIsAheadAndInsideTheHorizon(t *testing.T) {
	ar := rich()
	// Both rows far away: no claim.
	ar.Calendar.Rows = []types.CalendarRow{{Date: "2027-06-01", Kind: types.CalendarRowDataset,
		Dataset: "kubeversions", DatasetVersion: "2026-08-31", DatasetSource: "embedded", Observation: "far"}}
	for _, l := range Select(ar).Lines {
		if l.Kind == "dated-obligation" {
			t.Errorf("a date 9 months out was called an obligation inside %d days: %q", horizonDays, l.Claim)
		}
	}
	// A date already passed: not ahead.
	ar.Calendar.Rows = []types.CalendarRow{{Date: "2026-06-01", Passed: true, Kind: types.CalendarRowDataset,
		Dataset: "kubeversions", DatasetVersion: "2026-08-31", DatasetSource: "embedded", Observation: "behind"}}
	for _, l := range Select(ar).Lines {
		if l.Kind == "dated-obligation" {
			t.Errorf("a passed date was called an obligation ahead: %q", l.Claim)
		}
	}
	// Inside: claimed, with the row's own source in the basis.
	ar.Calendar.Rows = []types.CalendarRow{{Date: "2026-10-01", Kind: types.CalendarRowObject, Field: "status.notAfter",
		Object: &types.ResourceRef{Kind: "Certificate", Namespace: "payments", Name: "tls"}, Observation: "soon"}}
	var found bool
	for _, l := range Select(ar).Lines {
		if l.Kind == "dated-obligation" {
			found = true
			if !strings.Contains(l.Basis, "2026-10-01") || !strings.Contains(l.Basis, "status.notAfter") {
				t.Errorf("the basis does not name the date and the field it was read from: %q", l.Basis)
			}
		}
	}
	if !found {
		t.Error("a certificate expiring in under a month is not an obligation inside 90 days")
	}
}

// The headline's own sentences carry no banned claim. Findings' titles are the report's data and are governed
// where they are written; this scans what this package composes.
func TestSelect_CopyIsClean(t *testing.T) {
	h := Select(rich())
	var all []string
	for _, l := range h.Lines {
		all = append(all, l.Claim, l.Basis)
	}
	all = append(all, h.Remainder, h.Trace)
	text := strings.ToLower(strings.Join(all, "\n"))
	sections := func(s lexicon.Scope) (string, bool) {
		if s == lexicon.ScopeComparison {
			// A headline is one reading; the comparison words have no honest use in it.
			return text, true
		}
		return "", true
	}
	if un := lexicon.UnmappedScopes(sections); len(un) != 0 {
		t.Fatalf("scopes unmapped: %v", un)
	}
	for _, v := range lexicon.Scan(text, sections) {
		t.Errorf("banned: %s", v.Detail())
	}
	// And the two sentences this product refuses outright.
	for _, banned := range []string{"you are not monitoring", "your alerts do not work", "guaranteed"} {
		if strings.Contains(text, banned) {
			t.Errorf("the headline says %q", banned)
		}
	}
}

// Text is what a terminal prints: claim, basis indented, then the remainder and the cost.
func TestText_PairsEachClaimWithItsBasis(t *testing.T) {
	h := Select(rich())
	lines := Text(h)
	if len(lines) != len(h.Lines)*2+2 {
		t.Fatalf("%d lines for %d claims + remainder + trace", len(lines), len(h.Lines))
	}
	for i, l := range h.Lines {
		if lines[i*2] != l.Claim {
			t.Errorf("line %d is %q, want the claim %q", i*2, lines[i*2], l.Claim)
		}
		if !strings.HasPrefix(lines[i*2+1], "    ") || !strings.Contains(lines[i*2+1], l.Basis) {
			t.Errorf("the basis under claim %d is %q", i, lines[i*2+1])
		}
	}
}

func kinds(h Headline) []string {
	var out []string
	for _, l := range h.Lines {
		out = append(out, l.Kind)
	}
	return out
}

// THE OPENING LEADS ALL THREE SURFACES, SO ITS ARITHMETIC HAS TO BE THE DOCUMENT'S.
//
// Select derives Total from len(ar.Findings) while every rendered section counts Summary.TotalFindings.
// AuditReport.Validate refuses a report where those two disagree, which is what makes the opening's "N more in
// the document" trustworthy — but nothing on THIS side of the seam said so, and a future Select that counted
// something else (findings above a severity floor, say, or the collapsed set) would drift from the document it
// introduces without a single test objecting.
//
// The two figures a reader can check against the rest of the document are the count and the money, so both are
// pinned: Total against the validated summary, and the money claim against Summary.EstimatedSavingsUSD — the
// same field the cover prints.
func TestSelect_ReconcilesWithTheSummaryTheDocumentPrints(t *testing.T) {
	ar := rich()
	ar.Summary = types.DeriveSummary(ar.Findings)

	h := Select(ar)

	if h.Total != ar.Summary.TotalFindings {
		t.Errorf("the opening counts %d findings and the document's summary counts %d — the remainder line "+
			"then names a number no section agrees with", h.Total, ar.Summary.TotalFindings)
	}
	if got := h.Shown + countRemainder(t, h); got != h.Total {
		t.Errorf("shown (%d) plus the remainder (%d) is %d, not the total %d: the opening accounts for a "+
			"different reading than the one it introduces", h.Shown, got-h.Shown, got, h.Total)
	}

	// And the money, when it is claimed at all, is the cover's own figure.
	var money string
	for _, l := range h.Lines {
		if l.Kind == "identified-dollars" {
			money = l.Claim
		}
	}
	switch {
	case ar.Summary.EstimatedSavingsUSD > 0 && money == "":
		// Not necessarily a defect — the cap may have spent all five lines on more specific claims — but the
		// remainder then has to be what carries it, and that is the property above.
		if h.Remainder == "" {
			t.Error("the summary banks a dollar figure, the opening claims none, and nothing says anything " +
				"was left out")
		}
	case money != "":
		want := "$" + thousands(ar.Summary.EstimatedSavingsUSD) + "/mo identified"
		if money != want {
			t.Errorf("the opening claims %q and the summary banks %.2f (%q) — two figures for one quantity, "+
				"on two surfaces of one reading", money, ar.Summary.EstimatedSavingsUSD, want)
		}
	}
}

// countRemainder reads the number back out of the remainder sentence, because that sentence is what a reader
// actually sees; asserting on h.Total-h.Shown would check the subtraction against itself.
func countRemainder(t *testing.T, h Headline) int {
	t.Helper()
	if h.Remainder == "" {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(h.Remainder, "%d more in the document", &n); err != nil {
		t.Fatalf("the remainder sentence %q does not begin with a count, so nothing in the opening states "+
			"what it left out", h.Remainder)
	}
	return n
}

// A DISCOUNTED FIGURE IS NOT A LIST PRICE.
//
// `--discount 0.3` on the mesh testbed printed "$63/mo identified · prometheus over 6h · list price · upper bound
// if consolidated": the figure was 70% of list and the line beside it said list. The discount is part of the price
// basis, so the line names it.
func TestSelect_ADiscountedFigureSaysSo(t *testing.T) {
	cost := f("f-rs", "k8s.cost.overprovisioned-resources", types.SeverityMedium, node("node-a"))
	cost.Category = types.CategoryCost
	cost.DollarImpactMonthly = 63.22
	cost.PriceBasis = types.PricePriced
	ar := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at(), Findings: []types.Finding{cost},
		Methodology: types.Methodology{UsageMethodology: &types.UsageMethodology{Source: "prometheus", Window: "6h"}}}
	ar.Summary = types.DeriveSummary(ar.Findings)
	money := func(h Headline) string {
		for _, l := range h.Lines {
			if l.Kind == "identified-dollars" {
				return l.Basis
			}
		}
		t.Fatal("no money line on a reading whose only claim is money")
		return ""
	}
	if b := money(SelectWith(ar, Options{ComputeDiscount: 0.3})); !strings.Contains(b, "list price less 30% on compute") {
		t.Errorf("a discounted figure is still called a list price: %q", b)
	}
	if b := money(Select(ar)); strings.Contains(b, "less") {
		t.Errorf("an undiscounted reading names a discount: %q", b)
	}
}

// THE MONEY LINE'S BASIS IS THE BASIS OF THE DOLLARS IN IT.
//
// On the mesh testbed the line read "$90/mo identified · prometheus over 6h · list price · upper bound if
// consolidated", and $42 of the $90 was an instance-family list-price delta that rests on no measurement and has
// nothing to consolidate. The usage window is named only for the dollars that rest on it, with their share when
// they are not all of it.
func TestSelect_TheMoneyBasisIsTheBasisOfTheDollarsInIt(t *testing.T) {
	usage := &types.UsageMethodology{Source: "prometheus", Window: "6h"}
	money := func(ar *types.AuditReport) string {
		ar.Summary = types.DeriveSummary(ar.Findings)
		for _, l := range Select(ar).Lines {
			if l.Kind == "identified-dollars" {
				return l.Basis
			}
		}
		t.Fatal("no money line")
		return ""
	}
	priced := func(id, rule string, usd float64, usageBacked bool) types.Finding {
		x := f(id, rule, types.SeverityLow, node("node-a"))
		x.Category = types.CategoryCost
		x.DollarImpactMonthly = usd
		x.PriceBasis = types.PricePriced
		if usageBacked {
			x.Basis = &types.FindingBasis{UsageRequired: true, UsageSource: "prometheus"}
		}
		return x
	}
	listOnly := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at(),
		Findings:    []types.Finding{priced("f-lag", "k8s.cost.instance-generation-lag", 42, false)},
		Methodology: types.Methodology{UsageMethodology: usage}}
	if b := money(listOnly); strings.Contains(b, "prometheus") || strings.Contains(b, "consolidated") {
		t.Errorf("a list-price delta is described as a usage measurement: %q", b)
	}
	mixed := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at(),
		Findings: []types.Finding{priced("f-lag", "k8s.cost.instance-generation-lag", 42, false),
			priced("f-rs", "k8s.cost.overprovisioned-resources", 48, true)},
		Methodology: types.Methodology{UsageMethodology: usage}}
	if b := money(mixed); !strings.Contains(b, "$48") || !strings.Contains(b, "prometheus over 6h") {
		t.Errorf("the usage-backed share is not named with its basis: %q", b)
	}
	allUsage := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at(),
		Findings:    []types.Finding{priced("f-rs", "k8s.cost.overprovisioned-resources", 48, true)},
		Methodology: types.Methodology{UsageMethodology: usage}}
	if b := money(allUsage); !strings.HasPrefix(b, "prometheus over 6h") || !strings.Contains(b, "if consolidated") {
		t.Errorf("an all-usage figure lost its basis: %q", b)
	}
}
