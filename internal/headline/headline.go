// Package headline picks at most five sentences a stranger should read first.
//
// THE PROBLEM IT SOLVES. A first run on a real cluster produces between 1,300 and 2,100 findings, and 84.7% of
// them come from ten rules. The judgment layer already ranks and already picks a safest place to start, but
// what a stranger meets is still volume. This picks the few claims that are ABOUT THIS CLUSTER and that no
// other tool in the market makes, and states the rest as one line rather than hiding it.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// THE SELECTION CRITERION IS PRODUCT JUDGMENT, AND IT LIVES IN ONE TABLE: `claims`, below.
//
// SPECIFICITY BEATS SEVERITY here, deliberately. Twelve critical "container runs as root" findings are true,
// severe, and say nothing about this cluster that a linter would not say about any cluster. "Four nodes cannot
// be evacuated without force-deleting a Postgres primary" is a sentence about THIS cluster that nothing else
// in the field produces. The table is ordered by that judgment and by nothing computed, so changing the
// product's opening argument is an edit to one list rather than a change to a ranking function.
//
// To reorder the opening: move entries in `claims`. To add one: add an entry with its own phrasing and basis.
// Nothing else in this package needs to change, and the guards below apply to whatever the table holds.
// ─────────────────────────────────────────────────────────────────────────────────────────────────────────
//
// THE GUARDS, each asserted in headline_test.go:
//
//   - NO FIGURE WITHOUT ITS BASIS. Every line carries where its number came from, in the same breath.
//   - NO DOLLAR THE RULES DID NOT BANK. The money line is Summary.EstimatedSavingsUSD — the figure
//     validate.go already forces to reconcile with the findings — or it is absent.
//   - THE REMAINDER IS STATED, NEVER HIDDEN. Everything not shown is one line with a count.
//   - AT MOST FIVE CLAIMS. A sixth is the document's job.
//   - THE READING'S OWN COST IS ALWAYS LAST: requests, object writes, and what was refused.
package headline

import (
	"fmt"
	"strings"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Line and Headline are the schema's own types: the selection travels ON the report so the terminal, the
// document and the app render one selection rather than three that can disagree.
type Line = types.HeadlineLine

// Headline is what the three surfaces render.
type Headline = types.Headline

// MaxLines is the cap. Five is the number a stranger reads before deciding whether to keep reading.
const MaxLines = 5

// horizonDays is how far ahead a dated obligation counts as "soon" for the opening. A quarter: near enough to
// act on, far enough that a monthly reader sees it before it passes.
const horizonDays = 90

// claim is one candidate sentence.
type claim struct {
	// kind names it. Stable: tests and surfaces refer to these.
	kind string
	// build returns the line, or ok=false when this reading gives no honest sentence of this kind.
	build func(*types.AuditReport) (Line, bool)
	// buildWith, when set, is used instead of build: the claims whose sentence depends on how the reading was
	// priced (the money line, under a compute discount) read the Options.
	buildWith func(*types.AuditReport, Options) (Line, bool)
}

// Options is what a headline needs to know about a reading that the reading itself does not record.
type Options struct {
	// ComputeDiscount is the fraction the reading's compute dollars were discounted by (--discount), in [0, 0.9].
	// The figures carry it already; the money line's basis has to say it, or a discounted figure reads as list.
	ComputeDiscount float64
}

// claims is THE ORDER THE PRODUCT LEADS WITH. Most specific first. See the package comment.
var claims = []claim{
	// 0. What could not be read, when MOST of it could not. It outranks every finding because it bounds all of
	//    them: through an RBAC role that listed four kinds of twenty-eight, the opening led with a capacity
	//    line and the refusal was the trace's last clause — the shape of a nearly clean cluster. A smaller gap
	//    (a denied networkpolicies list is common) stays in the trace and the cover's floor sentence, and does
	//    not displace the claim the reading is for.
	{kind: "coverage-gap", build: coverageGap},

	// 1. Feasibility. The sentence nothing else in the market produces: a node that cannot be evacuated, from
	//    published budgets and the placement model, before anyone types kubectl drain.
	{kind: "drain-feasibility", build: drainFeasibility},

	// 2. A dated obligation. A date answers "why now" without asserting anything, and it comes from an object
	//    field or a named dataset — never from an image tag.
	{kind: "dated-obligation", build: datedObligation},

	// 3. A name that resolves to nothing. A reference, not an opinion: an HPA pointing at a workload that is
	//    not there, an Ingress backend with no Service, a PDB selecting no pods. Nobody argues with these.
	{kind: "unresolved-reference", build: unresolvedReference},

	// 4. Monitoring coverage. The one component whose failure removes the thing that would report it, and the
	//    only pillar in this document nothing else in the field audits.
	{kind: "monitoring-coverage", build: monitoringCoverage},

	// 5. Capacity that could not be resolved. The strongest negative-space line in the product: the buyer
	//    cannot tell whether the bill is spot or on-demand, and it moves the whole cost conclusion.
	{kind: "capacity-unresolved", build: capacityUnresolved},

	// 6. Money, last of the claims and never first. It is the figure most likely to be zero on an honest
	//    first run, and leading with a number the engine may refuse would be the promise this product does
	//    not make.
	{kind: "identified-dollars", buildWith: identifiedDollars},
}

// Select builds the headline for one reading priced at list.
func Select(ar *types.AuditReport) Headline { return SelectWith(ar, Options{}) }

// SelectWith builds the headline for one reading, with what the reading does not record about itself.
func SelectWith(ar *types.AuditReport, opts Options) Headline {
	h := Headline{}
	if ar == nil {
		return h
	}
	h.Total = len(ar.Findings)
	counted := map[string]bool{}
	for _, c := range claims {
		if len(h.Lines) >= MaxLines {
			break
		}
		var line Line
		var ok bool
		if c.buildWith != nil {
			line, ok = c.buildWith(ar, opts)
		} else {
			line, ok = c.build(ar)
		}
		if !ok {
			continue
		}
		line.Kind = c.kind
		h.Lines = append(h.Lines, line)
		for _, id := range line.FindingIDs {
			counted[id] = true
		}
	}
	h.Shown = len(counted)
	if rest := h.Total - h.Shown; rest > 0 {
		h.Remainder = fmt.Sprintf("%d more in the document — every finding, with what each rests on", rest)
	}
	h.Trace = traceLine(ar)
	return h
}

// Text renders the headline as lines for a terminal: the claim, then its basis indented.
func Text(h Headline) []string {
	var out []string
	for _, l := range h.Lines {
		out = append(out, l.Claim, "    "+l.Basis)
	}
	if h.Remainder != "" {
		out = append(out, h.Remainder)
	}
	if h.Trace != "" {
		out = append(out, h.Trace)
	}
	return out
}

// ── the claims ───────────────────────────────────────────────────────────────────────────────────

// drainRules are the drain's stops — held to internal/preflight's DrainStopRules by internal/gatecheck. The
// unmanaged-pod rule was missing: the sample's opening said 4 nodes where its own preflight stops on 5.
var drainRules = map[string]bool{
	"k8s.reliability.node-drain-budget":        true,
	"k8s.reliability.node-drain-unmanaged-pod": true,
	"k8s.reliability.node-pinned-volume":       true,
	"k8s.reliability.node-loss-feasibility":    true,
}

// DrainRuleIDs are the rules whose findings make a node one that "cannot be evacuated" in a reading's opening —
// the drain's stops, which internal/gatecheck holds equal to internal/preflight's.
func DrainRuleIDs() []string {
	out := make([]string, 0, len(drainRules))
	for id := range drainRules {
		out = append(out, id)
	}
	return out
}

func drainFeasibility(ar *types.AuditReport) (Line, bool) {
	nodes := map[string]bool{}
	var ids []string
	var why string
	for _, f := range ar.Findings {
		if !drainRules[f.RuleID] {
			continue
		}
		ids = append(ids, f.ID)
		for _, r := range f.AffectedResources {
			if r.Kind == "Node" {
				nodes[r.Name] = true
			}
		}
		// The node-loss finding names its node in the title rather than in the refs (its refs are the
		// displaced pods), so one is counted through its own rule below.
		if f.RuleID == "k8s.reliability.node-loss-feasibility" {
			nodes[f.ID] = true
		}
		if why == "" {
			why = firstEvidenceClause(f)
		}
	}
	if len(nodes) == 0 {
		return Line{}, false
	}
	claim := fmt.Sprintf("%d node%s cannot be evacuated", len(nodes), plural(len(nodes)))
	basis := "drain feasibility · published disruption budgets and the placement model, read from this cluster"
	if why != "" {
		basis = "drain feasibility · " + why
	}
	return Line{Claim: claim, Basis: basis, FindingIDs: ids}, true
}

func datedObligation(ar *types.AuditReport) (Line, bool) {
	c := ar.Calendar
	if c == nil || len(c.Rows) == 0 {
		return Line{}, false
	}
	at := ar.GeneratedAt.UTC().Truncate(24 * time.Hour)
	horizon := at.AddDate(0, 0, horizonDays)
	var soon []types.CalendarRow
	for _, r := range c.Rows {
		d, ok := types.ParseCalendarDay(r.Date)
		if !ok || r.Passed {
			continue
		}
		if !d.After(horizon) {
			soon = append(soon, r)
		}
	}
	if len(soon) == 0 {
		return Line{}, false
	}
	first := soon[0]
	claim := fmt.Sprintf("%d dated obligation%s inside %d days", len(soon), plural(len(soon)), horizonDays)
	basis := first.Date + " · "
	if first.Object != nil {
		basis += fmt.Sprintf("%s %s · %s", first.Object.Kind, nameOf(*first.Object), first.Field)
	} else {
		basis += fmt.Sprintf("dataset %s %s · %s", first.Dataset, first.DatasetVersion, first.DatasetSource)
	}
	var ids []string
	for _, r := range soon {
		ids = append(ids, r.FindingIDs...)
	}
	return Line{Claim: claim, Basis: basis, FindingIDs: ids}, true
}

// unresolvedRules are the rules whose finding is a name that resolves to nothing in the reading. Every registered
// rule whose id ends in -unresolved belongs here — internal/gatecheck holds the list to the registry, because six
// of eleven were counted until a review added the sample's findings up by hand.
var unresolvedRules = map[string]string{
	"k8s.config.hpa-target-unresolved":           "an autoscaler points at a workload that is not there",
	"k8s.config.ingress-backend-unresolved":      "an Ingress backend names a Service that is not there",
	"k8s.config.governing-service-unresolved":    "a StatefulSet names a governing Service that is not there",
	"k8s.config.pdb-selects-no-pods":             "a disruption budget selects nothing",
	"k8s.config.ingressclass-unresolved":         "an Ingress names a class that is not there",
	"k8s.config.priorityclass-unresolved":        "a workload names a PriorityClass that is not there",
	"k8s.config.serviceaccount-unresolved":       "a workload runs as a ServiceAccount that is not there",
	"k8s.config.storageclass-unresolved":         "a claim names a StorageClass that is not there",
	"k8s.rbac.roleref-unresolved":                "a binding grants a role that is not there",
	"k8s.rbac.binding-subject-unresolved":        "a binding grants to a ServiceAccount that is not there",
	"k8s.reliability.service-no-ready-endpoints": "a Service publishes no ready address",
}

// UnresolvedRuleIDs are the rules the "N references point at nothing" claim counts, for the gate that holds them to
// the registry.
func UnresolvedRuleIDs() []string {
	out := make([]string, 0, len(unresolvedRules))
	for id := range unresolvedRules {
		out = append(out, id)
	}
	return out
}

func unresolvedReference(ar *types.AuditReport) (Line, bool) {
	var ids []string
	var first string
	for _, f := range ar.Findings {
		what, ok := unresolvedRules[f.RuleID]
		if !ok {
			continue
		}
		ids = append(ids, f.ID)
		if first == "" {
			// THE OBJECT, NOT ONLY THE RULE. "a Service publishes no ready address · service-no-ready-endpoints"
			// told a reader which check fired and not which Service published no ready address; the name is the news.
			first = what + " · " + shortRule(f.RuleID)
			if len(f.AffectedResources) > 0 {
				first = what + " · " + f.AffectedResources[0].Kind + " " + nameOf(f.AffectedResources[0])
			}
		}
	}
	if len(ids) == 0 {
		return Line{}, false
	}
	return Line{
		// "names resolve to nothing" was the engine's vocabulary; a reader asks what is pointing where.
		Claim:      fmt.Sprintf("%d reference%s point%s at nothing", len(ids), plural(len(ids)), verbS(len(ids))),
		Basis:      first + " — a reference, not an opinion",
		FindingIDs: ids,
	}, true
}

func monitoringCoverage(ar *types.AuditReport) (Line, bool) {
	var ids []string
	var first string
	for _, f := range ar.Findings {
		if f.Pillar != types.PillarObservability {
			continue
		}
		ids = append(ids, f.ID)
		if first == "" {
			first = shortRule(f.RuleID) + " · " + firstEvidenceClause(f)
		}
	}
	if len(ids) == 0 {
		return Line{}, false
	}
	return Line{
		Claim:      fmt.Sprintf("%d gap%s in what your monitoring would tell you", len(ids), plural(len(ids))),
		Basis:      strings.TrimSuffix(first, " · "),
		FindingIDs: ids,
	}, true
}

func capacityUnresolved(ar *types.AuditReport) (Line, bool) {
	if ar.Architecture == nil {
		return Line{}, false
	}
	var unknown, total int
	for _, p := range ar.Architecture.NodePools {
		total += p.Count
		unknown += p.UnknownCapCount
	}
	if total == 0 || unknown == 0 {
		return Line{}, false
	}
	return Line{
		Claim: fmt.Sprintf("spot vs on-demand unresolved on %d of %d node%s", unknown, total, plural(total)),
		Basis: "node labels · the purchase mode could not be determined, and it moves the whole cost conclusion",
	}, true
}

// identifiedDollars is the money line, and its basis is the basis of the dollars in it.
//
// IT USED TO BE THE READING'S BASIS, NOT THE FIGURE'S. Whenever the reading had a usage source the line read
// "prometheus over 6h · list price · upper bound if consolidated" — and on the mesh testbed $42 of the $90 was an
// instance-family list-price delta, which rests on no measurement and has nothing to consolidate. The usage window
// is now named only for the dollars that rest on it, with their share when they are not all of it, and "if
// consolidated" travels with them. A compute discount the reading was given is part of the price, so it is named
// too.
func identifiedDollars(ar *types.AuditReport, opts Options) (Line, bool) {
	usd := ar.Summary.EstimatedSavingsUSD
	if usd <= 0 {
		return Line{}, false
	}
	var measured float64
	for _, f := range ar.Findings {
		if f.DollarImpactMonthly > 0 && f.Basis != nil && f.Basis.UsageRequired {
			measured += f.DollarImpactMonthly
		}
	}
	price := "list price"
	if opts.ComputeDiscount > 0 {
		price = fmt.Sprintf("list price less %.0f%% on compute", opts.ComputeDiscount*100)
	}
	u := ar.Methodology.UsageMethodology.Basis()
	var basis string
	switch {
	case measured <= 0 || u == "":
		basis = price + " · upper bound"
	case measured >= usd-0.005:
		basis = u + " · " + price + " · upper bound if consolidated"
	default:
		basis = fmt.Sprintf("%s · upper bound · $%s of it rests on %s, if consolidated", price, thousands(measured), u)
	}
	return Line{Claim: fmt.Sprintf("$%s/mo identified", thousands(usd)), Basis: basis}, true
}

// traceLine is the reading's own cost, and it is always last: what it issued, what it wrote, what it could not
// read. A reading with no trace says that rather than printing zeroes.
func traceLine(ar *types.AuditReport) string {
	st := ar.Methodology.SessionTrace
	if st == nil {
		return "this reading recorded no session trace"
	}
	s := fmt.Sprintf("%d read%s · %d object write%s", st.Total, plural(st.Total), st.ObjectWrites, plural(st.ObjectWrites))
	if n := len(ar.Methodology.DeniedKinds); n > 0 {
		s += fmt.Sprintf(" · %d list%s refused", n, plural(n))
	}
	return s
}

// ── small helpers ────────────────────────────────────────────────────────────────────────────────

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func verbS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

func nameOf(r types.ResourceRef) string {
	if r.Namespace != "" {
		return r.Namespace + "/" + r.Name
	}
	return r.Name
}

func shortRule(id string) string {
	parts := strings.Split(id, ".")
	return parts[len(parts)-1]
}

// firstEvidenceClause is the first evidence line, trimmed to one clause, so a basis stays one line. The
// snapshot note every rule prepends is skipped: it says the same thing on every finding.
func firstEvidenceClause(f types.Finding) string {
	for _, e := range f.Evidence {
		if strings.HasPrefix(e, "Snapshot taken at") {
			continue
		}
		if i := strings.IndexAny(e, ";"); i > 0 {
			return strings.TrimSpace(e[:i])
		}
		if len(e) > 110 {
			return strings.TrimSpace(e[:107]) + "…"
		}
		return strings.TrimSpace(e)
	}
	return ""
}

func thousands(v float64) string {
	s := fmt.Sprintf("%.0f", v)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// coverageGap is the line that says how much of the cluster this reading could not read. The claim counts the
// kinds against what was asked; the basis names a few and says what that does to every other number.
func coverageGap(ar *types.AuditReport) (Line, bool) {
	denied := len(ar.Methodology.DeniedKinds)
	if denied == 0 || denied <= len(ar.Methodology.CollectedKinds) {
		return Line{}, false
	}
	asked := denied + len(ar.Methodology.CollectedKinds)
	names := ar.Methodology.DeniedKinds
	more := ""
	if len(names) > 3 {
		more = fmt.Sprintf(" and %d more", len(names)-3)
		names = names[:3]
	}
	return Line{
		Claim: fmt.Sprintf("%d of %d resource kinds could not be read", denied, asked),
		Basis: fmt.Sprintf("%s%s · every count in this reading is a floor, and the rules that need them did not run",
			strings.Join(names, ", "), more),
	}, true
}
