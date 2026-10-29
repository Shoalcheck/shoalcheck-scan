package history

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Comparing two audits is the one place in this product where a wrong answer is indistinguishable from
// a valuable one. "Two findings fixed since Monday" is the sentence an operator most wants to read, and
// producing it from a run that simply lost an RBAC verb hands them a compliment for someone else's
// mistake. So the comparison is built as a series of GATES, in order, each of which can only ever move a
// finding from a stronger claim to a weaker one:
//
//	Gate 0  Is a comparison possible at all?      → Comparability, whole-diff
//	Gate 1  Could the other reading evaluate this? → NotEvaluated, per finding
//	Gate 2  Is the rule behind it still the same?  → RuleChanged
//	Gate 3  Was it produced from the same DATA?    → NotEvaluated / ValueNotCompared
//	Gate 4  Did anything load-bearing move?        → Changed / Present
//	Gate 5  Whatever is left is a set difference.  → NewInSet / NoLongerInSet
//
// Nothing reaches Gate 5 until every earlier gate has declined to claim it, which is why the order is
// part of the contract rather than an implementation detail.
//
// GATE 3 IS RENUMBERED IN, NOT APPENDED. This block asserts the order is the contract, so a gate bolted on
// at the end would make the block false. It sits between 2 and the old 3 because Gate 2 asks "is the LOGIC
// behind this the same?" and Gate 3 asks the same question about THE DATA THE LOGIC READ — the two halves of
// "was this produced the same way" belong adjacent, and both must be answered before anything is allowed to
// say a value moved. It cannot sit after movement(), because movement() is the site of the false claim; and
// it must not sit in Gate 0, because a Kubernetes-EOL table update has nothing to do with whether
// no-network-policy is still present, and refusing the whole comparison would withhold far more than the
// reading justifies.
//
// What deliberately has no bucket: a finding that vanished because its object was RENAMED. The old
// finding leaves the set and a new one enters, and both statements are true. Pairing them would require
// guessing that two differently-keyed findings are the same problem, and the first live run of the loop
// showed why that guess is dangerous — a recommended fix cleared one finding and created another, 145 to
// 145, and the honest headline was the NET rather than the win.

// Side names which of the two readings a per-finding note came from.
type Side string

const (
	// SidePrevious marks a finding that was in the earlier reading.
	SidePrevious Side = "previous"
	// SideCurrent marks a finding that is in this reading.
	SideCurrent Side = "current"
)

// Deps is what the comparison needs to know about whatever produced a finding. History defines it rather
// than importing a registry so it stays a leaf; the caller builds the map (see pipeline.HistoryDeps).
type Deps struct {
	// Kinds are collector step names, exactly as a report records them in Methodology.CollectedKinds.
	Kinds []string
	// Usage marks a producer that emits nothing without a resolved usage source.
	Usage bool
	// Datasets are the reference datasets this producer's findings rest on, by registry name. A dataset
	// belongs here on the same test Kinds uses: it belongs when the CLAIM changes if the dataset moved, not
	// when only the wording would.
	Datasets []DatasetDep
	// Producer is the id a reading's RunBasis.RuleSet records this finding's producer under, when that is not
	// the finding's own id. An analyzer stamps ITS id — stack.argocd.sync — and files findings under others —
	// stack.argocd.outofsync — so Gate 1, looking the finding's id up in the other reading's rule set, found
	// nothing and held every one-sided analyzer finding back as "not part of the build", between two readings
	// by the same build. Empty for a rule, whose findings carry the id it stamps.
	Producer string
}

// DatasetDep is one reference-data dependency, and the Presence flag is the whole of Gate 3's behaviour.
type DatasetDep struct {
	Name string
	// Presence marks a dataset that decides WHETHER the finding exists at all — a Kubernetes API-removal
	// table: no row, no finding. False marks a dataset that only supplies a DERIVED VALUE — a price table:
	// the finding fires either way, with or without a figure.
	//
	// NOT DECORATION. The existing tests already prove the difference: pricing does not change which findings
	// appear (gates_test.go:265-269), while an API-removal table absolutely does — we would stop listing a
	// removal and the finding would vanish with the cluster untouched. So one moves the finding to
	// NotEvaluated and the other only disarms its value comparison.
	Presence bool
}

// Comparability is Gate 0: whether these two readings may be compared at all. A false OK is NOT a
// zeroed comparison — it is the absence of one, and the difference matters because a zeroed delta reads
// as "nothing changed".
type Comparability struct {
	OK bool
	// Reason states which gate refused, in words a report can print verbatim.
	Reason string
	// Note is printed beside a comparison that WAS made, when something about it deserves a sentence — today,
	// that the two readings came from different engine versions and the rule-set stamps made a per-finding
	// answer possible. Empty when there is nothing to say.
	Note string
}

// Unevaluated is a finding the comparison declined to classify, and why.
type Unevaluated struct {
	Finding types.Finding
	// Side is the reading this finding came from. A previous-side entry means we cannot say it left the
	// cluster; a current-side entry means we cannot say it arrived.
	Side Side
	// Reason names the missing input, so the report can be specific rather than apologetic.
	Reason string
}

// Change is a finding present in both readings with something load-bearing moved.
type Change struct {
	Finding types.Finding
	// ValueNotCompared names the datasets whose version differed between the two readings, so the derived
	// figure was withheld rather than compared.
	//
	// A FLAG AND NOT AN EXCLUSIVE BUCKET, deliberately. A DataVersionChanged bucket mirroring RuleChanged is
	// tidier and swallows a severity regression — which is the one thing a report leads with. This withholds
	// exactly the derived figure and nothing more.
	ValueNotCompared []string
	// What names every field that moved, e.g. "severity medium → high".
	What string
	// Regressed marks a severity that grew more urgent.
	Regressed bool
}

// Diff is the structured comparison between a previous audit and this one. Findings are matched by their
// stable ID (types.Finding.ID).
type Diff struct {
	// PrevAt is the timestamp of the previous audit this diff is against.
	PrevAt time.Time
	// PrevLabel and CurLabel are the two readings' Methodology.Label, carried so ToTrendDelta can print them.
	PrevLabel, CurLabel string

	// Comparable is Gate 0. When it is not OK, every bucket below is empty and every delta is zero —
	// not because nothing changed, but because no statement about change is available.
	Comparable Comparability

	// NewInSet holds findings in this reading whose absence from the earlier one was CONFIRMED: the
	// earlier run read everything they rest on and did not report them.
	NewInSet []types.Finding
	// NoLongerInSet holds findings in the earlier reading whose absence from this one was confirmed the
	// same way. Named for what it is: shoalcheck reads two states minutes apart, so it cannot know WHY a
	// finding is absent — the object may have been deleted, an autoscaler may have acted, or someone
	// else may have changed something in the same minute.
	NoLongerInSet []types.Finding
	// NotEvaluated holds the findings Gate 1 declined, with the missing input named.
	NotEvaluated []Unevaluated
	// RuleChanged holds findings present in both readings whose rule changed version between them, so
	// the match cannot be read as the same problem persisting.
	RuleChanged []types.Finding
	// Changed holds findings present in both with something load-bearing moved.
	Changed []Change
	// Regressed is the subset of Changed whose severity grew more urgent, kept as its own slice because
	// it is the one change a report leads with.
	Regressed []types.Finding
	// Present counts findings in both readings with nothing load-bearing moved.
	Present int
	// InBoth counts every finding matched on both sides, whether or not something moved — Present plus
	// Changed plus RuleChanged. Kept as its own number because "still present" and "unchanged" are
	// different statements, and a consumer that had to add three buckets to get the first one would
	// eventually add two.
	InBoth int

	// PricingCoverageChanged marks that the two readings could price a different set of node types or
	// storage classes. It is a gate on the DOLLAR only, not on the findings: the cost rules wrap their
	// price lookup in a conditional, so an unpriced finding still exists and still appears in both
	// readings — but the SUM moves for a reason that has nothing to do with the cluster. A price table
	// that gained a region between two runs would otherwise have the strip announce money the operator
	// did nothing to create.
	PricingCoverageChanged bool

	// SavingsDelta is current EstimatedSavingsUSD minus the previous value. Read it together with
	// PricingCoverageChanged: when that is set, this number mixes a changed cluster with a changed price
	// table and the two cannot be separated.
	SavingsDelta float64

	// SavingsPriced says whether SavingsDelta is a measurement at all — that is, whether BOTH readings'
	// savings figures were. A delta between two non-measurements is not one, and it renders as "+0.00
	// USD/mo (Δ)", which reads as "the savings did not move". Nothing moved because nothing was ever
	// priced, and those are opposite news.
	//
	// A SIBLING OF PricingCoverageChanged AND NOT THE SAME GATE. That one catches a sum moving because the
	// price table changed under two comparable readings. This one catches two readings that never had a
	// figure to compare: the coverage is identical, the gate above stays silent, and the delta is arithmetic
	// over two absences.
	SavingsPriced bool

	// ReferenceDataChanged names the reference datasets whose versions differ between the two readings, and
	// SavingsDelta is withheld when it is non-empty — exactly as it is when PricingCoverageChanged is set.
	//
	// A SIBLING OF PricingCoverageChanged, NOT A REPLACEMENT. Coverage and version are two different ways for
	// a sum to move for a non-cluster reason, and one does not imply the other: a refreshed table that prices
	// the same set of instance types changes every figure and leaves both coverage sets identical.
	ReferenceDataChanged []string
	// ReferenceDataReason is prose a report prints verbatim beside a number it did not compute. It names both
	// versions, because a caveat without the two values is unfalsifiable.
	ReferenceDataReason string
	// FindingsDelta is current total findings minus the previous total.
	FindingsDelta int
	// BySeverityDelta is per-severity (current - previous), zero entries omitted.
	BySeverityDelta map[types.Severity]int
}

// severityRank orders severities so a regression is detectable. Lower = more urgent.
var severityRank = map[types.Severity]int{
	types.SeverityCritical: 0,
	types.SeverityHigh:     1,
	types.SeverityMedium:   2,
	types.SeverityLow:      3,
	types.SeverityInfo:     4,
}

// Compute compares a previous audit against this one. deps maps producer ID to what its findings rest
// on; passing nil refuses the comparison outright rather than quietly skipping the gates that depend on
// it, because a Compute that can be called into a blind mode is a Compute that eventually is.
func Compute(prev, cur *types.AuditReport, deps map[string]Deps) Diff {
	d := Diff{PrevAt: prev.GeneratedAt, PrevLabel: prev.Methodology.Label, CurLabel: cur.Methodology.Label,
		BySeverityDelta: map[types.Severity]int{}}

	// ---- Gate 0 ----
	d.Comparable = comparable(prev, cur, deps)
	if !d.Comparable.OK {
		return d
	}

	d.SavingsDelta = cur.Summary.EstimatedSavingsUSD - prev.Summary.EstimatedSavingsUSD
	// Both sides, because a difference is only a measurement when both of its terms are — and the rule is
	// types.DollarsAreAMeasurement, the one every other surface applies to a single reading.
	d.SavingsPriced = types.DollarsAreAMeasurementForReading(prev) &&
		types.DollarsAreAMeasurementForReading(cur)
	d.PricingCoverageChanged = pricingCoverageChanged(prev, cur)
	// ---- Gate 3, whole-diff half ----
	d.ReferenceDataChanged, d.ReferenceDataReason = referenceDataChanged(prev, cur)
	if len(d.ReferenceDataChanged) > 0 {
		// Withheld, not zeroed-and-labelled: a rendered 0 reads as "nothing changed", which is the one
		// sentence this whole layer exists to stop. The reason travels beside it.
		d.SavingsDelta = 0
	}
	d.FindingsDelta = cur.Summary.TotalFindings - prev.Summary.TotalFindings

	prevByID := make(map[string]types.Finding, len(prev.Findings))
	for _, f := range prev.Findings {
		prevByID[f.ID] = f
	}
	curByID := make(map[string]types.Finding, len(cur.Findings))
	for _, f := range cur.Findings {
		curByID[f.ID] = f
	}

	// Current-side pass.
	for _, f := range cur.Findings {
		pf, both := prevByID[f.ID]
		if both {
			d.InBoth++
		}
		if !both {
			// Gate 1: could the EARLIER reading have seen this? If not, it is not new to the cluster —
			// what changed is that we could finally look.
			if why, blocked := blockedBy(f, prev, deps); blocked {
				d.NotEvaluated = append(d.NotEvaluated, Unevaluated{Finding: f, Side: SideCurrent, Reason: why})
				continue
			}
			// Gate 3, presence half: a dataset that decides WHETHER this finding exists moved between the
			// readings, so we cannot say it arrived — we may simply have started listing it. Same bucket as
			// Gate 1 because the honest sentence is identical.
			if why, blocked := presenceDatasetMoved(f, prev, cur, deps, SideCurrent); blocked {
				d.NotEvaluated = append(d.NotEvaluated, Unevaluated{Finding: f, Side: SideCurrent, Reason: why})
				continue
			}
			d.NewInSet = append(d.NewInSet, f)
			continue
		}
		// Gate 2.
		if f.RuleVersion != pf.RuleVersion {
			d.RuleChanged = append(d.RuleChanged, f)
			continue
		}
		// Gate 3, per-finding: was this produced from the same reference data? A presence-bearing dataset
		// that moved was already handled on the way in (see the !both branch); here the finding exists in
		// both readings, so what a moved dataset can invalidate is only its derived VALUE.
		valueOff := movedValueDatasets(f, prev, cur, deps)
		// Gate 4.
		if what, moved := movement(pf, f, len(valueOff) > 0); moved {
			c := Change{
				Finding: f, What: what, ValueNotCompared: valueOff,
				Regressed: severityRank[f.Severity] < severityRank[pf.Severity],
			}
			d.Changed = append(d.Changed, c)
			if c.Regressed {
				d.Regressed = append(d.Regressed, f)
			}
			continue
		}
		d.Present++
	}

	// Previous-side pass: Gate 1, then Gate 4.
	for _, f := range prev.Findings {
		if _, both := curByID[f.ID]; both {
			continue
		}
		if why, blocked := blockedBy(f, cur, deps); blocked {
			d.NotEvaluated = append(d.NotEvaluated, Unevaluated{Finding: f, Side: SidePrevious, Reason: why})
			continue
		}
		if why, blocked := presenceDatasetMoved(f, prev, cur, deps, SidePrevious); blocked {
			d.NotEvaluated = append(d.NotEvaluated, Unevaluated{Finding: f, Side: SidePrevious, Reason: why})
			continue
		}
		d.NoLongerInSet = append(d.NoLongerInSet, f)
	}

	for sev, n := range cur.Summary.BySeverity {
		d.BySeverityDelta[sev] = n - prev.Summary.BySeverity[sev]
	}
	for sev, n := range prev.Summary.BySeverity {
		if _, seen := cur.Summary.BySeverity[sev]; !seen {
			d.BySeverityDelta[sev] = -n
		}
	}
	for sev, delta := range d.BySeverityDelta {
		if delta == 0 {
			delete(d.BySeverityDelta, sev)
		}
	}

	return d
}

// comparable is Gate 0. Every condition here invalidates the comparison WHOLESALE, which is why they are
// checked before a single finding is looked at.
func comparable(prev, cur *types.AuditReport, deps map[string]Deps) Comparability {
	if deps == nil {
		// THE CALLER, NOT THE READINGS. This sentence used to read "no record of what each finding rests on
		// was supplied", which a reader takes as a fact about the two readings — and cmd/shoalcheck-mcp passed
		// nil for a year, so every comparison it made blamed the data for the caller's omission. The map is
		// an argument; say whose it is.
		return Comparability{Reason: "this caller supplied no rule-dependency map, so a difference between " +
			"these readings could not be told apart from a difference in what was readable — the readings " +
			"themselves were not examined"}
	}
	pb, cb := prev.Methodology.RunBasis, cur.Methodology.RunBasis
	if pb == nil || cb == nil {
		return Comparability{Reason: "one of these readings does not record what it was a reading of, and " +
			"nothing can be claimed against a reading of unknown origin"}
	}
	if pb.ClusterUID == "" || cb.ClusterUID == "" {
		return Comparability{Reason: "the identity of the cluster is missing from one of these readings — a " +
			"context name can be renamed or reused for a rebuilt cluster, so it is not an identity"}
	}
	if pb.Redacted != cb.Redacted {
		return Comparability{Reason: "one of these readings was redacted and the other was not, so their cluster " +
			"identities cannot be matched — compare two redacted readings or two plain ones"}
	}
	if pb.ClusterUID != cb.ClusterUID {
		return Comparability{Reason: "these are readings of two different clusters"}
	}
	if pb.IncludeSystem != cb.IncludeSystem {
		return Comparability{Reason: "the two readings covered different namespaces — one included the " +
			"operator-managed namespaces and the other did not, so findings appear and vanish wholesale"}
	}
	// An unstamped engine version is not a matching one. The ClusterUID check above already refuses an
	// EMPTY value on the reasoning that a reading which does not say what it is a reading of cannot be
	// claimed against, and the same doctrine is stated for prices two functions below: "an unconfirmed
	// equivalence is not an equivalence". Two readings that are both silent about the engine compare EQUAL
	// under a bare !=, which is the one case where the honest answer is not "the same engine" but "we
	// cannot say" — and what an unknown engine hides is precisely a rule that did not exist in one of the
	// two builds, i.e. an absence that is ours and not the cluster's.
	if pb.EngineVersion == "" || cb.EngineVersion == "" {
		return Comparability{Reason: "one of these readings does not record which version of the engine " +
			"produced it, so the two sets of findings cannot be confirmed to come from the same rules"}
	}
	if pb.EngineVersion != cb.EngineVersion {
		// TWO BUILDS, ONE QUESTION EACH. When both readings carry RuleSet, Gate 1 can ask per finding whether
		// the other build had its rule, so refusing everything here would withhold comparisons we are entitled
		// to make. When either side lacks the stamp — a snapshot from before 2026-09-02 — the sharp question
		// cannot be asked and the wholesale refusal is the honest answer, as it was.
		if len(pb.RuleSet) > 0 && len(cb.RuleSet) > 0 {
			return Comparability{OK: true, Note: fmt.Sprintf("the readings were taken by different versions "+
				"of the engine (%s and %s); findings whose rule was added, removed or re-versioned between "+
				"them are held back one by one below", pb.EngineVersion, cb.EngineVersion)}
		}
		return Comparability{Reason: fmt.Sprintf("the readings were taken by different versions of the "+
			"engine (%s and %s), so an absence may be a change to a rule rather than to the cluster",
			pb.EngineVersion, cb.EngineVersion)}
	}
	return Comparability{OK: true}
}

// pricingCoverageChanged compares what each reading was ABLE to price. An unknown coverage on either side
// counts as changed: we cannot confirm the two sums were built from the same table, and an unconfirmed
// equivalence is not an equivalence. Gate 0 already refuses snapshots old enough to lack an Architecture,
// so in practice this is a set comparison rather than a nil check.
func pricingCoverageChanged(prev, cur *types.AuditReport) bool {
	if prev.Architecture == nil || cur.Architecture == nil {
		return true
	}
	return !sameSet(prev.Architecture.UnpricedNodeTypes, cur.Architecture.UnpricedNodeTypes) ||
		!sameSet(prev.Architecture.UnpricedStorageClasses, cur.Architecture.UnpricedStorageClasses)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// blockedBy is Gate 1: whether the OTHER reading was in a position to produce this finding at all. It
// asks about the other side deliberately — a finding is only a difference if both readings could have
// contained it.
func blockedBy(f types.Finding, other *types.AuditReport, deps map[string]Deps) (string, bool) {
	dep, known := deps[f.RuleID]
	if !known {
		// A producer this build cannot describe. Refusing is the only safe answer: the alternative is to
		// classify a finding whose inputs are unknown.
		return fmt.Sprintf("%q is not a rule this build knows, so what its findings rest on cannot be "+
			"checked against the other reading", f.RuleID), true
	}
	// The rule-set question, asked only when the other reading can answer it. An absent stamp is a legacy
	// snapshot, and Gate 0 has already refused the pair if the engine moved.
	if rs := other.Methodology.RunBasis.RuleSet; len(rs) > 0 {
		stamped := f.RuleID
		if dep.Producer != "" {
			stamped = dep.Producer // an analyzer's finding is stamped under the analyzer's id; see Deps.Producer
		}
		v, had := ruleVersionIn(rs, stamped)
		if !had {
			return fmt.Sprintf("rule %s was not part of the %s reading's build", stamped,
				other.GeneratedAt.Format("2 Jan 2006")), true
		}
		if v != f.RuleVersion {
			return fmt.Sprintf("rule %s changed from %s to %s between the readings", stamped, v, f.RuleVersion), true
		}
	}
	if dep.Usage {
		src := other.Methodology.RunBasis.UsageSource
		if src == "" || src == "none" {
			return "this finding exists only where usage figures were resolved, and the other reading had " +
				"no usage source", true
		}
	}
	collected := map[string]bool{}
	for _, k := range other.Methodology.CollectedKinds {
		collected[k] = true
	}
	denied := map[string]bool{}
	for _, k := range other.Methodology.DeniedKinds {
		denied[k] = true
	}
	var missing []string
	for _, k := range dep.Kinds {
		// Denied and un-mentioned are both "not confirmed read", the same discipline as rules.observed:
		// an unlooked-at list is never read as an empty one.
		if denied[k] || !collected[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Sprintf("the other reading did not confirm reading %s, which this finding rests on",
			strings.Join(missing, ", ")), true
	}
	return "", false
}

// Blocked is Gate 1 for callers outside the pairwise diff — the recurrence timeline asks it once per
// (finding, reading). It IS blockedBy: two copies of this question would drift, and the timeline would then
// call an absence what the diff calls unreadable.
func Blocked(f types.Finding, other *types.AuditReport, deps map[string]Deps) (string, bool) {
	return blockedBy(f, other, deps)
}

// ruleVersionIn finds a producer in a RunBasis.RuleSet. Linear: the set is ~100 entries and this runs once
// per one-sided finding.
func ruleVersionIn(rs []types.RuleStamp, id string) (string, bool) {
	for _, s := range rs {
		if s.ID == id {
			return s.Version, true
		}
	}
	return "", false
}

// movement is Gate 3: what moved between two readings of the same finding. Only fields an operator would
// act on differently count — evidence wording shifts on every run and would make everything "changed".
// valueDisarmed is Gate 3's effect on this function: when the reference data behind the derived figure moved,
// the figure's comparison cannot fire. Passed in rather than looked up here so this function stays a pure
// comparison of two findings.
func movement(prev, cur types.Finding, valueDisarmed bool) (string, bool) {
	var parts []string
	if prev.Severity != cur.Severity {
		// "->" spelled out, for the same reason flows.go uses "to": the report ships no face carrying
		// U+2192, and this string is rendered into the comparison surface. It has never fired the glyph
		// gate only because no corpus document carries a severity movement.
		parts = append(parts, fmt.Sprintf("severity %s to %s", prev.Severity, cur.Severity))
	}
	if len(prev.AffectedResources) != len(cur.AffectedResources) {
		parts = append(parts, fmt.Sprintf("affected resources %d to %d",
			len(prev.AffectedResources), len(cur.AffectedResources)))
	}
	// THE SITE OF THE FALSE CLAIM. Two readings priced from different tables land here, and "the monthly
	// figure moved" attributes our table's movement to the customer's cluster. Gate 3 disarms exactly this
	// comparison and nothing else — a severity move on the same finding still surfaces.
	if !valueDisarmed && prev.DollarImpactMonthly != cur.DollarImpactMonthly {
		parts = append(parts, "the monthly figure moved")
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "; "), true
}

// ToTrendDelta projects a Diff into the compact types.TrendDelta the report carries for the renderer.
// Returns nil when no comparison was possible, so the strip renders nothing rather than a row of zeroes
// that would read as "nothing changed".
func (d Diff) ToTrendDelta() *types.TrendDelta {
	if !d.Comparable.OK {
		return nil
	}
	return &types.TrendDelta{
		PreviousAt:             d.PrevAt,
		Label:                  d.CurLabel,
		PreviousLabel:          d.PrevLabel,
		NewCount:               len(d.NewInSet),
		NewIDs:                 idsOf(d.NewInSet),
		ResolvedCount:          len(d.NoLongerInSet), // deprecated alias, still emitted
		NoLongerInSetCount:     len(d.NoLongerInSet),
		NoLongerInSet:          namedOf(d.NoLongerInSet),
		NotEvaluatedCount:      len(d.NotEvaluated),
		RegressedCount:         len(d.Regressed),
		ChangedCount:           len(d.Changed),
		EngineNote:             d.Comparable.Note,
		FindingsDelta:          d.FindingsDelta,
		SavingsDelta:           d.SavingsDelta,
		PricingCoverageChanged: d.PricingCoverageChanged,
		SavingsUnpriced:        !d.SavingsPriced,
		ReferenceDataChanged:   d.ReferenceDataChanged,
		ReferenceDataReason:    d.ReferenceDataReason,
	}
}

// namedOf is what the earlier reading said about each finding that left, sorted by id for the same reason idsOf
// sorts. nil for an empty set, so the field is omitted rather than written as an empty list.
func namedOf(fs []types.Finding) []types.TrendFinding {
	if len(fs) == 0 {
		return nil
	}
	out := make([]types.TrendFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, types.TrendFinding{ID: f.ID, RuleID: f.RuleID, Severity: f.Severity, Title: f.Title})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// idsOf is the ids of fs, sorted: a set has no order of its own, and the same two readings must name the
// same findings in the same order every time they are compared. nil for an empty set, so the field is
// omitted rather than written as an empty list.
func idsOf(fs []types.Finding) []string {
	if len(fs) == 0 {
		return nil
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

// Refusal is the delta for a pair Gate 0 refused: the prior's timestamp and the gate's sentence, and no
// counts at all. nil when the comparison was made — callers use ToTrendDelta first and this second.
func (d Diff) Refusal() *types.TrendDelta {
	if d.Comparable.OK {
		return nil
	}
	return &types.TrendDelta{
		PreviousAt:  d.PrevAt,
		NotCompared: &types.NotCompared{PreviousAt: d.PrevAt, Reason: d.Comparable.Reason},
	}
}
