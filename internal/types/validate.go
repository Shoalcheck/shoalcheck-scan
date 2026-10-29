package types

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// severityRank orders severities for priority selection (lower = more urgent).
var severityRank = map[Severity]int{
	SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3, SeverityInfo: 4,
}

// SortByPriority orders findings the way the report consumes them:
// severity first (critical → info), then dollar impact descending, then the finding's own id.
// The renderer's "Highest priority" tile reads findings[0].
//
// THE ID IS THE TIE-BREAK, AND WITHOUT IT THIS WAS NOT AN ORDER. Two findings tied on severity and dollars
// compared equal in both directions and kept their INPUT order, so the same cluster read twice could put a
// different finding first — visible as a different Summary.HighestPriorityID in the JSON, a different
// "Highest priority" tile, and different deep-link ids in Architecture.Topologies and .Flows, all of which
// read findings[0] or keep the first finding per resource on a tie. internal/verdict has carried exactly this
// tie-break since it was written and every finding-emitting analyzer ends with a sort on ID; the report's own
// ordering was the one place the discipline was skipped.
func SortByPriority(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank[findings[i].Severity] != severityRank[findings[j].Severity] {
			return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
		}
		if findings[i].DollarImpactMonthly != findings[j].DollarImpactMonthly {
			return findings[i].DollarImpactMonthly > findings[j].DollarImpactMonthly
		}
		return findings[i].ID < findings[j].ID
	})
}

// DeriveSummary recomputes Summary from findings. The audit pipeline always
// uses this; render mode uses it to verify the input's Summary tells the truth.
func DeriveSummary(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
		BySeverity:    map[Severity]int{},
		ByCategory:    map[Category]int{},
	}
	bestIdx := -1
	for i, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByCategory[f.Category]++
		s.EstimatedSavingsUSD += f.DollarImpactMonthly
		// The same total order SortByPriority uses, down to the id. DeriveSummary scans rather than reading
		// findings[0] — render mode calls it on findings in whatever order the input file had — and Validate()
		// hard-fails a report whose stored HighestPriorityID disagrees, so the two must break ties identically.
		if bestIdx == -1 ||
			severityRank[f.Severity] < severityRank[findings[bestIdx].Severity] ||
			(severityRank[f.Severity] == severityRank[findings[bestIdx].Severity] &&
				f.DollarImpactMonthly > findings[bestIdx].DollarImpactMonthly) ||
			(severityRank[f.Severity] == severityRank[findings[bestIdx].Severity] &&
				f.DollarImpactMonthly == findings[bestIdx].DollarImpactMonthly &&
				f.ID < findings[bestIdx].ID) {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		s.HighestPriorityID = findings[bestIdx].ID
	}
	return s
}

// DeriveComplianceScore recomputes a ComplianceScore from the control statuses,
// the way DeriveSummary recomputes Summary from findings. Scored = Passed+Failed
// (the denominator-honest count: MANUAL/NA are reported but never inflate the
// rate), and PassRate = Passed/Scored (0 when nothing was scored). Total is the
// control count. Validate() uses this to reject a compliance score that lies the
// way a lying Summary is rejected — a customer-facing "X of M pass" headline must
// be derivable from the controls it claims to summarize.
func DeriveComplianceScore(controls []ComplianceControl) ComplianceScore {
	s := ComplianceScore{Total: len(controls), Totals: map[ControlStatus]int{}}
	for _, c := range controls {
		s.Totals[c.Status]++
		switch c.Status {
		case ControlStatusPass:
			s.Passed++
		case ControlStatusFail:
			s.Failed++
		case ControlStatusManual:
			s.Manual++
		case ControlStatusNA:
			s.NA++
		}
	}
	s.Scored = s.Passed + s.Failed
	if s.Scored > 0 {
		s.PassRate = float64(s.Passed) / float64(s.Scored)
	}
	return s
}

// Validate checks schema version, enum validity, confidence range, and that
// Summary is consistent with Findings. A wrong number in an audit report is
// worse than a hard error, so violations reject the whole report.
func (ar *AuditReport) Validate() error {
	var errs []error
	if ar.SchemaVersion != "v1" {
		errs = append(errs, fmt.Errorf("unsupported schemaVersion %q (want \"v1\")", ar.SchemaVersion))
	}
	seen := map[string]bool{}
	for _, f := range ar.Findings {
		if f.ID == "" {
			errs = append(errs, errors.New("finding with empty id"))
			continue
		}
		if seen[f.ID] {
			errs = append(errs, fmt.Errorf("finding %s: duplicate id", f.ID))
		}
		seen[f.ID] = true
		if !f.Severity.Valid() {
			errs = append(errs, fmt.Errorf("finding %s: invalid severity %q", f.ID, f.Severity))
		}
		if !f.Category.Valid() {
			errs = append(errs, fmt.Errorf("finding %s: invalid category %q", f.ID, f.Category))
		}
		if !f.EstimatedEffort.Valid() {
			errs = append(errs, fmt.Errorf("finding %s: invalid effort %q", f.ID, f.EstimatedEffort))
		}
		if f.Confidence < 0 || f.Confidence > 1 {
			errs = append(errs, fmt.Errorf("finding %s: confidence %.3f outside [0,1]", f.ID, f.Confidence))
		}
		// Defensibility invariant (the node-headroom class, structural): a dollar
		// figure that lands in the customer-facing headline must cite the evidence
		// it was derived from. A confident $-finding with no Evidence is exactly the
		// node-headroom false positive — block it here so no current rule, future
		// rule, or hand-edited fixture can bill a dollar without showing its work.
		if f.DollarImpactMonthly < 0 {
			errs = append(errs, fmt.Errorf("finding %s: dollarImpactMonthly %.2f is negative", f.ID, f.DollarImpactMonthly))
		}
		if f.DollarImpactMonthly > 0 && len(f.Evidence) == 0 {
			errs = append(errs, fmt.Errorf("finding %s: dollarImpactMonthly=%.2f with no evidence (a billed dollar must cite its basis)", f.ID, f.DollarImpactMonthly))
		}
	}
	errs = append(errs, validateCalendar(ar.Calendar)...)
	d := DeriveSummary(ar.Findings)
	if ar.Summary.TotalFindings != d.TotalFindings {
		errs = append(errs, fmt.Errorf("summary inconsistent: totalFindings=%d but %d findings present", ar.Summary.TotalFindings, d.TotalFindings))
	}
	if math.Abs(ar.Summary.EstimatedSavingsUSD-d.EstimatedSavingsUSD) > 0.01 {
		errs = append(errs, fmt.Errorf("summary inconsistent: estimatedSavingsUsd=%.2f but findings sum to %.2f", ar.Summary.EstimatedSavingsUSD, d.EstimatedSavingsUSD))
	}
	for sev, n := range d.BySeverity {
		if ar.Summary.BySeverity[sev] != n {
			errs = append(errs, fmt.Errorf("summary inconsistent: bySeverity[%s]=%d, derived %d", sev, ar.Summary.BySeverity[sev], n))
		}
	}
	// Reverse direction: a key present in the input but absent from derived
	// (e.g. "critical": 5 with zero critical findings) must also fail.
	for sev, n := range ar.Summary.BySeverity {
		if n != 0 && d.BySeverity[sev] == 0 {
			errs = append(errs, fmt.Errorf("summary inconsistent: bySeverity[%s]=%d, derived 0", sev, n))
		}
	}
	for cat, n := range d.ByCategory {
		if ar.Summary.ByCategory[cat] != n {
			errs = append(errs, fmt.Errorf("summary inconsistent: byCategory[%s]=%d, derived %d", cat, ar.Summary.ByCategory[cat], n))
		}
	}
	for cat, n := range ar.Summary.ByCategory {
		if n != 0 && d.ByCategory[cat] == 0 {
			errs = append(errs, fmt.Errorf("summary inconsistent: byCategory[%s]=%d, derived 0", cat, n))
		}
	}
	if d.HighestPriorityID != "" && ar.Summary.HighestPriorityID != d.HighestPriorityID {
		errs = append(errs, fmt.Errorf("summary.highestPriorityId=%q but derived highest priority is %q",
			ar.Summary.HighestPriorityID, d.HighestPriorityID))
	}
	// ComplianceAssessment is an optional v1-additive field. These assertions
	// fire ONLY when it's populated (the pipeline always populates it; v0
	// fixtures that omit it serialize and validate identically — a nil pointer
	// skips this block entirely).
	if ca := ar.ComplianceAssessment; ca != nil {
		for _, c := range ca.Controls {
			if !c.Status.Valid() {
				errs = append(errs, fmt.Errorf("complianceAssessment control %s: invalid status %q", c.Control, c.Status))
			}
			if !c.Profile.Valid() {
				errs = append(errs, fmt.Errorf("complianceAssessment control %s: invalid profile %d", c.Control, c.Profile))
			}
			// "Never PASS an unchecked control": a PASS means an evidence rule ran
			// and found nothing — it MUST cite that rule. This invariant is enforced
			// by construction in BuildComplianceAssessment (the only PASS path requires
			// EvidenceRuleIDs); re-asserting it here holds every OTHER assembly path
			// (hand-authored fixtures, future LLM enrichment, fleet-merge, refactors)
			// to the same bar, so a control can never be marked PASS without machine
			// evidence behind it.
			if c.Status == ControlStatusPass && len(c.EvidenceRuleIDs) == 0 {
				errs = append(errs, fmt.Errorf("complianceAssessment control %s: PASS with no evidenceRuleIds (never PASS an unchecked control)", c.Control))
			}
		}
		// ComplianceScore must be re-derivable from the controls it summarizes, the
		// same way Summary is re-derived from Findings above. A score that claims a
		// pass rate the control statuses don't support is the compliance-side analog
		// of a lying Summary — reject it instead of letting "X of M controls pass"
		// be fabricated.
		ds := DeriveComplianceScore(ca.Controls)
		sc := ca.Score
		switch {
		case sc.Total != ds.Total:
			errs = append(errs, fmt.Errorf("complianceAssessment score.total=%d but %d controls present", sc.Total, ds.Total))
		case sc.Passed != ds.Passed:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: passed=%d, derived %d", sc.Passed, ds.Passed))
		case sc.Failed != ds.Failed:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: failed=%d, derived %d", sc.Failed, ds.Failed))
		case sc.Manual != ds.Manual:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: manual=%d, derived %d", sc.Manual, ds.Manual))
		case sc.NA != ds.NA:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: na=%d, derived %d", sc.NA, ds.NA))
		case sc.Scored != ds.Scored:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: scored=%d but passed+failed=%d", sc.Scored, ds.Scored))
		case math.Abs(sc.PassRate-ds.PassRate) > 0.0001:
			errs = append(errs, fmt.Errorf("complianceAssessment score inconsistent: passRate=%.4f but passed/scored=%.4f", sc.PassRate, ds.PassRate))
		}
	}
	// Layer 1 cost-realization enums are v1-additive. These checks fire ONLY when
	// a value is populated (zero value "" is Valid), so old fixtures with no
	// capacity/cost-source signal validate byte-identically. ActualSpend (Layer 2)
	// is intentionally NOT introduced here — its guard ships with the billing
	// module, and ActualSpend NEVER feeds DeriveSummary (the estimate-sum
	// invariant at the top of this function stays untouched).
	if !ar.Cluster.SpendSource.Valid() {
		errs = append(errs, fmt.Errorf("cluster: invalid spendSource %q", ar.Cluster.SpendSource))
	}
	if arch := ar.Architecture; arch != nil {
		for _, p := range arch.NodePools {
			if !p.Capacity.Valid() {
				errs = append(errs, fmt.Errorf("nodePool %s: invalid capacityType %q", p.Type, p.Capacity))
			}
			if !p.CostSource.Valid() {
				errs = append(errs, fmt.Errorf("nodePool %s: invalid costSource %q", p.Type, p.CostSource))
			}
		}
		for _, az := range arch.AZs {
			for _, n := range az.Nodes {
				if !n.Capacity.Valid() {
					errs = append(errs, fmt.Errorf("node %s: invalid capacityType %q", n.Name, n.Capacity))
				}
			}
		}
	}
	return errors.Join(errs...)
}
