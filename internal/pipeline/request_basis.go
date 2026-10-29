package pipeline

import (
	"fmt"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// attachRequestBasis is the second rung of the provenance ladder: it joins each finding to the REQUESTS that
// read its inputs, and each ledger row to the rules that consumed what it read.
//
// The first rung (attachFindingBasis) needed no vocabulary map because rule dependencies and
// Methodology.CollectedKinds are both collector step names. This one crosses into the trace, which is keyed by
// the RBAC unit — an apiGroup/resource tuple — so it needs collect.StepTuple, and that is the entire reason
// these two rungs are separate steps in the build order.
//
// WHAT IT DOES NOT CLAIM. A reference says a request was issued while this finding was produced. It does not
// say the request supports the finding, and nothing here should be read as evidence of support; the chip is
// worded "requests issued" for that reason. The rung that would establish support is derivation — the formula —
// and that is a different thing again.
func attachRequestBasis(ar *types.AuditReport) {
	if ar == nil || ar.Methodology.SessionTrace == nil {
		// No measurement was taken, so there is nothing to cite. Leaving Requests empty and RequestsUnknown
		// false is correct here and is NOT the withheld state: the withheld state means "we took a reading and
		// cannot resolve it", and this means "no reading was taken", which the trace section's own absence
		// already says.
		return
	}
	rows := ar.Methodology.SessionTrace.Rows

	// Refs are minted in a canonical order over the row's identity, not over arrival, so two readings of one
	// cluster line up. Sorted on a copy of the index list: reordering Rows itself would change the document's
	// reading order, which is a record of what happened and not ours to sort.
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ra, rb := rows[order[a]], rows[order[b]]
		if ra.Resource != rb.Resource {
			return ra.Resource < rb.Resource
		}
		return ra.Scope < rb.Scope
	})
	// Width follows the count so the column stays aligned in a monospaced table and sorts lexically for as
	// long as it can — T-04 beside T-11, not T-4 beside T-11.
	width := len(fmt.Sprintf("%d", len(rows)))
	if width < 2 {
		width = 2
	}
	refByTuple := make(map[string]string, len(rows))
	for n, idx := range order {
		ref := fmt.Sprintf("T-%0*d", width, n+1)
		rows[idx].Ref = ref
		// Two rows can share a tuple when they differ by scope. The first in canonical order wins the tuple
		// lookup, and the other is still individually citable by its own Ref — a kind-level citation cannot
		// distinguish them anyway, because a kind does not carry a scope.
		if _, seen := refByTuple[rows[idx].Resource]; !seen {
			refByTuple[rows[idx].Resource] = ref
		}
	}

	// The inversion: tuple → the rules that consumed the reading. Built from the same registry the basis came
	// from, so a rule cannot appear in one and not the other.
	deps := FindingDependencies()
	consumers := map[string]map[string]bool{}
	for ruleID, d := range deps {
		for _, kind := range d.Kinds {
			tuple, ok := collect.StepTuple(kind)
			if !ok {
				continue
			}
			if consumers[tuple] == nil {
				consumers[tuple] = map[string]bool{}
			}
			consumers[tuple][ruleID] = true
		}
	}
	// Only rules that actually produced a finding in THIS report are named. A registry-wide list would tell
	// the reader that a request fed a rule which, in this run, found nothing and appears nowhere else in the
	// document — a citation pointing at an absence.
	fired := map[string]bool{}
	for _, f := range ar.Findings {
		fired[f.RuleID] = true
	}
	for i := range rows {
		set := consumers[rows[i].Resource]
		if set == nil {
			continue
		}
		var ids []string
		for id := range set {
			if fired[id] {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		rows[i].ConsumedBy = ids
	}

	for i := range ar.Findings {
		b := ar.Findings[i].Basis
		if b == nil {
			continue
		}
		refs, ok := resolveRefs(b.Kinds, refByTuple)
		if !ok {
			b.Requests = nil
			b.RequestsUnknown = true
			continue
		}
		b.Requests = refs
		b.RequestsUnknown = false
	}
}

// resolveRefs turns a finding's kinds into ledger references, and returns false if ANY of them cannot be
// resolved — see FindingBasis.RequestsUnknown for why a partial answer is refused rather than trimmed.
//
// A kind with a tuple but no row is as unresolvable as a kind with no tuple, and for a subtler reason: it means
// the step never issued a request in this session, so citing its kind would point the reader at a row that is
// not there. Both cases withhold.
func resolveRefs(kinds []string, refByTuple map[string]string) ([]string, bool) {
	if len(kinds) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	var out []string
	for _, kind := range kinds {
		tuple, ok := collect.StepTuple(kind)
		if !ok {
			return nil, false
		}
		ref, ok := refByTuple[tuple]
		if !ok {
			return nil, false
		}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out, true
}
