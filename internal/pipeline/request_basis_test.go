package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE JOIN HAS NO PARTIAL VALUE.
//
// Rule dependencies are collector STEP NAMES ("pods", "cr:certificates.cert-manager.io") and a trace row is
// keyed by an apiGroup/RESOURCE tuple ("core/pods"). Nothing in the tree mapped one to the other, which is the
// blocker that made this rung a separate step. Half a map is strictly worse than none: chips that resolve for
// workload rules and dangle for a third of the findings advertise a join the document cannot make.
//
// So the map is asserted total over the registry rather than spot-checked. A new rule declaring a kind nobody
// mapped fails here, at the point the kind is introduced, instead of shipping a document with a dead reference.
func TestEveryKindMapsToAResource(t *testing.T) {
	var missing []string
	kinds := map[string]bool{}
	for id, d := range FindingDependencies() {
		for _, k := range d.Kinds {
			kinds[k] = true
			if _, ok := collect.StepTuple(k); !ok {
				missing = append(missing, k+" (declared by "+id+")")
			}
		}
	}
	if len(kinds) == 0 {
		t.Fatal("no rule declared any kind, so this assertion proved nothing — the registry is empty or " +
			"FindingDependencies stopped reading it")
	}
	if len(missing) > 0 {
		t.Errorf("%d declared kind(s) have no apiGroup/resource tuple, so a finding citing them would render "+
			"a reference into the ledger that resolves to nothing:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("%d distinct kinds, every one mapped", len(kinds))
}

// EVERY CHIP RESOLVES TO A ROW A READER CAN FIND.
//
// A chip is a locator, and a locator into an appendix that has no such row is worse than no chip: it invites
// the reader to check something and then wastes the trip. This walks a real report.
func TestEveryChipResolvesToALedgerRow(t *testing.T) {
	ar := reportWithTrace()
	attachRequestBasis(ar)

	refs := map[string]bool{}
	for _, row := range ar.Methodology.SessionTrace.Rows {
		if row.Ref == "" {
			t.Errorf("a ledger row (%s) has no reference, so nothing can cite it", row.Resource)
			continue
		}
		if refs[row.Ref] {
			t.Errorf("two ledger rows share the reference %q; a citation that resolves to two rows resolves "+
				"to neither", row.Ref)
		}
		refs[row.Ref] = true
	}

	cited := 0
	for _, f := range ar.Findings {
		if f.Basis == nil {
			continue
		}
		for _, ref := range f.Basis.Requests {
			cited++
			if !refs[ref] {
				t.Errorf("finding %s cites %q, which is not a row in this report's ledger", f.ID, ref)
			}
		}
	}
	if cited == 0 {
		t.Fatal("no finding cited any request, so this assertion proved nothing")
	}
	t.Logf("%d citation(s) across %d ledger row(s), all resolving", cited, len(refs))
}

// A REFERENCE IS A POSITION IN A CANONICAL ORDER, NOT AN ARRIVAL NUMBER.
//
// Numbering by arrival makes the same reading of the same cluster produce different numbers whenever the
// collector's concurrency interleaves differently, so two documents of one cluster cannot be laid side by side.
// Numbering by the tuple — which is the row's real identity — makes them line up.
func TestRequestRefsAreCanonical(t *testing.T) {
	forward := reportWithTrace()
	reversed := reportWithTrace()
	rows := reversed.Methodology.SessionTrace.Rows
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	attachRequestBasis(forward)
	attachRequestBasis(reversed)

	got := map[string]string{}
	for _, r := range forward.Methodology.SessionTrace.Rows {
		got[r.Resource+"|"+r.Scope] = r.Ref
	}
	for _, r := range reversed.Methodology.SessionTrace.Rows {
		k := r.Resource + "|" + r.Scope
		if got[k] != r.Ref {
			t.Errorf("%s got %q in one ordering and %q in the other; the reference is following arrival "+
				"order rather than the row's identity", k, got[k], r.Ref)
		}
	}
}

// AN UNMAPPABLE KIND SUPPRESSES THE WHOLE LIST, NOT JUST ITS OWN ENTRY.
//
// This is the rule the spec is sharpest about. A finding resting on four kinds, three of which can be traced,
// must not print three chips: a reader counts them, reads them as the whole basis, and concludes the fourth
// input was never read. Saying "we cannot cite the requests for this one" is the shorter and truer sentence.
func TestRequestBasis_APartialJoinIsWithheld(t *testing.T) {
	ar := reportWithTrace()
	for i := range ar.Findings {
		if ar.Findings[i].Basis != nil {
			ar.Findings[i].Basis.Kinds = append(ar.Findings[i].Basis.Kinds, "a-step-nobody-mapped")
		}
	}
	attachRequestBasis(ar)
	for _, f := range ar.Findings {
		if f.Basis == nil {
			continue
		}
		if len(f.Basis.Requests) > 0 {
			t.Errorf("finding %s printed %d chip(s) while one of its kinds could not be traced; a partial "+
				"list reads as a complete one", f.ID, len(f.Basis.Requests))
		}
		if !f.Basis.RequestsUnknown {
			t.Errorf("finding %s withheld its chips without saying why, which reads as "+
				"\"no requests were issued\"", f.ID)
		}
	}
}

// reportWithTrace is a report whose findings rest on kinds the collector really has, with a ledger holding the
// tuples those kinds map to plus one the findings do not use.
func reportWithTrace() *types.AuditReport {
	return &types.AuditReport{
		Findings: []types.Finding{
			{ID: "f-1", RuleID: "k8s.workload.missing-requests", Basis: &types.FindingBasis{
				Kinds: []string{"deployments", "pods"}}},
			{ID: "f-2", RuleID: "k8s.rbac.wildcard", Basis: &types.FindingBasis{
				Kinds: []string{"clusterrolebindings"}}},
			{ID: "f-3", RuleID: "no.basis.recorded", Basis: nil},
		},
		Methodology: types.Methodology{
			SessionTrace: &types.SessionTrace{
				Rows: []types.SessionTraceRow{
					{Resource: "core/pods", Scope: "cluster", Verbs: []string{"list"}, Requests: 3, Class: "read"},
					{Resource: "apps/deployments", Scope: "cluster", Verbs: []string{"list"}, Requests: 1, Class: "read"},
					{Resource: "rbac.authorization.k8s.io/clusterrolebindings", Scope: "cluster",
						Verbs: []string{"list"}, Requests: 1, Class: "read"},
					{Resource: "core/services", Scope: "cluster", Verbs: []string{"list"}, Requests: 1, Class: "read"},
				},
				Total: 6, Run: 6,
			},
		},
	}
}
