package headline

import (
	"strings"
	"testing"
)

// WHAT COULD NOT BE READ LEADS. A reading through an RBAC role that could list nodes, pods and namespaces and
// nothing else — 24 of 28 kinds refused, measured on the e2e cluster 2026-10-17 — opened on "spot vs
// on-demand unresolved on 3 of 3 nodes", and the refusal was the last clause of the trace line. The largest
// fact about that reading is that most rules never ran; the opening says it first.
func TestSelect_ACoverageGapLeads(t *testing.T) {
	ar := rich()
	ar.Methodology.DeniedKinds = []string{"deployments", "statefulsets", "daemonsets"} // 3 of 5: most
	h := Select(ar)
	if len(h.Lines) == 0 || h.Lines[0].Kind != "coverage-gap" {
		var kinds []string
		for _, l := range h.Lines {
			kinds = append(kinds, l.Kind)
		}
		t.Fatalf("the opening does not lead with what could not be read: %v", kinds)
	}
	l := h.Lines[0]
	total := len(ar.Methodology.CollectedKinds) + 3
	if !strings.Contains(l.Claim, "3 of ") || !strings.Contains(l.Claim, "could not be read") {
		t.Errorf("claim %q does not count what was not read against what was asked (%d)", l.Claim, total)
	}
	if !strings.Contains(l.Basis, "floor") || !strings.Contains(l.Basis, "deployments") {
		t.Errorf("basis %q does not say the counts are a floor and name the kinds", l.Basis)
	}

	// A reading that read everything, or most of it, keeps the claim it is for in front.
	for _, denied := range [][]string{nil, {"networkpolicies"}, {"networkpolicies", "poddisruptionbudgets"}} {
		ar.Methodology.DeniedKinds = denied
		for _, l := range Select(ar).Lines {
			if l.Kind == "coverage-gap" {
				t.Errorf("%d of %d kinds denied displaced the opening: %q", len(denied),
					len(denied)+len(ar.Methodology.CollectedKinds), l.Claim)
			}
		}
	}
}
