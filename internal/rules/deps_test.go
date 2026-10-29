package rules

import (
	"sort"
	"strings"
	"testing"
)

// Every rule must say what its findings rest on. A rule that declares nothing cannot be compared
// safely: the comparison would have no way to tell "this finding is gone because the cluster changed"
// from "this finding is gone because the input it needed was denied this time".
func TestEveryRuleDeclaresWhatItRestsOn(t *testing.T) {
	for _, r := range All() {
		kinds := r.RequiredKinds()
		if len(kinds) == 0 {
			// A RULE MAY REST ON THE METRICS SOURCE AND ON NO COLLECTOR STEP, and that is a declaration
			// rather than an omission. The temporal family is the case: an alert is a rule plus a time
			// window and scrape health is not an object, so neither has a kind to name — and naming one
			// they do not read would make the comparison withhold whenever an unrelated list was denied.
			//
			// What the gate is actually protecting is that a vanished finding can always be explained. A
			// usage-dependent rule is explained by RunBasis.UsageSource, which the comparison already
			// reads, so the declaration is complete. What stays forbidden is declaring NOTHING at all.
			u, ok := r.(usageDependent)
			if !ok || !u.RequiresUsage() {
				t.Errorf("%s declares no required kinds and does not rest on the metrics source either — "+
					"every rule reads something, and a rule that declares nothing cannot be compared "+
					"safely", r.ID())
			}
			continue
		}
		seen := map[string]bool{}
		for _, k := range kinds {
			if k == "" || strings.TrimSpace(k) != k {
				t.Errorf("%s declares %q — kinds are collector step names, verbatim", r.ID(), k)
			}
			if seen[k] {
				t.Errorf("%s declares %q twice", r.ID(), k)
			}
			seen[k] = true
		}
		if !sort.StringsAreSorted(kinds) {
			t.Errorf("%s declares %v unsorted — a stable order keeps the diff of this list readable", r.ID(), kinds)
		}
	}
}

// DependenciesByRule is what a comparison consumes: it holds only a rule ID, never the rule itself.
func TestDependenciesByRule_CoversTheWholeRegistry(t *testing.T) {
	deps := DependenciesByRule()
	for _, r := range All() {
		d, ok := deps[r.ID()]
		if !ok {
			t.Errorf("%s is in the registry but not in DependenciesByRule", r.ID())
			continue
		}
		if len(d.Kinds) != len(r.RequiredKinds()) {
			t.Errorf("%s: DependenciesByRule reports %v, the rule declares %v", r.ID(), d.Kinds, r.RequiredKinds())
		}
	}
	if len(deps) != len(All()) {
		t.Errorf("DependenciesByRule holds %d entries for %d rules — an ID collision would hide a rule", len(deps), len(All()))
	}
}

// The usage-dependent flag exists for exactly one reason: an audit run with Prometheus and a later one
// without it must not report every rightsizing finding as gone from the cluster.
func TestUsageDependency_IsDeclaredByTheRulesThatCannotRunWithoutIt(t *testing.T) {
	deps := DependenciesByRule()
	if !deps[Rightsizing{}.ID()].Usage {
		t.Error("Rightsizing reads Prometheus usage and produces nothing without it, but does not declare Usage")
	}
	if deps[NodeHeadroom{}.ID()].Usage {
		t.Error("NodeHeadroom declares a usage dependency it does not have — that would suppress a real comparison")
	}
}
