package pipeline

import (
	"sort"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// EVERY PRODUCER IN THE DEPENDENCY REGISTRY IS ONE SOMETHING CAN MINT.
//
// internal/history looks a finding's dependencies up by `f.RuleID` — the id on the finding — to decide
// whether a finding that is gone was fixed or simply not looked for. A producer it cannot describe is
// REFUSED, which is the safe answer and also a silent one.
//
// The analyzer half of this map was keyed by the ANALYZER's id (`stack.certmanager.expiry`) while the
// findings carry the ids the analyzer declares (`stack.certmanager.expiring`, `stack.certmanager.not-
// issued`). Two vocabularies, one map: all fifteen analyzer keys named nothing that can appear on a
// finding, and all sixteen ids that can were absent. Every analyzer finding in every comparison was
// answered with "is not a rule this build knows" — the comparison covered the rule half of the engine and
// said nothing about the other, which is M-58's mechanism in a third table.
func TestFindingDependencies_EveryProducerIdIsOneSomethingCanMint(t *testing.T) {
	real := map[string]bool{}
	for _, r := range rules.All() {
		real[r.ID()] = true
	}
	if n := len(rules.All()); n < 80 {
		t.Fatalf("the rule registry holds %d rule(s); this comparison would then be measuring a fraction", n)
	}
	analyzerIDs := 0
	for _, a := range analyzers.All() {
		for _, id := range a.FindingIDs() {
			real[id] = true
			analyzerIDs++
		}
	}
	if analyzerIDs < 15 {
		t.Fatalf("the analyzers declare %d finding id(s); this comparison would then be measuring a "+
			"fraction of the second producer", analyzerIDs)
	}

	deps := FindingDependencies()
	var ghost, absent []string
	for id := range deps {
		if !real[id] {
			ghost = append(ghost, id)
		}
	}
	for id := range real {
		if _, ok := deps[id]; !ok {
			absent = append(absent, id)
		}
	}
	sort.Strings(ghost)
	sort.Strings(absent)

	for _, id := range ghost {
		t.Errorf("the dependency registry describes %q and nothing can mint it. A key in one vocabulary "+
			"read with another is a producer nobody can look up.", id)
	}
	for _, id := range absent {
		t.Errorf("%q can appear on a finding and the dependency registry does not describe it, so every "+
			"comparison of a finding with that id is refused with \"is not a rule this build knows\".", id)
	}
	t.Logf("%d producer(s) in the registry, %d id(s) something can mint", len(deps), len(real))
}
