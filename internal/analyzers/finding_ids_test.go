package analyzers

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// AN ANALYZER MUST DECLARE THE FINDING IDS IT CAN PRODUCE.
//
// THE PROBLEM THIS ENDS. `StackAnalyzer.ID()` is a REGISTRATION id — "stack.hpa.sanity",
// "stack.monitoring.prometheus" — and **no finding carries one**. The ids findings actually carry are
// different and more specific: "stack.hpa.no-headroom", "stack.monitoring.prometheus-storage-ephemeral".
// Nothing declared them, so every gate that needed them SCANNED THE PACKAGE'S SOURCE with a regex over
// `"stack\..."` literals — and the ids are minted in three different shapes:
//
//	istio.go       a named const                 (ruleIstioPermissiveMTLS)
//	hpa.go         a helper ARGUMENT             ("stack.hpa.no-headroom", ns, name, …)
//	monitoring.go  four types in one file        (a file-level scan cannot say which type emits which)
//
// A scanner has to know all three. A declared method has to know none of them, and the compiler checks it.
//
// WHAT IT COST. Three defects this stretch came from "which registry does 'the rules' mean": the
// claim-boundary gate walked `rules.All()` and reported sixteen analyzer ids as invented; the coverage gate
// walked the same registry and called fifteen analyzers covered when they had nothing; and the end-to-end
// test walked it too, so the analyzer path never ran against a real API server (M-55, M-56). I then made
// the same mistake myself while measuring, comparing registration ids against the boundary table and
// reporting a defect that did not exist.
//
// TWO ANALYZERS DECLARE NOTHING, AND THAT IS A FACT RATHER THAN AN OMISSION. `CalicoPolicy.Analyze` and
// `CiliumPolicy.Analyze` return nil by design — they exist so `netpol.go` can count policy objects instead
// of falling back to its honest 0.45 confidence. An empty declaration says so out loud, and stops a
// coverage gate demanding boundary text for findings nobody emits.
func TestEveryAnalyzerDeclaresItsFindingIDs(t *testing.T) {
	// The registration id is not a finding id, and this is the assertion that keeps the two apart.
	for _, a := range All() {
		for _, id := range a.FindingIDs() {
			if id == a.ID() {
				t.Errorf("%s declares its own REGISTRATION id %q as a finding id. No finding carries a "+
					"registration id (B-108 was exactly that confusion); declare the id findings carry.",
					a.ID(), id)
			}
			if !strings.HasPrefix(id, "stack.") {
				t.Errorf("%s declares finding id %q, which is not in the stack.* namespace this registry "+
					"owns", a.ID(), id)
			}
		}
	}

	// EVERY DECLARED ID HAS A CLAIM BOUNDARY. This is the coverage the register recorded as closed and the
	// gate could only check by regex. Now it is a method call.
	for _, a := range All() {
		for _, id := range a.FindingIDs() {
			if len(boundaries.For(id)) == 0 {
				t.Errorf("%s can produce %q and internal/boundaries has no family naming it, so the "+
					"pipeline would stamp that finding with nothing", a.ID(), id)
			}
		}
	}

	// THE ORPHAN DIRECTION — a family naming an id nobody emits — IS PROVEN IN internal/rules, NOT HERE.
	//
	// It was here for an hour, and then the dependency direction turned out to allow something better:
	// internal/rules/boundaries_test.go now merges this registry's declarations into its own and checks
	// every family entry against BOTH producers in one place. Measured with `go list -deps`, neither
	// package imports the other, so that gate takes a TEST-ONLY import of this one — invisible to
	// scripts/depcheck.sh, which walks the shipped graph.
	//
	// Asserting it in both places would be two gates over one property, which is the duplication these
	// gates exist to prevent. What stays here is what only this package can say: an id is not a
	// registration id, it is in the stack.* namespace, and it has a boundary.
	declared := map[string]bool{}
	for _, a := range All() {
		for _, id := range a.FindingIDs() {
			declared[id] = true
		}
	}

	if len(declared) == 0 {
		t.Fatal("no analyzer declares any finding id, so every assertion above passed over an empty set")
	}
	t.Logf("%d finding id(s) declared across %d analyzer(s)", len(declared), len(All()))
}

// AN ANALYZER MAY ONLY EMIT AN ID IT DECLARED.
//
// The declaration is a promise about behaviour, and a promise nothing checks is a comment. This runs each
// analyzer over an inventory and asserts every finding's RuleID was declared. It cannot prove the reverse —
// that a declared id is reachable — because that needs a cluster with the operator on it, which is what
// internal/e2e/mesh_test.go is for.
func TestAnalyzers_EmitOnlyDeclaredIDs(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 15 {
		t.Fatalf("the registry holds %d stack analyzer(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	inv := &collect.Inventory{}
	for _, a := range All() {
		ok := map[string]bool{}
		for _, id := range a.FindingIDs() {
			ok[id] = true
		}
		for _, f := range a.Analyze(inv) {
			if !ok[f.RuleID] {
				t.Errorf("%s emitted %q, which it does not declare in FindingIDs()", a.ID(), f.RuleID)
			}
		}
	}
}
