package analyzers

import (
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// run.go — running the whole registry, in one place.
//
// WHY THIS EXISTS. `internal/pipeline` held the loop and its GVR gate, and the end-to-end test held neither:
// it walked `rules.All()` and stopped, so on a live cluster the ANALYZER PATH WAS NEVER EXERCISED — fifteen
// rules, a dynamic client, and a presence gate, none of it run against a real API server by anything.
//
// That is the two-producer blindness this project has now hit three times: the claim-boundary gate walked
// `rules.All()` and reported sixteen analyzer ids as invented; the boundary COVERAGE gate walked the same
// registry and called fifteen analyzers covered when they had nothing; and the e2e test walked it too.
// Every gate written about "the rules" has to say which registry it means.
//
// The fix is not a second copy of the loop in the test. It is one function both callers use, so a cluster
// that has an operator's CRDs and a cluster that does not are both covered by whatever exercises either
// caller.

// RunAll evaluates every analyzer whose required CRDs are PRESENT on the cluster and returns their findings.
//
// An analyzer for an absent operator emits nothing, and that is a gate rather than an accident: without it
// each one would issue a List against a resource the API server does not serve, and a 404 is not a finding.
// See StackAnalyzer.RequiredGVRs and collect.Inventory.PresentGVRs.
//
// FOUR COPIES OF THE PRESENCE PREDICATE EXISTED when this was written: hasAllGVRs here, an identical
// hasAllAnalyzerGVRs in internal/pipeline, the loop in internal/pipeline/determinism_test.go whose comment
// promised "the same GVR gate" and delivered it by duplication, and — briefly — a fifth I added while
// extracting this, before finding the one that was already here. The predicate stays unexported and this
// function is what both packages call.
func RunAll(inv *collect.Inventory) []types.Finding {
	var out []types.Finding
	for _, a := range Eligible(inv) {
		out = append(out, a.Analyze(inv)...)
	}
	return out
}

// Eligible is the analyzers whose required CRDs this cluster serves — the ones RunAll will actually call.
//
// IT EXISTS SO A CHECK CAN PRINT ITS DENOMINATOR. The end-to-end test asserted that no analyzer fires on a
// cluster serving no custom resources, and that condition is never true: plain kind serves 67 GVRs through
// discovery, so the assertion was dead on every cluster it would ever run against — a check reporting a
// pass over an empty set, which is the mistake this project keeps finding in its own gates. What a live run
// can honestly say is "N of 15 were eligible here, and M of those produced a finding", and that sentence
// needs this count.
func Eligible(inv *collect.Inventory) []StackAnalyzer {
	var out []StackAnalyzer
	for _, a := range All() {
		if hasAllGVRs(inv.PresentGVRs, a.RequiredGVRs()) {
			out = append(out, a)
		}
	}
	return out
}
