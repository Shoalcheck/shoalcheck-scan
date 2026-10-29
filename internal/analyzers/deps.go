// Analyzer dependencies — the same discipline internal/rules/deps.go documents, for the findings that
// come from the stack analyzers. The pipeline merges both lists into ONE findings slice, so a comparison
// that only knows what the RULES rest on would have no declaration for a third of the findings in the
// report and would have to fall back to withholding every analyzer comparison forever.
//
// Almost none of this is hand-written. An analyzer already declares RequiredGVRs, and the collector
// labels each of those steps "cr:<resource>.<group>" — so the dependency is DERIVED from the declaration
// that already exists, using the same construction the collector uses. A rename of a GVR moves both
// sides at once. Only an analyzer that reads a CORE kind has anything left to declare by hand.
package analyzers

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// CRStepPrefix is how the collector labels a custom-resource list step. An ALIAS of the collector's own
// constant, not a second copy of the string: this package's callers keep the name they already use, and the
// spelling that actually matters is defined once, in the package that mints it.
const CRStepPrefix = collect.CRStepPrefix

// coreKindReader is an optional interface for an analyzer that reads a kind the core collector gathers
// rather than a CRD of its own. HPASanity is the case: it judges inv.HPAs and declares no GVR at all, so
// without this its findings would appear to rest on nothing.
type coreKindReader interface {
	RequiredCoreKinds() []string
}

// RequiredKinds names the collector steps this analyzer's findings rest on: its CRD steps, derived from
// RequiredGVRs, plus any core kinds it declares.
func RequiredKinds(a StackAnalyzer) []string {
	var out []string
	for _, gvr := range a.RequiredGVRs() {
		out = append(out, CRStepPrefix+gvr.GroupResource().String())
	}
	if c, ok := a.(coreKindReader); ok {
		out = append(out, c.RequiredCoreKinds()...)
	}
	sort.Strings(out)
	return out
}

// DependenciesByAnalyzer maps every FINDING ID an analyzer can mint to the collector steps that finding
// rests on. Built from the registry, so it cannot drift from it.
//
// KEYED BY THE FINDING ID, NOT THE ANALYZER'S. It was keyed by a.ID() until 2026-09-15, and the map is read
// by internal/history with the id on a FINDING — `stack.certmanager.expiring`, not
// `stack.certmanager.expiry`. Two vocabularies in one map: all fifteen keys named something no finding
// carries, all sixteen ids a finding can carry were absent, and every analyzer finding in every comparison
// was answered with "is not a rule this build knows". The refusal is the safe answer and it is also a
// silent one, so the comparison covered the rule half of the engine and said nothing about the other.
//
// An analyzer's findings all rest on the same reads — its RequiredGVRs plus any core kinds it declares —
// so every id it mints gets that list. TestFindingDependencies_EveryProducerIdIsOneSomethingCanMint holds
// both directions.
func DependenciesByAnalyzer() map[string][]string {
	out := make(map[string][]string, len(All()))
	for _, a := range All() {
		kinds := RequiredKinds(a)
		for _, id := range a.FindingIDs() {
			out[id] = kinds
		}
	}
	return out
}

// ProducerByFinding maps every finding id an analyzer files under to the analyzer's own id — the id a reading's
// rule set records it by. The comparison needs both halves of that pair: the finding carries one id, the stamp the
// other, and looking one up under the other is how every one-sided analyzer finding was held back as "not part
// of the build" between two readings by one build.
func ProducerByFinding() map[string]string {
	out := map[string]string{}
	for _, a := range All() {
		for _, id := range a.FindingIDs() {
			out[id] = a.ID()
		}
	}
	return out
}
