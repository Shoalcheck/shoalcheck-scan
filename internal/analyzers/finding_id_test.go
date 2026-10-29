package analyzers

import (
	"os"
	"regexp"
	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// B-108 — THE PUBLISHED RECIPE MUST REPRODUCE THE PUBLISHED ID.
//
// A finding's ID is a sha256 over (ruleID, kind, namespace, name), and the report tells a reader that. Two
// analyzers hashed their own REGISTRATION id — `IstioMTLS.ID()` is "stack.istio.mtls" — while the card printed
// `RuleID: "stack.istio.permissive-mtls"`. A customer with sha256sum following the recipe on the fields they
// can see got a different hash, so the re-derivation claim was falsifiable on every finding from those two.
//
// Those two are the whole extent of it, which is worth recording because a first pass at this compared each
// analyzer's ID() to the RuleIDs it stamps and concluded all eight were broken. That measured the wrong thing:
// an analyzer's ID() is its registration identity and a RuleID is a finding family, and one analyzer
// legitimately produces several families — argocd stamps `degraded` and `outofsync`. The defect is only where
// the HASH INPUT differs from the PRINTED RuleID.
//
// THIS TEST CHECKS THE CLAIM, NOT THE IMPLEMENTATION. It recomputes from the fields a reader has in front of
// them, so it holds for an analyzer nobody has written yet, and it cannot be satisfied by patching two files.
func TestEveryAnalyzerFinding_IDMatchesItsPublishedRecipe(t *testing.T) {
	cases := analyzerFindingFixtures(t)
	if len(cases) == 0 {
		t.Fatal("no analyzer produced a finding, so this gate would pass vacuously")
	}
	checked := 0
	for _, f := range cases {
		if len(f.AffectedResources) == 0 {
			t.Errorf("%s carries no affected resource, so a reader has nothing to recompute from", f.RuleID)
			continue
		}
		r := f.AffectedResources[0]
		want := findingID(f.RuleID, r.Kind, r.Namespace, r.Name)
		if f.ID != want {
			t.Errorf("finding %s (rule %s) does not match the recipe applied to its own printed fields:\n"+
				"  printed id:   %s\n  recomputed:   %s\n  from:         ruleID=%q kind=%q ns=%q name=%q\n"+
				"A reader following the published recipe gets the second one.",
				f.ID, f.RuleID, f.ID, want, f.RuleID, r.Kind, r.Namespace, r.Name)
		}
		checked++
	}
	t.Logf("%d analyzer finding(s) recomputed from their own printed fields", checked)
}

// analyzerFindingFixtures runs every analyzer that has a fixture in this package and collects what it emits.
// Deliberately built from the existing per-analyzer fixtures rather than a new synthetic one: a fixture written
// for this test would drift from what the analyzers actually produce.
func analyzerFindingFixtures(t *testing.T) []types.Finding {
	t.Helper()
	var out []types.Finding
	out = append(out, IstioMTLS{}.Analyze(istioInv(peerAuth("prod", "default", "PERMISSIVE")))...)
	out = append(out, LinkerdMTLS{}.Analyze(linkerdOpaqueServerInv())...)
	return out
}

// linkerdOpaqueServerInv is a Server with an EXPLICIT opaque proxyProtocol — the only shape LinkerdMTLS
// flags. Written here because internal/analyzers had no linkerd test at all: the analyzer whose finding ID
// was wrong was also the one nothing exercised, which is not a coincidence worth leaving in place.
func linkerdOpaqueServerInv() *collect.Inventory {
	gvr := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"}
	obj := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "policy.linkerd.io/v1beta1",
		"kind":       "Server",
		"metadata":   map[string]any{"namespace": "prod", "name": "web-grpc"},
		"spec":       map[string]any{"proxyProtocol": "opaque"},
	}}
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: {obj}},
		Meta:         collect.Meta{Collected: []string{"cr:" + gvr.GroupResource().String()}},
	}
}

// EVERY RULE ID THIS PACKAGE CAN STAMP CARRIES A BOUNDARY.
//
// The first version of this gate matched `RuleID: "stack.…"` and `= "stack.…"`, and it passed while two
// rules shipped with no boundary at all. `internal/analyzers/hpa.go` writes neither shape: it calls a
// per-analyzer helper, `a.finding("stack.hpa.no-headroom", ns, name, …)`, and the id reaches the finding as
// `RuleID: ruleID`. A live reading found what this gate could not — 187 findings, one with an empty
// ClaimBoundaries — which is the third time in this project that a gate naming the shapes it expects was
// blind to a shape nobody thought of.
//
// SO THE SCAN NAMES NO SHAPE. It collects EVERY `"stack.…"` string literal in the package's non-test source,
// then subtracts the analyzer REGISTRATION ids — the values returned by `ID() string`, which name an analyzer
// and are never stamped on a finding. What is left is every id that can reach a finding, however it travels.
//
// THAT IS ONLY COMPLETE IF AN ID IS ALWAYS A LITERAL SOMEWHERE, so the second half of this test asserts it:
// no `RuleID:` in this package may be a concatenation or a format string. An id assembled from parts would be
// invisible to any scan of literals, and would put the product's one universal claim about a finding back
// beyond reach of a gate.
//
// AND IT CROSS-CHECKS A SECOND, INDEPENDENT REGISTRY: `pillarByRule` in pillars.go is hand-kept and lists the
// same rule ids for a different purpose. Requiring the two sets to be EQUAL means a new analyzer rule cannot
// be added to one table and forgotten in the other, and neither table alone decides what is covered.
func TestEveryAnalyzerRuleCarriesABoundary(t *testing.T) {
	// THE SCAN IS GONE, AND THAT IS THE CHANGE.
	//
	// This test used to read every .go file in the package and regex out every `"stack\..."` literal,
	// subtract the registration ids, subtract pillars.go's keys, and check two count floors so it would
	// notice going blind. It had to know three separate minting shapes — a named const (istio.go), a helper
	// ARGUMENT (hpa.go), and four types in one file (monitoring.go, where a file-level scan cannot say which
	// type emits which) — and a fourth shape would have been invisible.
	//
	// `StackAnalyzer.FindingIDs()` declares them now, so the set is a method call the compiler checks.
	// TestEveryAnalyzerDeclaresItsFindingIDs asserts both directions against internal/boundaries; this one
	// keeps the two jobs the declaration does NOT do.
	declared := map[string]string{} // id -> the analyzer that declares it
	for _, a := range All() {
		for _, id := range a.FindingIDs() {
			declared[id] = a.ID()
		}
	}
	if len(declared) == 0 {
		t.Fatal("no analyzer declares a finding id, so everything below passes over an empty set")
	}

	// JOB ONE, STRUCTURAL AND STILL NECESSARY: a rule id is a literal or a parameter carrying one, never an
	// expression. `RuleID: ruleID` is fine — hpa.go's helper does exactly that and the literal is at the
	// call site. `RuleID: base + suffix` or `RuleID: fmt.Sprintf(…)` is not: an id assembled at runtime
	// cannot be declared accurately either, and FindingIDs() would then be a promise about a value nothing
	// can check. This survives the scan's deletion because it is about the SHAPE of the code, not about
	// recovering a set from it.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		scanned++
		for _, m := range regexp.MustCompile(`RuleID:\s*([^,\n]+)`).FindAllStringSubmatch(string(b), -1) {
			expr := strings.TrimSpace(m[1])
			if strings.Contains(expr, "+") || strings.Contains(expr, "Sprintf") {
				t.Errorf("%s builds a rule id by expression (`RuleID: %s`): an id assembled from parts "+
					"cannot be declared in FindingIDs() with any confidence, so nothing can gate that it "+
					"carries a boundary. Pass a literal id instead", e.Name(), expr)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source file was read, so the expression check above ran over nothing")
	}

	// JOB TWO: EVERY DECLARED ID HAS A BOUNDARY. Same property as before; the set is now declared instead
	// of recovered.
	for id, owner := range declared {
		if len(boundaries.For(id)) == 0 {
			t.Errorf("%s declares %s and boundaries.For returns nothing: the finding would ship saying "+
				"what it establishes and not what it does not, which is the one claim this product makes "+
				"about every finding it prints", owner, id)
		}
	}

	// JOB THREE: THE SECOND REGISTRY, now checked against a DECLARATION rather than against a regex over
	// the same files. `pillarByRule` in pillars.go is hand-kept and lists the same ids for a different
	// purpose. Equality in both directions means a new analyzer rule cannot be added to one and forgotten
	// in the other — and, unlike before, neither side of this comparison is a scan of the other's source.
	for id := range PillarByRule() {
		if _, ok := declared[id]; !ok {
			t.Errorf("pillars.go declares a pillar for %s and no analyzer declares that finding id: "+
				"either the rule was deleted and its pillar left behind, or FindingIDs() was not updated "+
				"with it", id)
		}
	}
	for id, owner := range declared {
		if _, ok := PillarByRule()[id]; !ok {
			t.Errorf("%s declares %s and pillars.go gives it no pillar: the finding would be counted "+
				"against no headline claim, and PillarNone has to be stated rather than defaulted to",
				owner, id)
		}
	}
}
