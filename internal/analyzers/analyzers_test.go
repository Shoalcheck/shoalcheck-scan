package analyzers

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

func TestAllRegistryNonEmptyAndStable(t *testing.T) {
	first := All()
	if len(first) == 0 {
		t.Fatal("All() registry is empty")
	}
	second := All()
	if len(first) != len(second) {
		t.Fatalf("registry length unstable: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID() != second[i].ID() {
			t.Errorf("registry order unstable at %d: %q vs %q", i, first[i].ID(), second[i].ID())
		}
	}
	seen := map[string]bool{}
	for _, a := range first {
		if a.ID() == "" {
			t.Errorf("analyzer with empty ID(): %T", a)
		}
		if seen[a.ID()] {
			t.Errorf("duplicate analyzer ID %q", a.ID())
		}
		seen[a.ID()] = true
		if a.Version() == "" {
			t.Errorf("analyzer %q has empty Version()", a.ID())
		}
	}
}

func TestRequiredGVRsUnionDedupsAndCoversAnalyzers(t *testing.T) {
	union := RequiredGVRsUnion()
	set := map[schema.GroupVersionResource]int{}
	for _, gvr := range union {
		set[gvr]++
	}
	for gvr, n := range set {
		if n != 1 {
			t.Errorf("GVR %v appears %d times in the union (must be deduped)", gvr, n)
		}
	}
	// cert-manager Certificate must be in the union; HPA contributes none.
	want := schema.GroupVersionResource{Group: "cert-manager.io", Resource: "certificates"}
	found := false
	for _, gvr := range union {
		if gvr.Group == want.Group && gvr.Resource == want.Resource {
			found = true
		}
	}
	if !found {
		t.Errorf("union missing cert-manager certificates GVR: %v", union)
	}
}

func TestListSucceededMatchesCollectorKey(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	// The collector records cr:<gvr.GroupResource().String()>.
	collectedKey := "cr:" + gvr.GroupResource().String()

	collected := &collect.Inventory{Meta: collect.Meta{Collected: []string{collectedKey}}}
	if !listSucceeded(collected, gvr.Group, gvr.Resource) {
		t.Errorf("listSucceeded must be true when %q is in Meta.Collected", collectedKey)
	}
	denied := &collect.Inventory{Meta: collect.Meta{
		Collected: []string{"deployments"},
		Denied:    []string{collectedKey + ": certificates.cert-manager.io is forbidden"},
	}}
	if listSucceeded(denied, gvr.Group, gvr.Resource) {
		t.Errorf("listSucceeded must be false when %q is in Meta.Denied", collectedKey)
	}
	notRecorded := &collect.Inventory{Meta: collect.Meta{Collected: []string{"deployments"}}}
	if listSucceeded(notRecorded, gvr.Group, gvr.Resource) {
		t.Error("listSucceeded must be false when the GVR is neither collected nor denied (un-confirmed)")
	}
}

// TestHasAllGVRsGate pins the registry gate helper: present-set membership
// drives whether an analyzer runs. An HPA-style analyzer with no RequiredGVRs
// always passes the gate.
// SUPERSEDED, not deleted for tidiness. This test asserted three cases — every wanted GVR present, one
// absent, and none wanted — and TestHasAllGVRs_IsAllNotAny in run_test.go asserts those three plus the one
// that separates ALL from ANY: two wanted and one present, which is a partial read and must be refused. A
// second test over the same predicate is how two tests eventually disagree about what it should do, so this
// one names its replacement instead of standing beside it.
