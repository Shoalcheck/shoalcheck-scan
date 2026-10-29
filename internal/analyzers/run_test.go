package analyzers

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// THE PRESENCE GATE IS ALL-OR-NOTHING, AND THE "ANY" VERSION LOOKS IDENTICAL FROM THE OUTSIDE.
//
// An analyzer that reads two custom resources and finds one cannot say anything about the pair, and a
// partial read is the state this product refuses to report as a finding. On a cluster with one of the two
// CRDs, an `any` gate would run the analyzer, its second List would 404, and whatever it concluded from the
// half it got would ship as a finding — with nothing on any surface saying half the input was missing.
//
// Both directions are asserted because only one of them fails when the quantifier flips.
func TestHasAllGVRs_IsAllNotAny(t *testing.T) {
	a := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	b := schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "servicemonitors"}

	both := collect.GVRSet{a: {}, b: {}}
	onlyA := collect.GVRSet{a: {}}
	// A NIL SET, not an empty one: Has must not panic on it, which is the state an inventory is in before
	// discovery has run and the state TestRunAll_NoCRDsMeansNoFindings hands RunAll below.
	var none collect.GVRSet

	for _, tc := range []struct {
		name    string
		present collect.GVRSet
		want    []schema.GroupVersionResource
		ok      bool
	}{
		{"needs nothing, so anything satisfies it", none, nil, true},
		{"needs one, cluster has it", onlyA, []schema.GroupVersionResource{a}, true},
		{"needs one, cluster has none", none, []schema.GroupVersionResource{a}, false},
		{"needs two, cluster has both", both, []schema.GroupVersionResource{a, b}, true},
		{"needs two, cluster has ONE — a partial read, refused", onlyA, []schema.GroupVersionResource{a, b}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAllGVRs(tc.present, tc.want); got != tc.ok {
				t.Errorf("hasAllGVRs = %v, want %v", got, tc.ok)
			}
		})
	}
}

// A CLUSTER WITH NO OPERATOR CRDs YIELDS NO ANALYZER FINDINGS, AND THAT IS A GATE.
//
// It is the state every plain cluster is in, and the one the end-to-end test runs against. What it proves is
// narrow and worth having: the whole registry is walked, every RequiredGVRs is consulted, and not one
// analyzer emits a finding it has no data for. An analyzer that forgot to declare its GVRs would fire here
// on an empty inventory.
//
// WHAT IT DOES NOT ESTABLISH: that any analyzer works. That needs a cluster with the operator installed —
// the kind+Istio+kube-prometheus-stack testbed — and this is not a substitute for it.
func TestRunAll_NoCRDsMeansNoFindings(t *testing.T) {
	inv := &collect.Inventory{}
	if got := RunAll(inv); len(got) != 0 {
		for _, f := range got {
			t.Errorf("an analyzer fired on an inventory with no CRDs and no objects: %s (%s) — it either "+
				"declares no RequiredGVRs or concludes something from an absence", f.RuleID, f.Title)
		}
	}
	if len(All()) == 0 {
		t.Fatal("the registry is empty, so this gate walked nothing and passed over it")
	}
}
