package analyzers

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// stackorder_test.go — the CR sweep ranges a map, and a map's range order is randomised per iteration.
//
// It is harmless today for two independent reasons, and NOTHING PINS EITHER: gvrs.go declares one version per
// (group, resource) so at most one key matches, and every emitting analyzer re-sorts its findings by id. Add a
// second version for one resource — which is what a cluster mid-migration serves — or let one analyzer
// aggregate across objects instead of emitting one finding each, and the order becomes whatever the runtime
// gives. This test removes the first reason on purpose, so the sweep has to be ordered by its own code.

func TestStackObjects_IterationOrderIsPinned(t *testing.T) {
	const group, resource = "cert-manager.io", "certificates"
	v1 := schema.GroupVersionResource{Group: group, Version: "v1", Resource: resource}
	beta := schema.GroupVersionResource{Group: group, Version: "v1beta1", Resource: resource}

	obj := func(name string) unstructured.Unstructured {
		return unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": group + "/v1", "kind": "Certificate",
			"metadata": map[string]interface{}{"namespace": "prod", "name": name},
		}}
	}
	inv := &collect.Inventory{StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{
		v1:   {obj("from-v1-a"), obj("from-v1-b")},
		beta: {obj("from-beta-a"), obj("from-beta-b")},
	}}

	names := func() []string {
		var out []string
		for _, o := range stackObjects(inv, group, resource) {
			n, _, _ := unstructured.NestedString(o.Object, "metadata", "name")
			out = append(out, n)
		}
		return out
	}

	first := names()
	if len(first) != 4 {
		t.Fatalf("the sweep returned %d object(s) from two keys of two; it is not reading both", len(first))
	}
	// Repeated many times: one disagreement is enough, and with two keys a single re-run agrees half the time.
	for i := 0; i < 200; i++ {
		got := names()
		for j := range first {
			if got[j] != first[j] {
				t.Fatalf("iteration %d returned a different order at position %d (%s vs %s)\n"+
					"the CR sweep ranges a map, so which version's objects come first is whatever the runtime gave",
					i, j, got[j], first[j])
			}
		}
	}

	// NON-VACUITY: the pinned order must be the one the code chooses, not merely "some fixed order". v1 sorts
	// before v1beta1 as a string, so v1's objects lead — a test that only checked self-consistency would pass
	// on a sweep that returned nothing at all, which the length check above already refuses.
	if first[0] != "from-v1-a" {
		t.Errorf("the sweep does not lead with the lowest GVR's objects: %v", first)
	}
}
