package collect

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// KUBERNETES' OWN GROUPS ARE NOT OPERATORS.
//
// Measured on a real two-cluster fleet: the divergence table's `operators.installed` row read
// "apps, autoscaling, batch, policy" for docker-desktop — a cluster with no operator installed on it — and
// listed the same four alongside Istio's and Prometheus's groups for the testbed. The exclusion here
// covered "" and *.k8s.io, and the BARE-WORD groups are exactly the ones a suffix test misses.
//
// A fleet comparison is a sentence a reader acts on. "Operators installed: apps, batch" is not a small
// wording problem: it is the tool reporting Kubernetes as somebody's operator.
func TestPolicyPosture_TheBuiltInGroupsAreNotOperators(t *testing.T) {
	inv := &Inventory{
		PresentGVRs: GVRSet{
			{Group: "apps", Version: "v1", Resource: "deployments"}:                     {},
			{Group: "batch", Version: "v1", Resource: "jobs"}:                           {},
			{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}:          {},
			{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}: {},
			{Group: "extensions", Version: "v1beta1", Resource: "ingresses"}:            {},
			{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}:      {},
			{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"}: {},
			{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheuses"}:   {},
		},
	}
	inv.Meta.Collected = []string{"server-resources"}
	pp := buildPolicyPosture(inv)
	if pp == nil {
		t.Fatal("no posture built, so this assertion is vacuous")
	}
	for _, g := range pp.Operators {
		if types.KubernetesOwnGroup(g) {
			t.Errorf("%q is a group Kubernetes itself ships and is reported as an installed operator: %v", g, pp.Operators)
		}
	}
	// AND THE REAL ONES SURVIVE, or the fix is a deletion dressed as a correction.
	want := map[string]bool{"networking.istio.io": true, "monitoring.coreos.com": true}
	got := map[string]bool{}
	for _, g := range pp.Operators {
		got[g] = true
	}
	for g := range want {
		if !got[g] {
			t.Errorf("%q is somebody's operator group and is missing: %v", g, pp.Operators)
		}
	}
	if len(pp.Operators) != len(want) {
		t.Errorf("Operators = %v, want exactly the two vendor groups", pp.Operators)
	}
}
