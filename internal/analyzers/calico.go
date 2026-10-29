package analyzers

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (CalicoPolicy) ID() string                                  { return "stack.calico.policy" }
func (CalicoPolicy) FindingIDs() []string                        { return nil } // Analyze returns nil: this exists so netpol.go can count, not to report
func (CalicoPolicy) Version() string                             { return "1.0.0" }
func (CalicoPolicy) RequiredGVRs() []schema.GroupVersionResource { return calicoGVRs() }
func (CalicoPolicy) Analyze(*collect.Inventory) []types.Finding  { return nil } // counts feed netpol.go

// CalicoPolicyCounts returns, per namespace, the number of Calico (namespaced)
// NetworkPolicy objects, plus the count of cluster-wide GlobalNetworkPolicy.
// Returns ok=false when the Calico CRDs were not present/collected so netpol.go
// keeps its honest 0.45 fallback.
func CalicoPolicyCounts(inv *collect.Inventory) (perNS map[string]int, clusterWide int, ok bool) {
	const group = "projectcalico.org"
	// The namespaced kind is projectcalico.org networkpolicies; gate on its GVR.
	nsGVR := schema.GroupVersionResource{Group: group, Version: "v3", Resource: "networkpolicies"}
	if !inv.PresentGVRs.Has(nsGVR) || !listSucceeded(inv, group, "networkpolicies") {
		return nil, 0, false
	}
	perNS = map[string]int{}
	for _, p := range stackObjects(inv, group, "networkpolicies") {
		ns, _, _ := unstructured.NestedString(p.Object, "metadata", "namespace")
		perNS[ns]++
	}
	clusterWide = len(stackObjects(inv, group, "globalnetworkpolicies"))
	return perNS, clusterWide, true
}
