package analyzers

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (CiliumPolicy) ID() string                                  { return "stack.cilium.policy" }
func (CiliumPolicy) FindingIDs() []string                        { return nil } // Analyze returns nil: this exists so netpol.go can count, not to report
func (CiliumPolicy) Version() string                             { return "1.0.0" }
func (CiliumPolicy) RequiredGVRs() []schema.GroupVersionResource { return ciliumGVRs() }
func (CiliumPolicy) Analyze(*collect.Inventory) []types.Finding  { return nil } // counts feed netpol.go

// CiliumPolicyCounts returns, per namespace, the number of CiliumNetworkPolicy
// objects, plus the count of cluster-wide CiliumClusterwideNetworkPolicy (which
// apply to every namespace). Returns ok=false when the Cilium CRDs were not
// present/collected so netpol.go keeps its honest 0.45 fallback.
func CiliumPolicyCounts(inv *collect.Inventory) (perNS map[string]int, clusterWide int, ok bool) {
	const group = "cilium.io"
	if !inv.PresentGVRs.Has(ciliumGVRs()[0]) || !listSucceeded(inv, group, "ciliumnetworkpolicies") {
		return nil, 0, false
	}
	perNS = map[string]int{}
	for _, p := range stackObjects(inv, group, "ciliumnetworkpolicies") {
		ns, _, _ := unstructured.NestedString(p.Object, "metadata", "namespace")
		perNS[ns]++
	}
	clusterWide = len(stackObjects(inv, group, "ciliumclusterwidenetworkpolicies"))
	return perNS, clusterWide, true
}
