package rules

import "github.com/Shoalcheck/shoalcheck-scan/internal/collect"

// podsByNamespace is the indices into inv.Pods in each namespace, in inventory order.
//
// A SELECTOR IS NAMESPACED, SO ITS SEARCH IS TOO. A Service, a PDB or a NetworkPolicy selects pods in its own
// namespace only, and a rule that walks every pod in the cluster for every such object pays services × pods for
// an answer that lives in one namespace's share of them — on 2,000 Services and 34,000 pods, sixty-eight million
// comparisons to find a few thousand. Reading from this index visits the same pods in the same order, so what the
// rule says does not change; only what it costs.
func podsByNamespace(inv *collect.Inventory) map[string][]int {
	out := map[string][]int{}
	for i := range inv.Pods {
		out[inv.Pods[i].Namespace] = append(out[inv.Pods[i].Namespace], i)
	}
	return out
}
