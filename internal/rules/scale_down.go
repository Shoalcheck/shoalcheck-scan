package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// NodeScaleDownBlocked reports nodes an autoscaler running in this cluster will not remove, with each documented
// reason it gives (ENG-32). It is the sound negative of a saving: a node nobody needs that cannot be taken away is
// billed for as long as the reason stands, and the reason is a declaration somebody can change.
//
// The reasons are the autoscalers' own published rules, each cited:
//   - Cluster Autoscaler (FAQ "What types of pods can prevent CA from removing a node?"): a pod annotated
//     cluster-autoscaler.kubernetes.io/safe-to-evict: "false"; a pod no controller manages; a pod with local storage
//     (emptyDir or hostPath) under the default --skip-nodes-with-local-storage; a kube-system pod with no
//     PodDisruptionBudget under the default --skip-nodes-with-system-pods; a pod whose budget allows no disruption.
//   - Karpenter (disruption controls): a pod or node annotated karpenter.sh/do-not-disrupt: "true"; a pod whose
//     budget allows no disruption.
//
// WHAT IT DOES NOT ESTABLISH. That the node is idle or that removing it would save anything: the node's price is
// stated as what it bills while blocked, never as a saving, and no dollar is summed. The autoscaler's flags are not
// read (they live in its own arguments); the CA defaults are named as defaults. With no autoscaler detected the rule
// is silent: without one, nothing removes a node anyway.
type NodeScaleDownBlocked struct{}

func (NodeScaleDownBlocked) ID() string      { return "k8s.cost.node-scale-down-blocked" }
func (NodeScaleDownBlocked) Version() string { return "1.0.0" }

func (NodeScaleDownBlocked) RequiredKinds() []string {
	return withWorkloads("nodes", "pods", "poddisruptionbudgets", "server-resources")
}

// detectAutoscaler names the autoscaler this cluster runs: Karpenter when its NodePool API is served or its
// controller runs, Cluster Autoscaler when its Deployment does. "" when neither.
func detectAutoscaler(inv *collect.Inventory) string {
	for gvr := range inv.PresentGVRs {
		if gvr.Group == "karpenter.sh" {
			return "karpenter"
		}
	}
	for _, d := range inv.Deployments {
		switch {
		case strings.Contains(d.Name, "karpenter"):
			return "karpenter"
		case strings.Contains(d.Name, "cluster-autoscaler"):
			return "cluster-autoscaler"
		}
	}
	return ""
}

func (r NodeScaleDownBlocked) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	for _, k := range []string{"nodes", "pods", "poddisruptionbudgets", "deployments"} {
		if !observed(inv, k) {
			return nil
		}
	}
	scaler := detectAutoscaler(inv)
	if scaler == "" {
		return nil
	}
	type budget struct {
		sel  labels.Selector
		zero bool
	}
	budgets := map[string][]budget{} // by namespace: a budget selects only in its own
	for i := range inv.PDBs {
		b := &inv.PDBs[i]
		s, err := metav1.LabelSelectorAsSelector(b.Spec.Selector)
		if err != nil {
			continue
		}
		budgets[b.Namespace] = append(budgets[b.Namespace], budget{s, b.Status.DisruptionsAllowed == 0})
	}
	prices := NodeMonthlyPrices(inv, opts)
	blockers := map[string]map[string][]string{} // node → reason → pods
	add := func(node, reason, pod string) {
		if blockers[node] == nil {
			blockers[node] = map[string][]string{}
		}
		blockers[node][reason] = append(blockers[node][reason], pod)
	}
	for i := range inv.Nodes {
		if n := &inv.Nodes[i]; scaler == "karpenter" && n.Annotations["karpenter.sh/do-not-disrupt"] == "true" {
			add(n.Name, "node-do-not-disrupt", n.Name)
		}
	}
	for i := range inv.Pods {
		p := inv.Pods[i]
		if p.Spec.NodeName == "" || isDaemonSetPod(p) || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if _, mirror := p.Annotations["kubernetes.io/config.mirror"]; mirror {
			continue
		}
		name := p.Namespace + "/" + p.Name
		covered, zero := false, false
		for _, b := range budgets[p.Namespace] {
			if b.sel.Matches(labels.Set(p.Labels)) {
				covered = true
				zero = zero || b.zero
			}
		}
		if zero {
			add(p.Spec.NodeName, "pdb-zero", name)
		}
		switch scaler {
		case "karpenter":
			if p.Annotations["karpenter.sh/do-not-disrupt"] == "true" {
				add(p.Spec.NodeName, "do-not-disrupt", name)
			}
		case "cluster-autoscaler":
			if p.Annotations["cluster-autoscaler.kubernetes.io/safe-to-evict"] == "false" {
				add(p.Spec.NodeName, "safe-to-evict-false", name)
				continue
			}
			if p.Annotations["cluster-autoscaler.kubernetes.io/safe-to-evict"] == "true" {
				continue // the annotation overrides the rules below, by the autoscaler's own rule
			}
			if controllerRef(p) == nil {
				add(p.Spec.NodeName, "unmanaged", name)
			}
			for _, v := range p.Spec.Volumes {
				if v.EmptyDir != nil || v.HostPath != nil {
					add(p.Spec.NodeName, "local-storage", name)
					break
				}
			}
			if p.Namespace == "kube-system" && !covered {
				add(p.Spec.NodeName, "kube-system-no-pdb", name)
			}
		}
	}
	nodes := make([]string, 0, len(blockers))
	for n := range blockers {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var out []types.Finding
	for _, n := range nodes {
		reasons := blockers[n]
		facts := []types.Fact{types.NewFact("scaledown.autoscaler", scaler)}
		var kinds []string
		for k := range reasons {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			sort.Strings(reasons[k])
			facts = append(facts, types.NewFact("scaledown.blocker."+k, len(reasons[k])))
		}
		if p, ok := prices[n]; ok {
			facts = append(facts, types.NewFact("scaledown.billed", p))
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Node", "", n),
			IDBasis:     &types.ResourceRef{Kind: "Node", Name: n},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s will not remove node %s while %s", autoscalerName(scaler), n, blockerSummary(kinds)),
			Description: fmt.Sprintf("The %s running in this cluster does not remove a node holding the pods listed in the "+
				"evidence, by its own published rules. Whether the node is needed was not established; if it is not, it "+
				"is billed for as long as these declarations stand.", autoscalerName(scaler)),
			WhyItMatters: "Scale-down is how an autoscaled cluster's bill follows its load. A node held by one annotation " +
				"or one budget stays whatever the load does, and nothing in the autoscaler's own output says which.",
			Evidence:          scaleDownLines(inv, n, reasons, facts),
			Facts:             facts,
			Severity:          types.SeverityLow,
			Category:          types.CategoryCost,
			PriceBasis:        types.PriceUnpriced, // stated, not summed — as commitment-candidate and the Graviton case
			SpendKind:         types.SpendCompute,
			AffectedResources: []types.ResourceRef{{Kind: "Node", Name: n}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

var blockerSaid = map[string]string{
	"safe-to-evict-false": "annotated cluster-autoscaler.kubernetes.io/safe-to-evict: \"false\" (CA FAQ: a pod that says it is not safe to evict)",
	"unmanaged":           "managed by no controller (CA FAQ: a pod not backed by a controller is not moved)",
	"local-storage":       "with local storage, emptyDir or hostPath (CA FAQ, under the default --skip-nodes-with-local-storage=true)",
	"kube-system-no-pdb":  "in kube-system with no PodDisruptionBudget (CA FAQ, under the default --skip-nodes-with-system-pods=true)",
	"pdb-zero":            "covered by a PodDisruptionBudget that allows no disruption now (both autoscalers respect it)",
	"do-not-disrupt":      "annotated karpenter.sh/do-not-disrupt: \"true\" (Karpenter disruption controls)",
	"node-do-not-disrupt": "the node itself annotated karpenter.sh/do-not-disrupt: \"true\" (Karpenter disruption controls)",
}

// scaleDownLines are the finding's sentences; every count is a fact's value (M-172).
func scaleDownLines(inv *collect.Inventory, node string, reasons map[string][]string, fs []types.Fact) []string {
	lines := []string{snapshotNote(inv)}
	var kinds []string
	for k := range reasons {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		names := reasons[k]
		shown := names
		if len(shown) > 5 {
			shown = shown[:5]
		}
		more := ""
		if len(names) > len(shown) {
			more = fmt.Sprintf(" and %d more", len(names)-len(shown))
		}
		lines = append(lines, fmt.Sprintf("%s %s: %s%s", nWord(int(types.FactNum(fs, "scaledown.blocker."+k)), "pod", "pods"),
			blockerSaid[k], strings.Join(shown, ", "), more))
	}
	if p, ok := types.FactValue(fs, "scaledown.billed"); ok {
		lines = append(lines, fmt.Sprintf("node %s lists at $%.2f/mo: that is what it bills while blocked, not a saving — "+
			"whether the cluster could do without it was not established, and no dollar is added to any total", node, p.(float64)))
	}
	lines = append(lines, "the autoscaler's own flags live in its arguments and were not read; the defaults named above are its defaults")
	return lines
}

func autoscalerName(s string) string {
	if s == "karpenter" {
		return "Karpenter"
	}
	return "Cluster Autoscaler"
}

func blockerSummary(kinds []string) string {
	short := map[string]string{"safe-to-evict-false": "a pod says it is not safe to evict", "unmanaged": "it holds an unmanaged pod",
		"local-storage": "it holds pods with local storage", "kube-system-no-pdb": "it holds kube-system pods without a budget",
		"pdb-zero": "a budget allows no disruption", "do-not-disrupt": "a pod says do-not-disrupt", "node-do-not-disrupt": "it is annotated do-not-disrupt"}
	if len(kinds) == 1 {
		return short[kinds[0]]
	}
	return fmt.Sprintf("%s (and %d other reasons)", short[kinds[0]], len(kinds)-1)
}
