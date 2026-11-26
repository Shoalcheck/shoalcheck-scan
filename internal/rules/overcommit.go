package rules

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// overcommitFloor is the ratio of memory limits to allocatable past which a node is reported. Limits above
// allocatable are ordinary — that is what a limit above a request buys — so the floor is where the node could not
// hold half of its pods at their limits at once.
const overcommitFloor = 1.5

// NodeMemoryOvercommit reports nodes whose pods' memory LIMITS add up to well past what the node can allocate
// (ENG-31). Requests decide placement and limits decide what a pod may take: when the pods on such a node rise toward
// their limits together, the node runs out before any of them reaches its own, and the kernel or the kubelet chooses
// who dies — BestEffort first, then Burstable by how far it is over its request. The QoS mix is stated, because it
// says who that is.
//
// What it does not establish: that the pods ever rise together (usage is not read here), or that a kill happened.
type NodeMemoryOvercommit struct{}

func (NodeMemoryOvercommit) ID() string      { return "k8s.reliability.node-memory-overcommit" }
func (NodeMemoryOvercommit) Version() string { return "1.0.0" }

func (NodeMemoryOvercommit) RequiredKinds() []string { return []string{"nodes", "pods"} }

func (r NodeMemoryOvercommit) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "nodes") || !observed(inv, "pods") {
		return nil
	}
	type tally struct {
		limits, unlimited                 int64
		guaranteed, burstable, bestEffort int
	}
	on := map[string]*tally{}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		t := on[p.Spec.NodeName]
		if t == nil {
			t = &tally{}
			on[p.Spec.NodeName] = t
		}
		switch qosClass(p) {
		case corev1.PodQOSGuaranteed:
			t.guaranteed++
		case corev1.PodQOSBestEffort:
			t.bestEffort++
		default:
			t.burstable++
		}
		for _, c := range p.Spec.Containers {
			if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				t.limits += q.Value()
			} else {
				t.unlimited++
			}
		}
	}
	var out []types.Finding
	nodes := append([]corev1.Node(nil), inv.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	for i := range nodes {
		n := &nodes[i]
		t := on[n.Name]
		alloc := n.Status.Allocatable.Memory().Value()
		if t == nil || alloc <= 0 {
			continue
		}
		ratio := float64(t.limits) / float64(alloc)
		if ratio < overcommitFloor {
			continue
		}
		facts := []types.Fact{
			types.NewFact("node.memory.limits", t.limits), types.NewFact("node.memory.allocatable", alloc),
			types.NewFact("node.memory.overcommit", ratio), types.NewFact("node.containers.unlimited", t.unlimited),
			types.NewFact("node.pods.guaranteed", t.guaranteed), types.NewFact("node.pods.burstable", t.burstable),
			types.NewFact("node.pods.besteffort", t.bestEffort),
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Node", "", n.Name),
			IDBasis:     &types.ResourceRef{Kind: "Node", Name: n.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Node %s: pods' memory limits are %.1f× what it can allocate", n.Name, ratio),
			Description: fmt.Sprintf("The pods on node %s may together take %.1f× the memory the node can allocate. "+
				"When they rise toward their limits at once, the node runs out first and the kernel or the kubelet "+
				"chooses which pods die; the QoS mix in the evidence says which go first.", n.Name, ratio),
			WhyItMatters: "A memory limit above a request is a loan the node cannot repay to everyone at once; the " +
				"pods that lose are the ones with the least guaranteed, not the ones that used the most.",
			Evidence:          append([]string{snapshotNote(inv)}, overcommitLines(n.Name, facts)...),
			Facts:             facts,
			Severity:          types.SeverityLow,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Node", Name: n.Name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

// overcommitLines are the finding's sentences, rendered from its facts (M-172).
func overcommitLines(node string, fs []types.Fact) []string {
	lines := []string{fmt.Sprintf("node %s: the memory limits of its running pods add up to %s against %s allocatable — %.2f×",
		node, humanMi(int64(types.FactNum(fs, "node.memory.limits"))), humanMi(int64(types.FactNum(fs, "node.memory.allocatable"))),
		types.FactNum(fs, "node.memory.overcommit"))}
	lines = append(lines, fmt.Sprintf("QoS of its pods: %d Guaranteed, %d Burstable, %d BestEffort — under memory pressure "+
		"the kubelet evicts BestEffort first, then Burstable by how far each is over its request",
		int(types.FactNum(fs, "node.pods.guaranteed")), int(types.FactNum(fs, "node.pods.burstable")), int(types.FactNum(fs, "node.pods.besteffort"))))
	if u := int(types.FactNum(fs, "node.containers.unlimited")); u > 0 {
		lines = append(lines, fmt.Sprintf("%s no memory limit at all, so the sum above is a floor: those may take "+
			"whatever the node has", nWord(u, "container has", "containers have")))
	}
	lines = append(lines, "usage is not read here: whether the pods ever rise together is what a monitoring stack's "+
		"node memory pressure would show")
	return lines
}

// qosClass is the pod's QoS class as the kubelet computes it, from status when the API server wrote it.
func qosClass(p *corev1.Pod) corev1.PodQOSClass {
	if p.Status.QOSClass != "" {
		return p.Status.QOSClass
	}
	requests, limits, all := 0, 0, 0
	guaranteed := true
	for _, c := range p.Spec.Containers {
		for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			all++
			rq, hasReq := c.Resources.Requests[r]
			lq, hasLim := c.Resources.Limits[r]
			if hasReq {
				requests++
			}
			if hasLim {
				limits++
			}
			if !hasLim || (hasReq && rq.Cmp(lq) != 0) {
				guaranteed = false
			}
		}
	}
	switch {
	case requests == 0 && limits == 0:
		return corev1.PodQOSBestEffort
	case guaranteed && limits == all:
		return corev1.PodQOSGuaranteed
	}
	return corev1.PodQOSBurstable
}
