package rules

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// drainGraceFloor is the longest termination grace a node's pods may ask for before the drain's duration is
// reported: ten minutes, past which a node rotation's own timeout (a managed node group's, an upgrade's surge) may
// end the wait before the pod does — and that timeout is the provider's, not readable from the cluster.
const drainGraceFloor = 600

// NodeDrainDuration reports nodes whose drain must wait long for its pods to stop (ENG-33): the longest
// terminationGracePeriodSeconds among the pods an eviction would stop, which is how long the kubelet waits after
// SIGTERM before it kills. With it, the pods behind a Service that have no preStop hook: they can be sent new
// connections in the moments between the signal and their endpoint's removal.
//
// What it does not establish: how long the pods really take (they may exit at once), or the provider's own drain
// timeout, which is set outside the cluster and not read.
type NodeDrainDuration struct{}

func (NodeDrainDuration) ID() string      { return "k8s.reliability.node-drain-duration" }
func (NodeDrainDuration) Version() string { return "1.0.0" }

func (NodeDrainDuration) RequiredKinds() []string { return []string{"nodes", "pods", "services"} }

// drainTiming is one node's two figures.
type drainTiming struct {
	graceMax        int64
	slowest         string // the pod whose grace is the longest
	servicePods     int
	servicePreStop0 int // pods behind a Service with no preStop hook on any container
}

// nodeDrainTimings is every node's timing over the pods an eviction would stop (not DaemonSet pods, not finished).
func nodeDrainTimings(inv *collect.Inventory) map[string]*drainTiming {
	// BY NAMESPACE, because a Service selects only in its own: a pod is matched against its namespace's
	// selectors, never every Service in the cluster.
	svcs := map[string][]labels.Selector{}
	for i := range inv.Services {
		s := &inv.Services[i]
		if len(s.Spec.Selector) > 0 {
			svcs[s.Namespace] = append(svcs[s.Namespace], labels.SelectorFromSet(s.Spec.Selector))
		}
	}
	out := map[string]*drainTiming{}
	for i := range inv.Pods {
		p := inv.Pods[i]
		if p.Spec.NodeName == "" || isDaemonSetPod(p) || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		t := out[p.Spec.NodeName]
		if t == nil {
			t = &drainTiming{}
			out[p.Spec.NodeName] = t
		}
		grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
		if p.Spec.TerminationGracePeriodSeconds != nil {
			grace = *p.Spec.TerminationGracePeriodSeconds
		}
		if grace > t.graceMax || (grace == t.graceMax && p.Namespace+"/"+p.Name < t.slowest) {
			t.graceMax, t.slowest = grace, p.Namespace+"/"+p.Name
		}
		behind := false
		for _, s := range svcs[p.Namespace] {
			if s.Matches(labels.Set(p.Labels)) {
				behind = true
				break
			}
		}
		if !behind {
			continue
		}
		t.servicePods++
		hook := false
		for _, c := range p.Spec.Containers {
			if c.Lifecycle != nil && c.Lifecycle.PreStop != nil {
				hook = true
			}
		}
		if !hook {
			t.servicePreStop0++
		}
	}
	return out
}

func (r NodeDrainDuration) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "nodes") || !observed(inv, "pods") || !observed(inv, "services") {
		return nil
	}
	timings := nodeDrainTimings(inv)
	names := make([]string, 0, len(timings))
	for n := range timings {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []types.Finding
	for _, n := range names {
		t := timings[n]
		if t.graceMax < drainGraceFloor {
			continue
		}
		facts := []types.Fact{types.NewFact("drain.grace.max", t.graceMax), types.NewFact("drain.pods.behind.service", t.servicePods),
			types.NewFact("drain.prestop.missing", t.servicePreStop0)}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Node", "", n),
			IDBasis:     &types.ResourceRef{Kind: "Node", Name: n},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Draining %s can wait %s for one pod to stop", n, graceSaid(t.graceMax)),
			Description: fmt.Sprintf("A pod on node %s asks for %s between the stop signal and the kill. A drain waits "+
				"that long for it, and a node rotation whose own timeout is shorter ends the wait first — that timeout is "+
				"set by the provider, outside the cluster, and is not read here.", n, graceSaid(t.graceMax)),
			WhyItMatters: "A node rotation or an upgrade is a sequence of drains; one node that waits an hour holds the " +
				"whole rotation for that hour, or is cut short by a timeout the pod never agreed to.",
			Evidence:          drainDurationLines(inv, n, t.slowest, facts),
			Facts:             facts,
			Severity:          types.SeverityLow,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Node", Name: n}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

// drainDurationLines are the finding's sentences, rendered from its facts (M-172).
func drainDurationLines(inv *collect.Inventory, node, slowest string, fs []types.Fact) []string {
	lines := []string{snapshotNote(inv),
		fmt.Sprintf("the longest terminationGracePeriodSeconds among the pods a drain of %s would evict is %d (%s), pod %s",
			node, int64(types.FactNum(fs, "drain.grace.max")), graceSaid(int64(types.FactNum(fs, "drain.grace.max"))), slowest)}
	if n := int(types.FactNum(fs, "drain.pods.behind.service")); n > 0 {
		lines = append(lines, fmt.Sprintf("%d of the %s behind a Service on it %s no preStop hook: between the stop signal "+
			"and their endpoint's removal they can still be sent new connections",
			int(types.FactNum(fs, "drain.prestop.missing")), nWord(n, "pod", "pods"), map[bool]string{true: "has", false: "have"}[int(types.FactNum(fs, "drain.prestop.missing")) == 1]))
	}
	lines = append(lines, "the grace period is the most the kubelet waits; a pod may exit at once. The provider's drain "+
		"timeout (a managed node group's, an upgrade's surge) is not read here")
	return lines
}

// graceSaid is a grace period in the unit a reader thinks in.
func graceSaid(s int64) string {
	switch {
	case s >= 3600 && s%3600 == 0:
		return nWord(int(s/3600), "hour", "hours")
	case s >= 60 && s%60 == 0:
		return nWord(int(s/60), "minute", "minutes")
	}
	return nWord(int(s), "second", "seconds")
}
