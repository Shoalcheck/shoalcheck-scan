package rules

import (
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ContainerOOMKilled reports containers whose last life ended in an OOM kill (ENG-30): the kernel killed them at
// their memory limit, or the node ran out. It is in every pod's status — lastState.terminated with reason OOMKilled —
// and nothing read it. A restart total says a container keeps dying; this says how, when, and at which limit.
//
// What it does not establish: that the next life will end the same way, how often it happens (the status keeps the
// LAST termination only), or whether the node or the limit did the killing — a pod OOM-killed for node pressure
// carries the same reason.
type ContainerOOMKilled struct{}

func (ContainerOOMKilled) ID() string      { return "k8s.reliability.container-oom-killed" }
func (ContainerOOMKilled) Version() string { return "1.0.0" }

// RequiredKinds — the pods carry the termination; their owners name the group.
func (ContainerOOMKilled) RequiredKinds() []string { return withWorkloads("pods") }

// oomKill is one container's last OOM kill.
type oomKill struct {
	pod, container string
	at             time.Time
	restarts       int32
	limit          int64 // bytes; 0 when the container has no memory limit
}

// lastOOM is the container's last termination when it was an OOM kill: the previous life (lastState) or, for a
// container not yet restarted, the current one.
func lastOOM(cs corev1.ContainerStatus) (*corev1.ContainerStateTerminated, bool) {
	if t := cs.LastTerminationState.Terminated; t != nil && t.Reason == "OOMKilled" {
		return t, true
	}
	if t := cs.State.Terminated; t != nil && t.Reason == "OOMKilled" {
		return t, true
	}
	return nil, false
}

func (r ContainerOOMKilled) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") {
		return nil
	}
	type group struct {
		label, ns string
		kills     []oomKill
	}
	groups := map[string]*group{}
	owners := derived(inv, opts).ownerIndex()
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		limits := map[string]int64{}
		for _, c := range p.Spec.Containers {
			if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				limits[c.Name] = q.Value()
			}
		}
		for _, cs := range p.Status.ContainerStatuses {
			t, ok := lastOOM(cs)
			if !ok {
				continue
			}
			key, label := podGroup(owners, inv, p)
			g := groups[key]
			if g == nil {
				g = &group{label: label, ns: p.Namespace}
				groups[key] = g
			}
			g.kills = append(g.kills, oomKill{pod: p.Name, container: cs.Name, at: t.FinishedAt.Time,
				restarts: cs.RestartCount, limit: limits[cs.Name]})
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []types.Finding
	for _, k := range keys {
		g := groups[k]
		sort.Slice(g.kills, func(i, j int) bool {
			if g.kills[i].pod != g.kills[j].pod {
				return g.kills[i].pod < g.kills[j].pod
			}
			return g.kills[i].container < g.kills[j].container
		})
		var facts []types.Fact
		ev := []string{snapshotNote(inv)}
		refs := []types.ResourceRef{}
		seen := map[string]bool{}
		latest := time.Time{}
		for _, kl := range g.kills {
			subj := &types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: kl.pod}
			kf := []types.Fact{
				withSubject(types.NewFact("oom.limit.memory", kl.limit), subj),
				withSubject(types.NewFact("oom.restarts", kl.restarts), subj),
			}
			if !kl.at.IsZero() {
				kf = append(kf, withSubject(types.NewFact("oom.finished", kl.at.UTC().Format(time.RFC3339)), subj))
				if kl.at.After(latest) {
					latest = kl.at
				}
			}
			facts = append(facts, kf...)
			ev = append(ev, oomLine(g.ns, kl.pod, kl.container, kf))
			if !seen[kl.pod] {
				seen[kl.pod] = true
				refs = append(refs, *subj)
			}
		}
		facts = append(facts, types.NewFact("oom.containers", len(g.kills)))
		ev = append(ev,
			"the status keeps the LAST termination only: how many earlier lives ended the same way is not in it, and "+
				"a monitoring stack's kube_pod_container_status_last_terminated_reason is the series that counts them",
			"OOMKilled is the kernel's word whether the container hit its own limit or the node ran out of memory; "+
				"the limit is stated beside each kill so the two can be told apart against the node's pressure")
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Pod", g.ns, g.label),
			IDBasis:     &types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: g.label},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s: a container's last life ended in an OOM kill", g.label),
			Description: fmt.Sprintf("%s of %s ended its last life OOMKilled — the kernel killed it for memory. "+
				"The limit, the time and the restart total of each are in the evidence.", nWord(len(g.kills), "container", "containers"), g.label),
			WhyItMatters: "An OOM kill drops whatever the process held in memory, mid-request. A container killed at " +
				"its limit will be killed there again unless its working set or its limit changes.",
			Evidence:          ev,
			Facts:             facts,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

// oomLine is one kill's sentence, rendered from its facts (M-172).
func oomLine(ns, pod, container string, fs []types.Fact) string {
	limit := "no memory limit"
	if l := int64(types.FactNum(fs, "oom.limit.memory")); l > 0 {
		limit = "memory limit " + humanMi(l)
	}
	at := "at a time the status does not record"
	if s := types.FactStr(fs, "oom.finished"); s != "" {
		at = "at " + s
	}
	return fmt.Sprintf("pod %s/%s container %q: last terminated OOMKilled %s, %s, restartCount = %d",
		ns, pod, container, at, limit, int(types.FactNum(fs, "oom.restarts")))
}

// withSubject sets a fact's subject.
func withSubject(f types.Fact, s *types.ResourceRef) types.Fact {
	f.Subject = s
	return f
}

// oomKilledContainers is, per pod name, the containers whose last life ended OOMKilled — what rightsizing reads to
// never lower the memory of a container the kernel has already killed for it.
func oomKilledContainers(pods []corev1.Pod) map[string]time.Time {
	out := map[string]time.Time{}
	for i := range pods {
		for _, cs := range pods[i].Status.ContainerStatuses {
			if t, ok := lastOOM(cs); ok {
				if t.FinishedAt.Time.After(out[cs.Name]) || out[cs.Name].IsZero() {
					out[cs.Name] = t.FinishedAt.Time
				}
			}
		}
	}
	return out
}
