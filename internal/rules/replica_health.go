package rules

import (
	"fmt"
	"math"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// replica_health.go — WHAT THE CONTROLLER COUNTED, AGAINST WHAT THE OPERATOR ASKED FOR.
//
// Two rows from Sweep 0, both marked OBSERVABLE-ELSEWHERE=yes: every monitoring stack plots
// `kube_deployment_status_replicas_available` and `kube_pod_container_status_restarts_total`. Under Q1 that
// makes them SHIP-DEMOTE-SAY-SO, never suppress — the decisive argument being that suppressing would make
// the document depend on the reader's TOOLING rather than on the cluster's state, so two identical clusters
// produce two different documents. The demotion is a placement question and its mechanism does not exist
// yet; nothing here changes what a finding SAYS.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DISCIPLINE, AND IT IS SWEEP 3'S
//
//	AN INTEGER STATUS FIELD'S ZERO IS AMBIGUOUS IN A WAY A POINTER'S IS NOT. `readyReplicas == 0` means
//	either "no replica is ready" or "the controller has not written this yet", and those are opposite
//	conclusions. Every claim below is paired with `observedGeneration` — the controller's own statement
//	that it has seen the spec in front of it — or it is not made.
//
//	A RESTART COUNT IS A TOTAL SINCE THE CONTAINER WAS CREATED, NOT A RATE. Forty restarts on a pod
//	created a year ago and forty on one created this morning are different facts, and the snapshot can
//	tell them apart only because it holds the pod's creation time. The finding states both numbers and
//	computes nothing from them.
//
//	NO DOLLARS.

// ── Rule: fewer ready replicas than the spec asks for ────────────────────────────────────────────

// ReplicasBelowDesired reports workloads whose controller reports fewer ready replicas than desired.
type ReplicasBelowDesired struct{}

func (ReplicasBelowDesired) ID() string      { return "k8s.reliability.replicas-below-desired" }
func (ReplicasBelowDesired) Version() string { return "1.0.0" }

func (ReplicasBelowDesired) RequiredKinds() []string { return withWorkloads() }

func (r ReplicasBelowDesired) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding

	add := func(kind, ns, name string, desired, ready int32, observed, generation int64, extra string) {
		if !opts.IncludeSystem && isSystemNamespace(ns) {
			return
		}
		// DELIBERATELY SCALED TO ZERO IS NOT A SHORTFALL. Every parked workload in the cluster would
		// otherwise be reported, which is the same false positive condition-unchanged had to exclude.
		if desired <= 0 || ready >= desired {
			return
		}
		// THE CONTROLLER MUST HAVE WRITTEN STATUS AT ALL, AND MUST HAVE SEEN THIS SPEC.
		//
		// The first version tested only `generation != 0 && observed != generation`, which let the
		// zero-versus-zero case straight through — and that case is precisely the one Sweep 3 warned
		// about: an object whose controller has written NO status reads as "0 ready of N", which is
		// indistinguishable from an outage and is in fact an unwritten field. It fired on TWELVE
		// workloads in the shipped fixture, every one of them healthy.
		//
		// A controller that has written status sets observedGeneration to at least 1. Zero means it has
		// not, so the counts beside it are UNKNOWN rather than zero — B-125's lesson, in the one place
		// where the unknown and the alarming value are the same number.
		if observed == 0 {
			return
		}
		if generation != 0 && observed != generation {
			return
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), kind, ns, name),
			IDBasis:     &types.ResourceRef{Kind: kind, Namespace: ns, Name: name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s %s/%s has %d of %s ready", kind, ns, name, ready, nWord(int(desired), "replica", "replicas")),
			Description: fmt.Sprintf("The controller for %s %s/%s reports %d ready of the %d its spec asks "+
				"for, and it has observed the current spec (observedGeneration matches metadata.generation). "+
				"WHY the remaining %d are not ready is not in this reading — the pods themselves carry that, "+
				"and k8s.reliability.pod-not-ready reports what the kubelet says about them.",
				kind, ns, name, ready, desired, desired-ready),
			WhyItMatters: "A workload running below its declared replica count has less headroom than its " +
				"manifest promises, and the manifest is what everyone reads. It is also the state a " +
				"half-finished rollout leaves behind once nobody is watching the terminal it started in.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("%s %s/%s: spec asks for %d, status reports %d ready%s",
					kind, ns, name, desired, ready, extra),
				fmt.Sprintf("status.observedGeneration = %d and metadata.generation = %d, so the controller "+
					"has seen this spec and the counts above are its verdict on it", observed, generation),
				"a monitoring stack plots this continuously; it is here because a cluster without one is " +
					"the common case, and because the reading should not depend on the reader's tooling",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: kind, Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}

	if observed(inv, "deployments") {
		for i := range inv.Deployments {
			d := &inv.Deployments[i]
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			add("Deployment", d.Namespace, d.Name, desired, d.Status.ReadyReplicas,
				d.Status.ObservedGeneration, d.Generation,
				fmt.Sprintf(", %d available, %d unavailable", d.Status.AvailableReplicas, d.Status.UnavailableReplicas))
		}
	}
	if observed(inv, "statefulsets") {
		for i := range inv.StatefulSets {
			s := &inv.StatefulSets[i]
			desired := int32(1)
			if s.Spec.Replicas != nil {
				desired = *s.Spec.Replicas
			}
			add("StatefulSet", s.Namespace, s.Name, desired, s.Status.ReadyReplicas,
				s.Status.ObservedGeneration, s.Generation,
				fmt.Sprintf(", %d available", s.Status.AvailableReplicas))
		}
	}
	if observed(inv, "daemonsets") {
		for i := range inv.DaemonSets {
			d := &inv.DaemonSets[i]
			// A DAEMONSET'S DESIRED COUNT IS THE CONTROLLER'S OWN, not the operator's: it is however many
			// nodes the selector matched. Comparing against a spec replica count would be comparing
			// against a field DaemonSets do not have.
			add("DaemonSet", d.Namespace, d.Name, d.Status.DesiredNumberScheduled, d.Status.NumberReady,
				d.Status.ObservedGeneration, d.Generation,
				fmt.Sprintf(", %d available, %d unavailable", d.Status.NumberAvailable, d.Status.NumberUnavailable))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: containers that have restarted many times ──────────────────────────────────────────────

// restartFloor is the count past which a restart total is reported.
//
// TWENTY, AND THE NUMBER IS BOUNDED BY WHAT THE FIELD MEANS. restartCount is a TOTAL since the container
// was created, with no rate — so a low threshold reports every long-lived pod that has ever been restarted
// by a node drain, an eviction or an OOM months ago. Twenty is past every ordinary accumulation and is
// where a crash loop separates from a history.
const restartFloor = 20

// ContainerRestartTotal reports containers whose restart total is high, with the age it accumulated over.
type ContainerRestartTotal struct{}

func (ContainerRestartTotal) ID() string      { return "k8s.reliability.container-restart-total" }
func (ContainerRestartTotal) Version() string { return "1.0.0" }

func (ContainerRestartTotal) RequiredKinds() []string { return withWorkloads("pods") }

func (r ContainerRestartTotal) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") {
		return nil
	}
	reading := readingTime(inv)

	type group struct {
		label, ns string
		lines     []string
		pods      []string
		worst     int32
	}
	groups := map[string]*group{}
	var order []string

	owners := newOwnerIndex(inv) // one lookup per pod, not a walk of every Deployment per pod
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.RestartCount < restartFloor {
				continue
			}
			key, label := podGroup(owners, inv, p)
			g := groups[key]
			if g == nil {
				g = &group{label: label, ns: p.Namespace}
				groups[key] = g
				order = append(order, key)
			}
			age := "unknown age"
			if !p.CreationTimestamp.IsZero() {
				days := int(math.Round(reading.Sub(p.CreationTimestamp.Time).Hours() / 24))
				age = nWord(days, "day", "days") + " since the pod was created"
			}
			g.lines = append(g.lines, fmt.Sprintf("pod %s/%s container %q: restartCount = %d, %s",
				p.Namespace, p.Name, cs.Name, cs.RestartCount, age))
			if !contains(g.pods, p.Name) {
				g.pods = append(g.pods, p.Name)
			}
			if cs.RestartCount > g.worst {
				g.worst = cs.RestartCount
			}
		}
	}

	sort.Strings(order)
	var out []types.Finding
	for _, key := range order {
		g := groups[key]
		sort.Strings(g.lines)
		sort.Strings(g.pods)
		refs := make([]types.ResourceRef, 0, len(g.pods))
		for _, n := range g.pods {
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: n})
		}
		evidence := append([]string{snapshotNote(inv)}, g.lines...)
		evidence = append(evidence,
			"restartCount is a TOTAL since the container was created and carries no rate, so the pod's age "+
				"is stated beside it — forty restarts over a year and forty over a morning are different "+
				"facts and this reading cannot compute the difference for you",
			"a monitoring stack plots the rate continuously; this is the total, which is what a snapshot has")
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Pod", g.ns, g.label),
			IDBasis:     &types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: g.label},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s has a container restarted %d times", g.label, g.worst),
			Description: fmt.Sprintf("%s of %s report a container restart total of %d or more, the "+
				"highest being %d. The count is cumulative since the container was created; the age of "+
				"each pod is in the evidence so the total can be read against it.", nWord(len(g.pods), "pod", "pods"), g.label, restartFloor, g.worst),
			WhyItMatters: "A container that keeps being restarted is being kept alive by the kubelet " +
				"rather than by working, and each restart drops whatever was in memory. The workload " +
				"reports itself as running throughout.",
			Evidence:          evidence,
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
