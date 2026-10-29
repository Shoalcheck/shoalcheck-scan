package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// pod_unready.go — WHAT THE KUBELET IS SAYING RIGHT NOW, WHICH IS THE HALF THE SEVEN-DAY THRESHOLD REFUSES.
//
// Phase 1, classified through the overlap census as **kind 3** — a different claim about the same subject —
// so it is a new rule AND the shipped rule it sits beside carries a cross-reference. The founder's rule
// (spec §2) is explicit that a kind-3 row must not let a reader read two cards as two problems, and
// NodeDrainBudget/PDBBlocksDrains is the precedent: they cite each other and only one carries remediation.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS IS NOT condition-unchanged, AND WHY THAT RULE IS NOT THIS
//
//	condition-unchanged reports a condition that has held the same non-healthy reading for SEVEN DAYS. Its
//	whole argument is that everything ordinary resolves inside a day, so a week means the cluster stopped
//	resolving it on its own. That argument is sound and it has a consequence: a pod that entered
//	CrashLoopBackOff an hour ago is DELIBERATELY EXCLUDED — and it is the more urgent of the two.
//
//	So the axis is TIME, not subject. One rule reports "this has been true long enough that nobody is
//	coming"; this one reports "the kubelet is saying something right now, and here is the word it used".
//	Neither is a threshold on the other.
//
//	THE OVERLAP IS REAL AND IT IS BOUNDED. A pod unready for eight days is reported by both. Measured on
//	the reference cluster: 0 containers Waiting and 1 pod not-Ready — and that one has been so since the
//	7th of August, so it is exactly the overlapping case. One instance. Both cards cross-reference the
//	other rule by ID so the reader sees one problem described twice rather than two problems.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS DOES NOT SAY
//
//	NOT WHY. The kubelet's reason is quoted, never interpreted: `ImagePullBackOff` is a fact about what
//	the kubelet reports, and whether the registry is down, the tag is wrong or the pull secret expired is
//	not in this snapshot.
//
//	NOT HOW LONG. That is the other rule's claim, and making it here would be inventing a duration from a
//	state. The reading time is stated; nothing else about time is.
//
//	NOT ABOUT COMPLETED WORK. A pod in Succeeded or Failed is not unready, it is finished, and every
//	CronJob leaves them behind.

// unreadyStableFor is how long a pod must have EXISTED before its unreadiness is reported.
//
// A pod thirty seconds old is starting, not failing, and every rollout creates them in batches. Two minutes
// is past image pull and past almost every readiness-probe initial delay, and it is far below the seven days
// at which condition-unchanged takes over — the two rules meet with a gap, not an edge.
const unreadyStableFor = 2 * 60 // seconds

// PodNotReady reports running pods whose kubelet says they are not ready, with the reason it published.
type PodNotReady struct{}

func (PodNotReady) ID() string      { return "k8s.reliability.pod-not-ready" }
func (PodNotReady) Version() string { return "1.0.0" }

// RequiredKinds — `pods` carries the whole claim. The workload kinds are load-bearing for GROUPING only,
// exactly as in image-digest-drift: without them a pod's ReplicaSet cannot be resolved to its Deployment
// and the finding is named after a hash-suffixed ReplicaSet. The claim survives; the label degrades.
func (PodNotReady) RequiredKinds() []string { return withWorkloads("pods") }

func (r PodNotReady) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") {
		return nil
	}
	reading := readingTime(inv)

	type group struct {
		label, ns string
		pods      []string
		reasons   map[string]int
		messages  []string
	}
	groups := map[string]*group{}
	var order []string

	owners := newOwnerIndex(inv) // one lookup per pod, not a walk of every Deployment per pod
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		// A FINISHED POD IS NOT AN UNREADY ONE. Every CronJob leaves them behind, and reporting them
		// would put a card on every cluster that has ever run a scheduled job.
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if p.DeletionTimestamp != nil {
			continue // being deleted: an operation, not a state
		}
		// A POD THAT HAS JUST BEEN CREATED IS STARTING. Without this every rollout reports its own
		// in-flight pods, which is B-131's defect — describing a cluster rather than reporting a problem.
		if p.CreationTimestamp.IsZero() ||
			reading.Sub(p.CreationTimestamp.Time).Seconds() < unreadyStableFor {
			continue
		}
		ready, known := podReadyCondition(p)
		if !known || ready {
			// An ABSENT Ready condition is unknown, not false — §2's discipline, and the kubelet writes
			// one within moments of admission, so its absence means this reading arrived first.
			continue
		}

		key, label := podGroup(owners, inv, p)
		g := groups[key]
		if g == nil {
			g = &group{label: label, ns: p.Namespace, reasons: map[string]int{}}
			groups[key] = g
			order = append(order, key)
		}
		g.pods = append(g.pods, p.Name)
		for _, cs := range p.Status.ContainerStatuses {
			if w := cs.State.Waiting; w != nil && w.Reason != "" {
				g.reasons[w.Reason]++
				if m := strings.TrimSpace(w.Message); m != "" && len(g.messages) < 3 {
					g.messages = append(g.messages, fmt.Sprintf("%s: %s", cs.Name, truncateMessage(m)))
				}
			}
			if t := cs.State.Terminated; t != nil && t.Reason != "" {
				g.reasons[t.Reason]++
			}
		}
	}

	sort.Strings(order)
	var out []types.Finding
	for _, key := range order {
		g := groups[key]
		sort.Strings(g.pods)

		reasons := make([]string, 0, len(g.reasons))
		for k := range g.reasons {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		reasonText := "no reason published by the kubelet"
		if len(reasons) > 0 {
			parts := make([]string, 0, len(reasons))
			for _, k := range reasons {
				parts = append(parts, fmt.Sprintf("%s (%s)", k, nWord(g.reasons[k], "container", "containers")))
			}
			reasonText = strings.Join(parts, ", ")
		}

		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s of %s report Ready=False: %s", nWord(len(g.pods), "pod", "pods"), g.label, strings.Join(g.pods, ", ")),
			fmt.Sprintf("kubelet container state reasons: %s", reasonText),
		}
		evidence = append(evidence, g.messages...)
		evidence = append(evidence,
			"the reason is the kubelet's own word for what it is doing, quoted rather than interpreted: "+
				"whether a registry is unreachable, a tag is wrong or a secret has expired is not in this reading",
			"HOW LONG this has been true is not claimed here — that is k8s.reliability.condition-unchanged, "+
				"which reports a condition that has held for seven days. A pod appearing in both is one "+
				"problem described twice, not two problems.")

		refs := make([]types.ResourceRef, 0, len(g.pods))
		for _, name := range g.pods {
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: name})
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Pod", g.ns, g.label),
			IDBasis:     &types.ResourceRef{Kind: "Pod", Namespace: g.ns, Name: g.label},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s of %s %s not ready", nWord(len(g.pods), "pod", "pods"), g.label,
				pick(len(g.pods), "is", "are")),
			Description: fmt.Sprintf("%s of %s report a Ready condition of False in this reading, "+
				"taken at %s. The kubelet published: %s. This is what it is saying now — how long it has "+
				"been saying it is a separate question and a separate finding.", nWord(len(g.pods), "pod", "pods"), g.label, stamp(reading), reasonText),
			WhyItMatters: "A pod that is not ready receives no traffic through any Service that selects " +
				"it, and its workload is running below the replica count its manifest declares. Both are " +
				"invisible in the manifest, which reads exactly as it did when everything was working.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			// The READING is exact. What is uncertain is whether it is momentary: a pod can become ready
			// a second after the snapshot, and the two-minute floor narrows that without removing it.
			Confidence: 0.8,
			Provenance: provenance(),
		})
	}
	return out
}

// podReadyCondition returns whether the pod's Ready condition is True, and whether it was found at all.
// The second return value is what separates "the kubelet says not ready" from "no kubelet has said
// anything yet", which are opposite states and must never be conflated — B-125's lesson, one layer down.
func podReadyCondition(p *corev1.Pod) (ready, known bool) {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue, true
		}
	}
	return false, false
}
