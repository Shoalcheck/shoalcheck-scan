package rules

// rollout_preflight.go — CHANGE PREFLIGHT: what a rolling update of this workload will run into.
//
// Four mechanical statements, each arithmetic over fields read directly off the workload object.
// The question is the one an operator has before they type `kubectl apply`: if I change this
// template, what does the controller actually do — and what does my own configuration say about it?
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// A PODDISRUPTIONBUDGET DOES NOT GATE A ROLLING UPDATE. THIS IS THE LOAD-BEARING FACT.
//
// PDBs are enforced by the Eviction API — the /eviction subresource. A rolling update does not use
// it: the Deployment controller scales the old ReplicaSet down and the ReplicaSet controller DELETEs
// pods, and a direct DELETE never consults the budget. node_drain.go:48 already draws exactly this
// line for the drain case ("budgets are bypassed entirely, as they are by `kubectl delete pod`"),
// and a rolling update is in the `kubectl delete pod` class, not the drain class.
//
// Proven rather than argued, on the kind testbed: one 1-replica Deployment under one PDB whose
// status published disruptionsAllowed=0. An eviction of that pod returned 429 TooManyRequests. A
// rollout of the same Deployment, same PDB, same budget, replaced the pod and completed. Two paths,
// one budget, opposite outcomes.
//
// So this file makes NO claim that a budget stops a rollout, and the words "blocked", "blocks" and
// "will block" are in rolloutBannedPhrases. Three of the four rules must not reference a PDB at all,
// which rollout_preflight_test.go enforces separately from the phrase list. The fourth names one on
// purpose, and what it reports is a contradiction between two things the OPERATOR declared — never a
// prediction that either mechanism will act.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
//	No durations. Nothing here reads image pull time, probe timing, or controller throughput, so
//	there is no floor and no ceiling on how long anything takes.
//
//	No user impact, and not the word "service" in an outcome sense. The Recreate statement is the
//	closest this file comes to impact and it stops at the replica count: whether zero running
//	replicas matters is a question about consumers we cannot see.
//
//	No "the rollout will fail". Each finding enumerates one mechanical thing, with its evidence.
//
//	NO SCHEDULING VERDICT. The surge rule compares the pod template's REQUESTS against node
//	ALLOCATABLE, never against observed usage — requests-versus-usage reasoning is wrong in both
//	directions and this project already carries a founder-caught false positive of that exact shape,
//	where $1,121 of apparent "headroom" was really an OOM. And even the requests reading is a
//	CAPACITY statement, not a scheduling one: taints, affinity, topology spread and the scheduler's
//	own decisions are unread, so per-node fragmentation can block a surge that fits in aggregate and
//	can equally permit one this arithmetic calls tight. That caveat rides in the same sentence as the
//	number, every time.
//
//	NO ROUND ARITHMETIC FOR STATEFULSETS, in either direction. A StatefulSet's
//	spec.updateStrategy.rollingUpdate.maxUnavailable sits behind the MaxUnavailableStatefulSet
//	feature gate, and feature gates are not readable from a read-only client on EKS/AKS/GKE. So we
//	could read the number and not know whether the cluster honours it. "One pod at a time" is also
//	false on a cluster that does honour it — merely pessimistically false, and this project's rule is
//	that wrong arithmetic stays wrong. The two StatefulSet findings here (OnDelete, and a left-behind
//	partition) are both gate-independent, which is what makes the question moot rather than merely
//	deferred.
//
//	No dollars. There is no traffic, revenue or SLA data in the snapshot.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// OVERLAP WITH k8s.workload.risky-rollout-strategy, DECLARED RATHER THAN HIDDEN
//
// RiskyRolloutStrategy (rollout_strategy.go) already fires on a Deployment with strategy Recreate,
// and its wording carries impact language this file refuses. Both findings will appear for the same
// Deployment. That is deliberate for now: silently suppressing either would change an existing
// claim, which needs founder sign-off, and the two say different things — the older rule offers a
// remediation, this one states the mechanism. It is flagged for the report restructure to resolve.

import (
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────
// shared strategy arithmetic
// ─────────────────────────────────────────────────────────────────────────────────────────────

func deployReplicas(d *appsv1.Deployment) int32 {
	if d.Spec.Replicas != nil {
		return *d.Spec.Replicas
	}
	return 1
}

func stsReplicas(s *appsv1.StatefulSet) int32 {
	if s.Spec.Replicas != nil {
		return *s.Spec.Replicas
	}
	return 1
}

// isRollingUpdate reports whether a Deployment rolls. An empty strategy type is RollingUpdate: the
// API server defaults it, so reading "" as "not rolling" would invent a Recreate that is not there.
func isRollingUpdate(d *appsv1.Deployment) bool {
	return d.Spec.Strategy.Type == "" || d.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType
}

// resolvedFenceposts returns maxUnavailable and maxSurge as absolute pod counts, using Kubernetes'
// own rounding: maxUnavailable rounds DOWN and maxSurge rounds UP, and both default to 25%. The
// asymmetry is not ours — it is what the Deployment controller does, and mirroring it is the whole
// point. `ok` is false for a value the API would not accept, in which case no claim is made.
func resolvedFenceposts(d *appsv1.Deployment, replicas int32) (maxUnavailable, maxSurge int, spec string, ok bool) {
	quarter := intstr.FromString("25%")
	mu, ms := &quarter, &quarter
	if ru := d.Spec.Strategy.RollingUpdate; ru != nil {
		if ru.MaxUnavailable != nil {
			mu = ru.MaxUnavailable
		}
		if ru.MaxSurge != nil {
			ms = ru.MaxSurge
		}
	}
	var err error
	maxUnavailable, err = intstr.GetScaledValueFromIntOrPercent(normalizeIntOrString(mu), int(replicas), false)
	if err != nil {
		return 0, 0, "", false
	}
	maxSurge, err = intstr.GetScaledValueFromIntOrPercent(normalizeIntOrString(ms), int(replicas), true)
	if err != nil {
		return 0, 0, "", false
	}
	// The API rejects maxUnavailable=0 together with maxSurge=0, so the shape cannot exist on a live
	// cluster. If a hand-built object presents it anyway, say nothing rather than reason about a
	// configuration the API server would not have accepted.
	if maxUnavailable == 0 && maxSurge == 0 {
		return 0, 0, "", false
	}
	return maxUnavailable, maxSurge, fmt.Sprintf("maxUnavailable=%s, maxSurge=%s", mu.String(), ms.String()), true
}

// normalizeIntOrString turns a bare-integer STRING ("3", no percent sign) into an Int form. The
// scaler rejects it otherwise, and it means the same thing as the int field — the same normalization
// rollout_strategy.go performs for the same reason.
func normalizeIntOrString(v *intstr.IntOrString) *intstr.IntOrString {
	if v.Type != intstr.String || strings.HasSuffix(v.StrVal, "%") {
		return v
	}
	var n int32
	if _, err := fmt.Sscanf(v.StrVal, "%d", &n); err != nil {
		return v
	}
	out := intstr.FromInt32(n)
	return &out
}

func sortedDeployments(inv *collect.Inventory) []int {
	idx := make([]int, 0, len(inv.Deployments))
	for i := range inv.Deployments {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.Deployments[idx[a]], &inv.Deployments[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})
	return idx
}

func sortedStatefulSets(inv *collect.Inventory) []int {
	idx := make([]int, 0, len(inv.StatefulSets))
	for i := range inv.StatefulSets {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.StatefulSets[idx[a]], &inv.StatefulSets[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})
	return idx
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 1 — an update that does not roll on its own
// ─────────────────────────────────────────────────────────────────────────────────────────────

// RolloutDoesNotSelfRoll reports a StatefulSet whose updateStrategy is OnDelete: the controller
// replaces a pod only after someone deletes it, so changing the template rolls nothing at all.
//
// IT COVERED DEPLOYMENT `Recreate` TOO, AND NO LONGER DOES — two reasons, and both are why this
// rule was renamed rather than merely trimmed.
//
// The first is a duplicate. `k8s.workload.risky-rollout-strategy` has fired on Deployment
// `Recreate` since f37abf2, and the Epic 2 spec listed `Recreate` as something to build without
// checking what already shipped. Two findings on one object double-count one configuration, and
// `verdict.Select` collapses per RuleID so it cannot dedupe them. That rule keeps `Recreate`: it
// carries the remediation and the ReadWriteOnce caveat this one never had.
//
// The second is the name. The old ID said `rollout-passes-through-zero` and the OnDelete branch
// does NOT pass through zero — the replica count is untouched, nothing rolls at all. An ID is the
// identity a history diff matches on; one that is false for half the findings it produces is a
// defect waiting for the first comparison. Renamed before it ever entered one.
type RolloutDoesNotSelfRoll struct{}

func (RolloutDoesNotSelfRoll) ID() string      { return "k8s.reliability.rollout-does-not-self-roll" }
func (RolloutDoesNotSelfRoll) Version() string { return "1.0.0" }

// RequiredKinds — the strategy field IS the claim, and it lives on the StatefulSet. `deployments`
// went with the Recreate branch: a kind this rule no longer reads must not be declared, or a
// comparison would report the rule as unevaluated on a run that evaluated it fully.
// `pods` is omitted because the claim is about what the controller will do to the template, not
// about which pods are bound now. `poddisruptionbudgets` is NOT declared because it is NOT read:
// see the file header.
// See deps.go for what belongs in this list.
func (RolloutDoesNotSelfRoll) RequiredKinds() []string {
	return sortedKinds([]string{"statefulsets"})
}

func (r RolloutDoesNotSelfRoll) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding

	for _, i := range sortedStatefulSets(inv) {
		s := &inv.StatefulSets[i]
		if !opts.IncludeSystem && isSystemNamespace(s.Namespace) {
			continue
		}
		if s.Spec.UpdateStrategy.Type != appsv1.OnDeleteStatefulSetStrategyType {
			continue
		}
		replicas := stsReplicas(s)
		evidence := []string{
			fmt.Sprintf("StatefulSet %s/%s: spec.updateStrategy.type=OnDelete over spec.replicas=%d — the "+
				"controller creates a replacement pod only after an existing one is deleted by hand",
				s.Namespace, s.Name, replicas),
		}
		if s.Status.CurrentRevision != "" && s.Status.UpdateRevision != "" {
			if s.Status.CurrentRevision != s.Status.UpdateRevision {
				evidence = append(evidence, fmt.Sprintf(
					"status.currentRevision=%s differs from status.updateRevision=%s, and status.updatedReplicas=%d "+
						"of %d — so a template change is already pending on this workload",
					s.Status.CurrentRevision, s.Status.UpdateRevision, s.Status.UpdatedReplicas, replicas))
			} else {
				evidence = append(evidence, fmt.Sprintf(
					"status.currentRevision equals status.updateRevision (%s), so no template change is pending "+
						"at the moment of this reading", s.Status.CurrentRevision))
			}
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "StatefulSet", s.Namespace, s.Name),
			IDBasis:     &types.ResourceRef{Kind: "StatefulSet", Namespace: s.Namespace, Name: s.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Template changes to %s/%s do not roll on their own", s.Namespace, s.Name),
			Description: fmt.Sprintf(
				"StatefulSet %s/%s declares spec.updateStrategy.type=OnDelete. Changing the pod template does "+
					"not replace any pod: the controller waits for each pod to be deleted by hand, and until "+
					"someone does, the workload keeps running the previous revision. The replica count does not "+
					"reach zero — nothing happens at all, which is the opposite reading and a different claim.",
				s.Namespace, s.Name),
			WhyItMatters: "OnDelete is a setting people choose once for a delicate migration and then forget; " +
				"afterwards every apply reports success while the running pods keep the old revision.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "StatefulSet", Namespace: s.Namespace, Name: s.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.6,
			Provenance:        provenance(),
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 2 — a surge with nowhere to put it
// ─────────────────────────────────────────────────────────────────────────────────────────────

// RolloutNeedsSurgeCapacity states a CAPACITY fact and refuses a scheduling one. With
// maxUnavailable resolving to 0 a rolling update must create a replacement before it removes any
// pod, so progress needs room for maxSurge additional pods. The comparison is the pod template's
// REQUESTS against node ALLOCATABLE minus the requests already bound — never against observed usage.
type RolloutNeedsSurgeCapacity struct{}

func (RolloutNeedsSurgeCapacity) ID() string      { return "k8s.reliability.rollout-needs-surge-capacity" }
func (RolloutNeedsSurgeCapacity) Version() string { return "1.0.0" }

// RequiredKinds — deployments for the strategy and the template's requests; nodes for allocatable;
// and PODS, because the headroom side is allocatable minus the requests already BOUND. The design
// spec omitted pods on the reasoning that the surge arithmetic reads the template — true of the
// numerator and false of the denominator. Without the pod list the bound side reads as ~0, abundant
// headroom is fabricated out of a collection gap, and the finding silently disappears between two
// audits, which is precisely what this declaration exists to prevent. `poddisruptionbudgets` is not
// declared because it is not read.
// See deps.go for what belongs in this list.
func (RolloutNeedsSurgeCapacity) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "nodes", "pods"})
}

// fragmentationCaveat rides in the same evidence line as every capacity number this rule prints.
const fragmentationCaveat = "this is an AGGREGATE capacity reading and not a scheduling answer: per-node " +
	"fragmentation can leave no single node with room for a surge pod that fits cluster-wide, and taints, " +
	"affinity, topology spread and the scheduler's own decisions are not read here"

func (r RolloutNeedsSurgeCapacity) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD. The claim is insufficiency, which is an absence claim on both sides: without
	// nodes there is no allocatable figure, and without pods the bound-requests figure reads as zero
	// and manufactures headroom.
	if !observed(inv, "nodes") || !observed(inv, "pods") {
		return nil
	}
	cap := clusterRequestedHeadroom(inv)
	if cap.eligibleNodes == 0 {
		return nil
	}

	var out []types.Finding
	for _, i := range sortedDeployments(inv) {
		d := &inv.Deployments[i]
		if !opts.IncludeSystem && isSystemNamespace(d.Namespace) {
			continue
		}
		if !isRollingUpdate(d) {
			continue
		}
		replicas := deployReplicas(d)
		if replicas < 1 {
			continue
		}
		maxUnavailable, maxSurge, specText, ok := resolvedFenceposts(d, replicas)
		if !ok || maxUnavailable != 0 || maxSurge < 1 {
			continue
		}
		reqCPU, reqMem, declared := templateRequests(&d.Spec.Template.Spec)
		if !declared {
			// A template with no requests reserves nothing, so this arithmetic has no numbers to
			// bound the surge with. Saying "it fits" would be the requests-versus-usage error in its
			// most flattering direction, so the rule says nothing at all.
			continue
		}
		needCPU := scaleQuantity(reqCPU, int64(maxSurge))
		needMem := scaleQuantity(reqMem, int64(maxSurge))

		cpuShort := needCPU.Cmp(cap.freeCPU) > 0
		memShort := needMem.Cmp(cap.freeMem) > 0
		if !cpuShort && !memShort {
			continue
		}

		var which []string
		if cpuShort {
			which = append(which, "CPU")
		}
		if memShort {
			which = append(which, "memory")
		}

		evidence := []string{
			fmt.Sprintf("Deployment %s/%s: spec.strategy.rollingUpdate %s resolves to maxUnavailable=0 over "+
				"spec.replicas=%d, so a replacement pod must be created before any pod is removed, and "+
				"progress needs room for %s",
				d.Namespace, d.Name, specText, replicas, nWord(maxSurge, "additional pod", "additional pods")),
			fmt.Sprintf("%s request %s CPU and %s memory in total, from the pod template", nWord(maxSurge, "surge pod", "surge pods"), needCPU.String(), needMem.String()),
			fmt.Sprintf("cluster allocatable across %s is %s CPU and %s memory; "+
				"requests already bound to those nodes total %s CPU and %s memory, leaving %s CPU and %s "+
				"memory of requested headroom — not enough requested-%s headroom for the surge. %s", nWord(cap.eligibleNodes, "schedulable Ready node", "schedulable Ready nodes"), cap.allocCPU.String(), cap.allocMem.String(),
				cap.reqCPU.String(), cap.reqMem.String(), cap.freeCPU.String(), cap.freeMem.String(),
				strings.Join(which, "/"), fragmentationCaveat),
		}
		if cap.skippedNodes > 0 {
			evidence = append(evidence, fmt.Sprintf(
				"%s are excluded from both sides of this arithmetic: %s", nWord(cap.skippedNodes, "node", "nodes"), strings.Join(cap.skipNotes, "; ")))
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Deployment", d.Namespace, d.Name),
			IDBasis:     &types.ResourceRef{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("Surge capacity for %s/%s is short by requested %s",
				d.Namespace, d.Name, strings.Join(which, " and ")),
			Description: fmt.Sprintf(
				"Deployment %s/%s resolves to maxUnavailable=0, so the controller must add a pod before it "+
					"removes one, and it needs room for %d. Summing the pod template's requests against node "+
					"allocatable minus the requests already bound, the cluster does not hold that much "+
					"requested %s. This is a capacity comparison between two declared numbers — requests and "+
					"allocatable — and deliberately not a statement about where any pod would be placed.",
				d.Namespace, d.Name, maxSurge, strings.Join(which, " or ")),
			WhyItMatters: "maxUnavailable=0 is chosen to make updates safe, and it is the one setting that " +
				"needs spare room to make any progress at all — the arithmetic is invisible until an apply sits still.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name}},
			EstimatedEffort:   types.EffortMedium,
			// The two sums are exact; the aggregate-versus-per-node gap is exactly why this is not 1.0.
			Confidence: 0.6,
			Provenance: provenance(),
		})
	}
	return out
}

// requestedHeadroom is allocatable minus bound requests, over the nodes a new pod could land on.
type requestedHeadroom struct {
	eligibleNodes int
	skippedNodes  int
	skipNotes     []string
	allocCPU      resource.Quantity
	allocMem      resource.Quantity
	reqCPU        resource.Quantity
	reqMem        resource.Quantity
	freeCPU       resource.Quantity
	freeMem       resource.Quantity
}

// clusterRequestedHeadroom sums allocatable over nodes that are Ready and schedulable, and the
// requests of every pod bound to one of those nodes.
//
// Cordoned and NotReady nodes are excluded from BOTH sides. Counting their allocatable would offer
// capacity a new pod cannot use; counting their pods' requests without their allocatable would
// understate headroom. Excluding both keeps the subtraction over one consistent node set, and the
// count is disclosed in the finding.
//
// Unlike node_headroom.go's consolidation math, DaemonSet pods are INCLUDED here: they occupy
// allocatable that a surge pod would otherwise use. The two rules ask different questions of the
// same numbers, which is why neither reuses the other's sum.
func clusterRequestedHeadroom(inv *collect.Inventory) requestedHeadroom {
	h := requestedHeadroom{}
	eligible := map[string]bool{}
	notReady, cordoned := 0, 0
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		if n.Spec.Unschedulable {
			cordoned++
			h.skippedNodes++
			continue
		}
		if !nodeIsReady(n) {
			notReady++
			h.skippedNodes++
			continue
		}
		eligible[n.Name] = true
		h.eligibleNodes++
		h.allocCPU.Add(*n.Status.Allocatable.Cpu())
		h.allocMem.Add(*n.Status.Allocatable.Memory())
	}
	if cordoned > 0 {
		h.skipNotes = append(h.skipNotes, fmt.Sprintf("%d with spec.unschedulable=true", cordoned))
	}
	if notReady > 0 {
		h.skipNotes = append(h.skipNotes, fmt.Sprintf("%d whose Ready condition is not True", notReady))
	}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !eligible[p.Spec.NodeName] {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue // terminal pods hold no allocatable
		}
		cpu, mem, _ := templateRequests(&p.Spec)
		h.reqCPU.Add(cpu)
		h.reqMem.Add(mem)
	}
	h.freeCPU = h.allocCPU.DeepCopy()
	h.freeCPU.Sub(h.reqCPU)
	h.freeMem = h.allocMem.DeepCopy()
	h.freeMem.Sub(h.reqMem)
	return h
}

func nodeIsReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	// A node with no Ready condition has not reported; treat it as not eligible rather than assume.
	return false
}

// templateRequests sums a pod spec's declared requests, and reports whether ANY were declared.
//
// Regular containers plus restartable init containers (sidecars, restartPolicy=Always) are additive
// because they run for the pod's whole life. A plain init container's request is compared rather than
// added, because it runs before the regular containers and the scheduler reserves the larger of the
// two — this mirrors the API's own effective-request computation closely enough for a capacity
// reading, and the simplification is stated here rather than hidden.
//
// THIS DELIBERATELY DISAGREES WITH node_headroom.go's podRequests(), WHICH COUNTS ONLY REGULAR
// CONTAINERS. That function's comment says init requests "are not additive to the steady-state
// footprint", which was true before native sidecars (KEP-753) existed: an initContainer with
// restartPolicy=Always runs for the pod's whole life, so the scheduler reserves its request for the
// pod's whole life. On the kind testbed the gap is exactly ten Istio istio-proxy sidecars — 100m of
// 4230m — and it points the dangerous way there, because undercounting bound requests OVERSTATES how
// idle a node pool is, and that figure carries a dollar. Fixing it changes the value of an existing
// priced claim, so it is logged (bug-ledger B-102) and left for sign-off rather than changed here.
// The two must not be "harmonised" in the wrong direction.
func templateRequests(spec *corev1.PodSpec) (cpu, mem resource.Quantity, declared bool) {
	for i := range spec.Containers {
		req := spec.Containers[i].Resources.Requests
		if c, ok := req[corev1.ResourceCPU]; ok {
			cpu.Add(c)
			declared = true
		}
		if m, ok := req[corev1.ResourceMemory]; ok {
			mem.Add(m)
			declared = true
		}
	}
	var initCPU, initMem resource.Quantity
	for i := range spec.InitContainers {
		ic := &spec.InitContainers[i]
		req := ic.Resources.Requests
		sidecar := ic.RestartPolicy != nil && *ic.RestartPolicy == corev1.ContainerRestartPolicyAlways
		if c, ok := req[corev1.ResourceCPU]; ok {
			declared = true
			if sidecar {
				cpu.Add(c)
			} else if c.Cmp(initCPU) > 0 {
				initCPU = c
			}
		}
		if m, ok := req[corev1.ResourceMemory]; ok {
			declared = true
			if sidecar {
				mem.Add(m)
			} else if m.Cmp(initMem) > 0 {
				initMem = m
			}
		}
	}
	if initCPU.Cmp(cpu) > 0 {
		cpu = initCPU
	}
	if initMem.Cmp(mem) > 0 {
		mem = initMem
	}
	return cpu, mem, declared
}

// scaleQuantity multiplies a quantity by n without losing its unit, so evidence reads "4" rather
// than "4000m" where the input was whole cores.
func scaleQuantity(q resource.Quantity, n int64) resource.Quantity {
	out := resource.NewMilliQuantity(q.MilliValue()*n, q.Format)
	// Re-canonicalize so a whole-core figure prints as "4" and a byte figure keeps its binary suffix.
	if out.MilliValue()%1000 == 0 {
		return *resource.NewQuantity(out.MilliValue()/1000, q.Format)
	}
	return *out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 3 — a rollout strategy that contradicts the operator's own declared minimum
// ─────────────────────────────────────────────────────────────────────────────────────────────

// RolloutContradictsDeclaredMinimum reports a disagreement between two things the operator wrote,
// and nothing about what any mechanism will do.
//
// A PodDisruptionBudget is a declared minimum available. A rollout strategy can take availability
// below it, and the disruption controller never notices — because the eviction path, the only path a
// budget constrains, is not the path a rolling update takes (see the file header, and the testbed
// experiment that proved it). So the finding is: THIS ROLLOUT STRATEGY CAN TAKE AVAILABILITY BELOW
// THE MINIMUM YOU DECLARED. Not that anything stops, not that anything fails.
//
// THE DENOMINATOR IS status.expectedPods, NOT spec.replicas. A PDB's scope is whatever its selector
// matches, which may be several workloads; B-098 is the record of resolving a budget against one
// workload's replicas and reporting "drains stall forever" on a cluster where a drain proceeds. So
// the arithmetic is expectedPods − maxUnavailable against desiredHealthy, which reduces to the
// single-workload case exactly and stays correct when the selector spans more.
type RolloutContradictsDeclaredMinimum struct{}

func (RolloutContradictsDeclaredMinimum) ID() string {
	return "k8s.config.rollout-contradicts-declared-minimum"
}
func (RolloutContradictsDeclaredMinimum) Version() string { return "1.0.0" }

// RequiredKinds — deployments for the strategy declaration and poddisruptionbudgets for the minimum
// declaration; the finding is the comparison, so both are load-bearing. `statefulsets` is
// deliberately omitted: a StatefulSet's maxUnavailable sits behind an unreadable feature gate, so no
// round arithmetic is done for one anywhere in this file. `pods` is omitted because the budget's own
// status already counts the matched set — reading pods would be a second, less authoritative count.
// See deps.go for what belongs in this list.
func (RolloutContradictsDeclaredMinimum) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "poddisruptionbudgets"})
}

func (r RolloutContradictsDeclaredMinimum) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, i := range sortedDeployments(inv) {
		d := &inv.Deployments[i]
		if !opts.IncludeSystem && isSystemNamespace(d.Namespace) {
			continue
		}
		// Recreate is deliberately out of scope here. It has no maxUnavailable to compare, and
		// k8s.workload.risky-rollout-strategy already states its mechanism — a second finding on the same
		// object would repeat rather than add.
		if !isRollingUpdate(d) {
			continue
		}
		replicas := deployReplicas(d)
		maxUnavailable, _, specText, ok := resolvedFenceposts(d, replicas)
		if !ok || maxUnavailable == 0 {
			continue
		}
		for _, pdb := range matchingPDBs(inv, d) {
			st := pdb.Status
			// An uncomputed status is not a declared minimum of zero; it is a controller that has
			// not answered. This is the same guard pdbStatusIsFresh exists for one level up.
			if !pdbStatusIsFresh(pdb) || st.ExpectedPods == 0 {
				continue
			}
			remaining := int(st.ExpectedPods) - maxUnavailable
			if remaining >= int(st.DesiredHealthy) {
				continue
			}
			declared := "spec.maxUnavailable"
			if pdb.Spec.MinAvailable != nil {
				declared = fmt.Sprintf("spec.minAvailable=%s", pdb.Spec.MinAvailable.String())
			} else if pdb.Spec.MaxUnavailable != nil {
				declared = fmt.Sprintf("spec.maxUnavailable=%s", pdb.Spec.MaxUnavailable.String())
			}
			evidence := []string{
				fmt.Sprintf("Deployment %s/%s: spec.strategy.rollingUpdate %s resolves to maxUnavailable=%d "+
					"over spec.replicas=%d", d.Namespace, d.Name, specText, maxUnavailable, replicas),
				fmt.Sprintf("PodDisruptionBudget %s/%s declares %s, and its controller publishes "+
					"status.expectedPods=%d with status.desiredHealthy=%d",
					pdb.Namespace, pdb.Name, declared, st.ExpectedPods, st.DesiredHealthy),
				fmt.Sprintf("expectedPods %d − maxUnavailable %d = %d available during an update, against a "+
					"declared minimum of %d: the two declarations disagree by %s",
					st.ExpectedPods, maxUnavailable, remaining, st.DesiredHealthy, nWord(int(st.DesiredHealthy)-remaining, "pod", "pods")),
				"A ROLLING UPDATE IS NOT AN EVICTION. The disruption controller acts on the /eviction " +
					"subresource; the ReplicaSet controller removes pods with a direct delete, which does not " +
					"consult the budget. So the budget does not constrain this path and is not consulted on " +
					"it — this finding reports a contradiction between two declarations the operator wrote, " +
					"and predicts nothing about either mechanism.",
			}
			if int(st.ExpectedPods) != int(replicas) {
				evidence = append(evidence, fmt.Sprintf(
					"the budget's selector spans more than this workload: status.expectedPods=%d against this "+
						"Deployment's spec.replicas=%d, so the arithmetic above is over the whole matched set, "+
						"which is the set the controller counts", st.ExpectedPods, replicas))
			}
			out = append(out, types.Finding{
				ID:          findingID(r.ID(), "Deployment", d.Namespace, d.Name+"|"+pdb.Name),
				IDBasis:     &types.ResourceRef{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name + "|" + pdb.Name},
				RuleID:      r.ID(),
				RuleVersion: r.Version(),
				Title: fmt.Sprintf("Update strategy for %s/%s goes below the minimum declared for it",
					d.Namespace, d.Name),
				Description: fmt.Sprintf(
					"Deployment %s/%s resolves to maxUnavailable=%d, which can leave %s available "+
						"during an update, while PodDisruptionBudget %s/%s declares that %d must stay "+
						"available. Both numbers were written by hand and they disagree. Nothing in the cluster "+
						"reconciles them: the budget is enforced on the eviction path and a rolling update does "+
						"not use it, so this contradiction produces no error, no event and no warning.",
					d.Namespace, d.Name, maxUnavailable, nWord(remaining, "pod", "pods"), pdb.Namespace, pdb.Name, st.DesiredHealthy),
				WhyItMatters: "Two numbers the same team wrote say different things about the same workload, " +
					"and the cluster will never tell them which one it is honouring.",
				Evidence: evidence,
				Severity: types.SeverityMedium,
				Category: types.CategoryConfig,
				AffectedResources: []types.ResourceRef{
					{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name},
					{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
				},
				EstimatedEffort: types.EffortLow,
				// Both readings are exact and the comparison is arithmetic; which of the two numbers
				// the operator meant is the part we cannot know.
				Confidence: 0.8,
				Provenance: provenance(),
			})
		}
	}
	return out
}

// matchingPDBs returns the budgets whose selector matches this Deployment's pod template, in name
// order. Selector compilation reuses pdbSelector so a nil, invalid or empty selector matches nothing
// here exactly as it does in pdb_blocks_drains.go.
func matchingPDBs(inv *collect.Inventory, d *appsv1.Deployment) []*policyv1.PodDisruptionBudget {
	podLabels := labels.Set(d.Spec.Template.Labels)
	var out []*policyv1.PodDisruptionBudget
	for i := range inv.PDBs {
		pdb := &inv.PDBs[i]
		if pdb.Namespace != d.Namespace {
			continue
		}
		sel := pdbSelector(pdb)
		if sel == nil || !sel.Matches(podLabels) {
			continue
		}
		out = append(out, pdb)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 4 — a partition nobody removed
// ─────────────────────────────────────────────────────────────────────────────────────────────

// StatefulSetPartitionLeftBehind reports a canary nobody finished. spec.updateStrategy.rollingUpdate
// .partition holds every ordinal BELOW it on the previous revision, permanently and silently: the
// StatefulSet reports Ready, the apply reports success, and the low ordinals keep the old image.
//
// This claim is gate-independent, which is why it exists instead of round arithmetic: partition is
// honoured by every cluster that serves apps/v1, unlike maxUnavailable.
type StatefulSetPartitionLeftBehind struct{}

func (StatefulSetPartitionLeftBehind) ID() string {
	return "k8s.config.statefulset-partition-left-behind"
}
func (StatefulSetPartitionLeftBehind) Version() string { return "1.0.0" }

// RequiredKinds — the StatefulSet's own spec and status carry the entire claim. `pods` is
// deliberately omitted: the ordinals held back are arithmetic over partition and replicas, and
// reading the pods would answer a different question (which pods exist now) that this claim does not
// rest on. `poddisruptionbudgets` is not declared because it is not read.
// See deps.go for what belongs in this list.
func (StatefulSetPartitionLeftBehind) RequiredKinds() []string { return []string{"statefulsets"} }

func (r StatefulSetPartitionLeftBehind) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, i := range sortedStatefulSets(inv) {
		s := &inv.StatefulSets[i]
		if !opts.IncludeSystem && isSystemNamespace(s.Namespace) {
			continue
		}
		// An empty updateStrategy type is RollingUpdate (the API server defaults it). OnDelete has
		// no partition semantics at all, and rollout-does-not-self-roll already reports it.
		if s.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType {
			continue
		}
		ru := s.Spec.UpdateStrategy.RollingUpdate
		if ru == nil || ru.Partition == nil || *ru.Partition <= 0 {
			continue
		}
		partition := *ru.Partition
		replicas := stsReplicas(s)
		heldBack := int(partition)
		if heldBack > int(replicas) {
			heldBack = int(replicas)
		}

		var ordinalText string
		if int(partition) >= int(replicas) {
			ordinalText = fmt.Sprintf("partition=%d is at or above spec.replicas=%d, so NO ordinal is replaced "+
				"when the pod template changes", partition, replicas)
		} else {
			ordinalText = fmt.Sprintf("partition=%d over %s: ordinals 0 through %d (%s) are "+
				"not replaced when the pod template changes; only ordinals %d and above are",
				partition, nWord(replicas, "replica", "replicas"), partition-1, nWord(heldBack, "pod", "pods"), partition)
		}
		evidence := []string{
			fmt.Sprintf("StatefulSet %s/%s: spec.updateStrategy.rollingUpdate.partition=%d", s.Namespace, s.Name, partition),
			ordinalText,
		}
		pending := s.Status.CurrentRevision != "" && s.Status.UpdateRevision != "" &&
			s.Status.CurrentRevision != s.Status.UpdateRevision
		if pending {
			evidence = append(evidence, fmt.Sprintf(
				"status.currentRevision=%s and status.updateRevision=%s already differ, with "+
					"status.updatedReplicas=%d of %d — so the pods below the partition are on the earlier "+
					"revision right now, not hypothetically",
				s.Status.CurrentRevision, s.Status.UpdateRevision, s.Status.UpdatedReplicas, replicas))
		} else {
			evidence = append(evidence, fmt.Sprintf(
				"status.currentRevision equals status.updateRevision (%s), so nothing is held back at the "+
					"moment of this reading — the partition applies to the NEXT template change",
				emptyAs(s.Status.CurrentRevision, "not reported")))
		}
		sev := types.SeverityMedium
		if !pending {
			sev = types.SeverityLow
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "StatefulSet", s.Namespace, s.Name),
			IDBasis:     &types.ResourceRef{Kind: "StatefulSet", Namespace: s.Namespace, Name: s.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("A partition is left set on %s/%s", s.Namespace, s.Name),
			Description: fmt.Sprintf(
				"StatefulSet %s/%s declares spec.updateStrategy.rollingUpdate.partition=%d over %s. "+
					"A partition holds every ordinal below it on the previous revision: the controller replaces "+
					"only ordinals at or above the number. Nothing reports this — the StatefulSet's own status "+
					"is consistent, and an apply that changes the template completes normally while those pods "+
					"keep what they had. A partition is the mechanism for a staged canary, so a non-zero value "+
					"is either a canary in progress or one nobody removed.",
				s.Namespace, s.Name, partition, nWord(replicas, "replica", "replicas")),
			WhyItMatters: "A partition left behind is a permanent version split inside one workload, and the " +
				"only place it is visible is the field itself.",
			Evidence:          evidence,
			Severity:          sev,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "StatefulSet", Namespace: s.Namespace, Name: s.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.7,
			Provenance:        provenance(),
		})
	}
	return out
}
