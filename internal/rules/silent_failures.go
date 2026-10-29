package rules

// silent_failures.go — GROUND TRUTH: states the cluster records and nothing reports.
//
// Four readings, all taken from `status` fields the controllers themselves wrote. Each one is a
// thing that can be true for weeks while every dashboard is green and every deployment reported
// success: a CronJob that has quietly stopped completing, an HPA the controller wanted to scale
// past its ceiling, a claim that never bound with a pod waiting on it, an Ingress naming a backend
// that resolves to nothing.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
// Every one of these readings has an innocent explanation the snapshot cannot rule out, so the
// finding states the observation and the window and stops:
//
//	No "broken", "failing", "misconfigured", "stuck". The file's own NAME says failures and its
//	OUTPUT must not — the same trap rotation.go has with the word "rotation". A CronJob with no
//	recorded success in the window may be paused on purpose, or may simply have a schedule whose
//	period is longer than the window. We do not parse cron expressions (that would be a dependency
//	and a second thing to be wrong about), so the schedule is QUOTED and the reader compares it to
//	the window themselves.
//
//	A NIL lastSuccessfulTime IS NOT AN OLD TIMESTAMP. "has never recorded a successful completion"
//	and "the last recorded success was 9d before this reading" are two different statements about
//	two different clusters, and a rule that renders the first as the second has invented a date.
//	They are separate branches with separate wording, and a test asserts they do not read alike.
//
//	THE WINDOW IS ALWAYS PRINTED. A window without its length is an unbounded claim.
//
//	No "under-provisioned" for an HPA at its ceiling. The reading is currentReplicas == maxReplicas
//	WITH the API's own ScalingLimited condition. Both halves are required: a workload legitimately
//	sized at exactly its ceiling is not a finding, and the condition is the controller saying it
//	wanted more.
//
//	No claim about WHICH of a Pending claim and its Pending pod is waiting for the other.
//	StorageClasses are not collected, so volumeBindingMode is unreadable, and
//	WaitForFirstConsumer + no scheduled consumer is the normal healthy state — the single most
//	likely false positive in this epic. The rule fires only when a Pod references the claim and is
//	itself Pending, because the pod is the evidence that a consumer exists at all, and the finding
//	says outright that the binding mode was not read.
//
//	No durations of anything that happens, no impact language, and no dollars. There is no request,
//	revenue or SLA data in the snapshot.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// cronJobSuccessWindow is the observation window for the CronJob rule, and it is named in every
// finding that rule emits. Seven days is long enough that a daily or hourly schedule has had many
// chances and short enough to be worth reading; a weekly or monthly schedule sits OUTSIDE it, which
// is exactly why the schedule string is quoted beside it.
const cronJobSuccessWindow = 7 * 24 * time.Hour

// cronJobFirstRunGrace applies only to the nil-lastSuccessfulTime branch: a CronJob whose last
// schedule was moments ago may have a run in flight, and "has never completed successfully" about
// a job that started 30s ago is a statement about our timing rather than the cluster's.
const cronJobFirstRunGrace = time.Hour

// dayCount renders a duration as whole days for evidence — "9d". time.Duration.String() would
// print "216h0m0s", which is a worse sentence and not the unit the window is expressed in.
func dayCount(d time.Duration) string { return fmt.Sprintf("%dd", int(d.Hours()/24)) }

// stamp renders a time the way node_drain.go:226 does, so every timestamp in the report reads the
// same and none of them carry a local timezone the reader cannot resolve.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ─────────────────────────────────────────────────────────────────────────────────────────────
// HPA pinned at its ceiling
// ─────────────────────────────────────────────────────────────────────────────────────────────

type HPAPinnedAtMax struct{}

// TEST COVERAGE, STATED: unit tests only. `ScalingLimited` is published by the HPA controller,
// which needs a metrics source; the kind testbed runs no metrics-server, so the condition is never
// written and the positive branch cannot fire there. Closing this is cheap — one metrics-server
// manifest in testdata/testbed — and is the first of the three coverage gaps worth closing.
func (HPAPinnedAtMax) ID() string      { return "k8s.reliability.hpa-pinned-at-max" }
func (HPAPinnedAtMax) Version() string { return "1.0.0" }

// RequiredKinds — the HPA list is the whole claim. The scale TARGET is deliberately not declared:
// the rule reads the HPA's own status and spec, never the Deployment behind scaleTargetRef, so a
// run without the workload lists makes exactly the same claim.
// See deps.go for what belongs in this list.
func (HPAPinnedAtMax) RequiredKinds() []string { return []string{"horizontalpodautoscalers"} }

func (r HPAPinnedAtMax) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// This rule reasons about a PRESENT condition rather than an absence, so the guard is not
	// strictly load-bearing for correctness — but a run that never listed HPAs must not be
	// comparable with one that did, and silence here is what makes RequiredKinds honest.
	if !observed(inv, "horizontalpodautoscalers") {
		return nil
	}
	var out []types.Finding
	idx := make([]int, 0, len(inv.HPAs))
	for i := range inv.HPAs {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.HPAs[idx[a]], &inv.HPAs[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})

	for _, i := range idx {
		h := &inv.HPAs[i]
		if !opts.IncludeSystem && isSystemNamespace(h.Namespace) {
			continue
		}
		if h.Spec.MaxReplicas <= 0 || h.Status.CurrentReplicas != h.Spec.MaxReplicas {
			continue
		}
		cond := scalingLimitedCondition(h)
		if cond == nil {
			continue
		}
		evidence := []string{
			fmt.Sprintf("HPA %s/%s: status.currentReplicas=%d equals spec.maxReplicas=%d",
				h.Namespace, h.Name, h.Status.CurrentReplicas, h.Spec.MaxReplicas),
			fmt.Sprintf("condition ScalingLimited=True (reason=%s) — the autoscaler's own report that "+
				"it wanted a replica count it is not allowed to reach: %q",
				emptyAs(cond.Reason, "not set"), strings.TrimSpace(cond.Message)),
			// A ZERO TIME IS NOT A DATE. An unset lastTransitionTime rendered through stamp() prints
			// 0001-01-01T00:00:00Z, which reads as a real timestamp from the year 1 — the same class
			// of defect as rendering a nil lastSuccessfulTime as an old success. Say it is absent.
			condTimeNote(cond.LastTransitionTime.Time, readingTime(inv)),
		}
		if h.Status.DesiredReplicas != 0 && h.Status.DesiredReplicas != h.Status.CurrentReplicas {
			evidence = append(evidence, fmt.Sprintf("status.desiredReplicas=%d", h.Status.DesiredReplicas))
		}
		target := fmt.Sprintf("%s %s/%s", h.Spec.ScaleTargetRef.Kind, h.Namespace, h.Spec.ScaleTargetRef.Name)
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "HorizontalPodAutoscaler", h.Namespace, h.Name),
			IDBasis:     &types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("HPA %s/%s sits at its maxReplicas ceiling", h.Namespace, h.Name),
			Description: fmt.Sprintf(
				"HorizontalPodAutoscaler %s/%s reports status.currentReplicas=%d, which is its own "+
					"spec.maxReplicas, and carries a ScalingLimited condition set to True. Both halves are "+
					"required to state this: a workload sized at exactly its ceiling is an ordinary steady "+
					"state, and the condition is the autoscaler reporting that it computed a higher "+
					"recommendation than the ceiling allows. The scale target is %s.",
				h.Namespace, h.Name, h.Status.CurrentReplicas, target),
			WhyItMatters: "An autoscaler at its ceiling has no headroom left to answer a change in demand, " +
				"and the ceiling is a number somebody chose once — the condition is the only place the cluster " +
				"says the number is now binding.",
			Evidence: evidence,
			Severity: types.SeverityMedium,
			Category: types.CategoryReliability,
			AffectedResources: []types.ResourceRef{
				{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name},
				{Kind: h.Spec.ScaleTargetRef.Kind, Namespace: h.Namespace, Name: h.Spec.ScaleTargetRef.Name},
			},
			EstimatedEffort: types.EffortLow,
			// The reading is exact; whether the ceiling should move is a capacity and budget
			// question the snapshot does not hold.
			Confidence: 0.7,
			Provenance: provenance(),
		})
	}
	return out
}

// scalingLimitedCondition returns the ScalingLimited condition when the controller has set it True.
// The condition is the second half of the claim: without it, currentReplicas == maxReplicas is just
// a workload sitting at a number somebody chose.
func scalingLimitedCondition(h *autoscalingv2.HorizontalPodAutoscaler) *autoscalingv2.HorizontalPodAutoscalerCondition {
	for i := range h.Status.Conditions {
		c := &h.Status.Conditions[i]
		if c.Type == autoscalingv2.ScalingLimited && c.Status == corev1.ConditionTrue {
			return c
		}
	}
	return nil
}

// condTimeNote renders a condition's transition time against the reading, and says so plainly when
// the API served no transition time at all rather than printing the zero value as a date.
func condTimeNote(transition, reading time.Time) string {
	if transition.IsZero() {
		return fmt.Sprintf("the condition carries no lastTransitionTime, so how long it has held is not "+
			"readable; reading taken %s", stamp(reading))
	}
	return fmt.Sprintf("condition lastTransitionTime=%s; reading taken %s", stamp(transition), stamp(reading))
}

func emptyAs(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A Pending claim with a Pending consumer
// ─────────────────────────────────────────────────────────────────────────────────────────────

type PVCPendingWithBlockedConsumer struct{}

func (PVCPendingWithBlockedConsumer) ID() string      { return "k8s.reliability.pvc-pending" }
func (PVCPendingWithBlockedConsumer) Version() string { return "1.0.0" }

// RequiredKinds — both lists are load-bearing, and the pod half is the interesting one. Without the
// pod list the rule cannot tell a claim nobody consumes (normal, and the most likely false positive
// in this family) from a claim a pod is waiting on, so it would either fire on every Pending claim
// or fall silent while looking identical. `persistentvolumes` is deliberately omitted: a Pending
// claim has no bound volume by definition, so no PV is read.
// See deps.go for what belongs in this list.
func (PVCPendingWithBlockedConsumer) RequiredKinds() []string {
	return sortedKinds([]string{"persistentvolumeclaims", "pods"})
}

func (r PVCPendingWithBlockedConsumer) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD. Both halves reason about absence: an unlisted pod list would make every
	// Pending claim look unconsumed, and an unlisted claim list would make the rule silent while
	// looking identical to a cluster with nothing Pending.
	if !observed(inv, "persistentvolumeclaims") || !observed(inv, "pods") {
		return nil
	}
	var out []types.Finding
	idx := make([]int, 0, len(inv.PVCs))
	for i := range inv.PVCs {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.PVCs[idx[a]], &inv.PVCs[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})

	for _, i := range idx {
		pvc := &inv.PVCs[i]
		if !opts.IncludeSystem && isSystemNamespace(pvc.Namespace) {
			continue
		}
		if pvc.Status.Phase != corev1.ClaimPending {
			continue
		}
		consumers := pendingPodsReferencing(inv, pvc.Namespace, pvc.Name)
		if len(consumers) == 0 {
			continue
		}
		names := make([]string, 0, len(consumers))
		refs := []types.ResourceRef{{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}}
		for _, p := range consumers {
			names = append(names, p.Name)
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name})
		}
		evidence := []string{
			fmt.Sprintf("PersistentVolumeClaim %s/%s: status.phase=Pending", pvc.Namespace, pvc.Name),
			fmt.Sprintf("%s reference this claim and are themselves status.phase=Pending: %s", nWord(len(names), "pod", "pods"), strings.Join(names, ", ")),
			"StorageClasses are NOT collected, so spec.volumeBindingMode is not read. A claim using " +
				"WaitForFirstConsumer binds only after a consumer is scheduled, so which of the two is " +
				"waiting for the other is not readable from this snapshot — a claim with no referencing " +
				"pod is deliberately not reported at all, in either direction.",
		}
		if msg := schedulingNote(consumers); msg != "" {
			evidence = append(evidence, msg)
		}
		if sc := pvc.Spec.StorageClassName; sc != nil {
			evidence = append(evidence, fmt.Sprintf("spec.storageClassName=%q (the class object itself was not read)", *sc))
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolumeClaim", pvc.Namespace, pvc.Name),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Claim %s/%s is Pending with a Pending consumer", pvc.Namespace, pvc.Name),
			Description: fmt.Sprintf(
				"PersistentVolumeClaim %s/%s reports status.phase=Pending, and %s that reference it "+
					"report status.phase=Pending as well. Both readings are taken verbatim from status. This "+
					"pairing is the whole condition for reporting it: a Pending claim with nothing consuming it "+
					"is the ordinary state of a WaitForFirstConsumer claim and is never reported here.",
				pvc.Namespace, pvc.Name, nWord(len(names), "pod", "pods")),
			WhyItMatters: "A claim that never bound is invisible in the workload's own status — the pod " +
				"simply waits, and nothing in the Deployment or StatefulSet says why.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.75,
			Provenance:        provenance(),
		})
	}
	return out
}

// pendingPodsReferencing returns the Pending pods in ns that mount claim, in name order. A pod that
// is Running proves the claim is not holding it up, whatever the claim's own phase says.
func pendingPodsReferencing(inv *collect.Inventory, ns, claim string) []corev1.Pod {
	var out []corev1.Pod
	for i := range inv.Pods {
		p := inv.Pods[i]
		if p.Namespace != ns || p.Status.Phase != corev1.PodPending {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == claim {
				out = append(out, p)
				break
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// schedulingNote quotes the scheduler's own PodScheduled message. It is the cluster's diagnostic
// rather than ours, which is why it is worth carrying — and it is capped, because an arbitrary
// message is data flowing into a document and long data is a rendering problem, not a claim.
func schedulingNote(pods []corev1.Pod) string {
	for _, p := range pods {
		for _, c := range p.Status.Conditions {
			if c.Type != corev1.PodScheduled || c.Status == corev1.ConditionTrue {
				continue
			}
			msg := strings.TrimSpace(c.Message)
			if len(msg) > 200 {
				msg = msg[:200] + "…"
			}
			if msg == "" {
				continue
			}
			return fmt.Sprintf("pod %s/%s condition PodScheduled=%s (reason=%s), scheduler message: %q",
				p.Namespace, p.Name, c.Status, emptyAs(c.Reason, "not set"), msg)
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// An Ingress backend that resolves to nothing
// ─────────────────────────────────────────────────────────────────────────────────────────────

type IngressBackendUnresolved struct{}

func (IngressBackendUnresolved) ID() string { return "k8s.config.ingress-backend-unresolved" }

// Version 1.1.0 (2026-08-30): the port branch. Rule logic changed, so Gate 2 withholds a comparison
// across it rather than reporting the new evidence as a cluster change.
func (IngressBackendUnresolved) Version() string { return "1.1.0" }

// RequiredKinds — all three are load-bearing and all three feed an ABSENCE claim: the Ingress list
// is what is iterated, the Service list is what "no Service named X" rests on, and the
// EndpointSlice list is what "publishes zero ready addresses" rests on. Deny any one and the rule
// would state an absence it never looked for.
// See deps.go for what belongs in this list.
func (IngressBackendUnresolved) RequiredKinds() []string {
	return sortedKinds([]string{"endpointslices", "ingresses", "services"})
}

func (r IngressBackendUnresolved) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "ingresses") || !observed(inv, "services") || !observed(inv, "endpointslices") {
		return nil
	}
	idx := make([]int, 0, len(inv.Ingresses))
	for i := range inv.Ingresses {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.Ingresses[idx[a]], &inv.Ingresses[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})

	// COVERAGE IS RULE-WIDE, NOT PER-OBJECT. The first version of this rule attached each skipped
	// backend's disclosure to the finding for the same Ingress — so an Ingress whose ONLY backend
	// could not be judged produced no finding and therefore no disclosure, and the report's coverage
	// looked total while a whole class of backend had been dropped. The counts below are cluster-wide
	// and ride on every finding this rule emits.
	judgedBackends := 0
	skippedClass := map[string]int{}
	type pending struct {
		ing      *networkingv1.Ingress
		evidence []string
		notes    []string
		refs     []types.ResourceRef
	}
	var found []pending

	for _, i := range idx {
		ing := &inv.Ingresses[i]
		if !opts.IncludeSystem && isSystemNamespace(ing.Namespace) {
			continue
		}
		var evidence, skipped []string
		seen := map[string]bool{}
		refs := []types.ResourceRef{{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name}}

		for _, b := range ingressBackends(ing) {
			if b.resourceKind != "" {
				skippedClass[skipResourceBackend]++
				note := fmt.Sprintf("backend.resource %s/%s is resolved by the Ingress controller, not by a "+
					"Service, so it is not judged here", b.resourceKind, b.resourceName)
				if !seen[note] {
					seen[note] = true
					skipped = append(skipped, note)
				}
				continue
			}
			if b.serviceName == "" {
				continue
			}
			key := "svc:" + b.serviceName
			if seen[key] {
				continue
			}
			seen[key] = true

			svc := findService(inv, ing.Namespace, b.serviceName)
			if svc == nil {
				judgedBackends++
				evidence = append(evidence, fmt.Sprintf(
					"rule host %q path %q names backend Service %q, and no Service named %q exists in namespace %s",
					emptyAs(b.host, "(no host)"), emptyAs(b.path, "/"), b.serviceName, b.serviceName, ing.Namespace))
				continue
			}
			if svc.Spec.Type == corev1.ServiceTypeExternalName {
				skippedClass[skipExternalNameBackend]++
				skipped = append(skipped, fmt.Sprintf(
					"backend Service %s/%s is type ExternalName, which has no endpoints by design, so its "+
						"published set is not judged here", svc.Namespace, svc.Name))
				continue
			}
			// THE PORT, NOT ONLY THE NAME — a refinement, not a second rule.
			//
			// An Ingress backend naming a real Service on a port that Service does not define is
			// unroutable in exactly the way a missing Service is, and it is the narrower case of this
			// rule's own claim: "this backend does not resolve". A separate rule would put a second card
			// on the same backend, which is what the overlap census exists to prevent.
			//
			// A backend with NEITHER a port name nor a number is legal — the controller picks the
			// Service's only port — so it is not judged.
			if portMissing(svc, b) {
				judgedBackends++
				evidence = append(evidence, fmt.Sprintf(
					"rule host %q path %q names backend Service %q on port %s, and that Service defines "+
						"no such port (it defines: %s)",
					emptyAs(b.host, "(no host)"), emptyAs(b.path, "/"), b.serviceName,
					backendPortText(b), servicePortsText(svc)))
				continue
			}
			pub := publishedFor(inv, svc)
			if pub.foreign {
				skippedClass[skipForeignBackend]++
				skipped = append(skipped, fmt.Sprintf(
					"backend Service %s/%s has EndpointSlices written by another controller, whose semantics "+
						"this arithmetic does not assume", svc.Namespace, svc.Name))
				continue
			}
			judgedBackends++
			if pub.ready == 0 {
				refs = append(refs, types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
				evidence = append(evidence, fmt.Sprintf(
					"rule host %q path %q names backend Service %s/%s, which publishes %s in the "+
						"%s family and 0 with conditions.ready=true",
					emptyAs(b.host, "(no host)"), emptyAs(b.path, "/"), svc.Namespace, svc.Name, nWord(pub.total, "address", "addresses"), emptyAs(pub.family, "no")))
			}
		}
		if len(evidence) == 0 {
			continue
		}
		sort.Strings(skipped)
		found = append(found, pending{ing: ing, evidence: evidence, notes: skipped, refs: refs})
	}

	coverage := ingressCoverageLine(judgedBackends, skippedClass)
	out := make([]types.Finding, 0, len(found))
	for _, p := range found {
		ing := p.ing
		evidence := append(append(append([]string{}, p.evidence...), p.notes...), coverage)
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Ingress", ing.Namespace, ing.Name),
			IDBasis:     &types.ResourceRef{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Ingress %s/%s names a backend that resolves to nothing", ing.Namespace, ing.Name),
			Description: fmt.Sprintf(
				"Ingress %s/%s declares %s that this reading could not resolve: either "+
					"no Service of that name was listed in the namespace, or the Service exists and its "+
					"EndpointSlices publish no address with conditions.ready=true. Those are two different "+
					"statements and the evidence says which applies to each backend. What the Ingress "+
					"controller does with an unresolved backend is controller-specific and not read here.",
				ing.Namespace, ing.Name, nWord(len(p.evidence), "backend reference", "backend references")),
			WhyItMatters: "An Ingress object is accepted whether or not its backend resolves, so a renamed or " +
				"deleted Service leaves the routing declaration intact and nothing reports the mismatch.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: p.refs,
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.7,
			Provenance:        provenance(),
		})
	}
	return out
}

// The backend shapes this rule cannot judge, spelled once so the coverage line and the per-object
// note cannot drift apart.
const (
	skipResourceBackend     = "backend.resource reference|backend.resource references|, which the Ingress controller resolves rather than a Service"
	skipExternalNameBackend = "backend Service|backend Services| of type ExternalName, which have no endpoints by design"
	skipForeignBackend      = "backend Service|backend Services| whose EndpointSlices are written by another controller"
)

var ingressSkipOrder = []string{skipResourceBackend, skipExternalNameBackend, skipForeignBackend}

func ingressCoverageLine(judged int, skipped map[string]int) string {
	var parts []string
	total := judged
	for _, k := range ingressSkipOrder {
		if n := skipped[k]; n > 0 {
			total += n
			// A class is "one|many|rest": the count says its noun in words.
			w := strings.SplitN(k, "|", 3)
			parts = append(parts, nWord(n, w[0], w[1])+w[2])
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("coverage: judged all %s in this reading", nWord(total, "Ingress backend reference", "Ingress backend references"))
	}
	return fmt.Sprintf("coverage: judged %d of %s in this reading; not judged: %s",
		judged, nWord(total, "Ingress backend reference", "Ingress backend references"), strings.Join(parts, ", "))
}

type ingressBackend struct {
	host, path   string
	serviceName  string
	resourceKind string
	resourceName string
	// portName and portNumber are the backend's declared port, exactly one of which is set. They are
	// carried so the PORT can be resolved against the Service and not only the Service's NAME — a
	// refinement of this rule's own claim rather than a second rule, per the Phase 1 overlap census.
	portName   string
	portNumber int32
}

// portMissing reports whether a backend names a port the Service does not define. A backend that names no
// port at all is not judged: the controller resolves it to the Service's single port, and a Service with
// exactly one port is the common shape.
func portMissing(svc *corev1.Service, b ingressBackend) bool {
	if b.portName == "" && b.portNumber == 0 {
		return false
	}
	for _, p := range svc.Spec.Ports {
		if b.portName != "" && p.Name == b.portName {
			return false
		}
		if b.portNumber != 0 && p.Port == b.portNumber {
			return false
		}
	}
	// A Service with no ports declared at all is a different defect and not this branch's claim.
	return len(svc.Spec.Ports) > 0
}

func backendPortText(b ingressBackend) string {
	if b.portName != "" {
		return strconv.Quote(b.portName)
	}
	return fmt.Sprintf("%d", b.portNumber)
}

func servicePortsText(svc *corev1.Service) string {
	if len(svc.Spec.Ports) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		if p.Name != "" {
			parts = append(parts, fmt.Sprintf("%q/%d", p.Name, p.Port))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d", p.Port))
	}
	return strings.Join(parts, ", ")
}

// ingressBackends flattens every backend an Ingress declares, including the default backend, in
// declaration order.
func ingressBackends(ing *networkingv1.Ingress) []ingressBackend {
	var out []ingressBackend
	add := func(host, path string, b networkingv1.IngressBackend) {
		e := ingressBackend{host: host, path: path}
		if b.Service != nil {
			e.serviceName = b.Service.Name
			e.portName = b.Service.Port.Name
			e.portNumber = b.Service.Port.Number
		}
		if b.Resource != nil {
			e.resourceKind = b.Resource.Kind
			e.resourceName = b.Resource.Name
		}
		out = append(out, e)
	}
	if ing.Spec.DefaultBackend != nil {
		add("(default backend)", "", *ing.Spec.DefaultBackend)
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			add(rule.Host, p.Path, p.Backend)
		}
	}
	return out
}

func findService(inv *collect.Inventory, ns, name string) *corev1.Service {
	for i := range inv.Services {
		if inv.Services[i].Namespace == ns && inv.Services[i].Name == name {
			return &inv.Services[i]
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A CronJob with no recorded success in the window
// ─────────────────────────────────────────────────────────────────────────────────────────────

type CronJobNoRecentSuccess struct{}

// TEST COVERAGE, STATED: unit tests AND live, all three states, on the kind testbed
// (testdata/testbed/cronjobs.yaml).
//
// This comment used to say the positive branch was unreachable because "status is controller-owned — it
// cannot be written by hand". That was simply wrong: the status subresource is writable,
// `kubectl patch --subresource=status`, and the wrong claim was doing real work — it was the recorded
// reason the branch went unwitnessed. Both positives are now verified against a live cluster:
// "succeeded 9 days ago" and "scheduled, never succeeded", each printing its own sentence, with a
// suspended CronJob beside them excluded and disclosed in the coverage line.
//
// The fixture ages two timestamps rather than waiting seven days for one and an hour for the other. It
// fabricates the INPUT — the state the controller would publish given time — and never the output.
func (CronJobNoRecentSuccess) ID() string      { return "k8s.reliability.cronjob-no-recent-success" }
func (CronJobNoRecentSuccess) Version() string { return "1.0.0" }

// RequiredKinds — the CronJob list is the whole claim, and it is the one collector addition this
// epic made. `jobs` is not declared BECAUSE JOBS ARE NOT COLLECTED: every CronJob run spawns one,
// the volume is orders of magnitude larger, and status.lastSuccessfulTime on the CronJob itself
// carries the claim. Declaring a kind nothing reads would make the comparison withhold a
// comparison it could safely have made.
// See deps.go for what belongs in this list.
func (CronJobNoRecentSuccess) RequiredKinds() []string { return []string{"cronjobs"} }

func (r CronJobNoRecentSuccess) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD. The claim is about the ABSENCE of a recorded success, so an unlisted CronJob
	// list must silence the rule rather than read as a cluster with no scheduled work.
	if !observed(inv, "cronjobs") {
		return nil
	}
	reading := readingTime(inv)
	cutoff := reading.Add(-cronJobSuccessWindow)
	window := dayCount(cronJobSuccessWindow)

	// coverage counts, so a report that judged 3 of 11 CronJobs never looks like one that judged 11.
	var judged, suspended, unscheduled, inFlight int
	type hit struct {
		cj    *batchv1.CronJob
		never bool
	}
	var hits []hit

	idx := make([]int, 0, len(inv.CronJobs))
	for i := range inv.CronJobs {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.CronJobs[idx[a]], &inv.CronJobs[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})

	for _, i := range idx {
		cj := &inv.CronJobs[i]
		if !opts.IncludeSystem && isSystemNamespace(cj.Namespace) {
			continue
		}
		// FOUNDER CONDITION 1: a deliberate pause, handled before anything else and never counted
		// as a silent anything.
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			suspended++
			continue
		}
		last := cj.Status.LastSuccessfulTime
		sched := cj.Status.LastScheduleTime
		if last == nil {
			// A CronJob the controller has never scheduled is not a CronJob that stopped
			// succeeding — it may be brand new, or its first occurrence may be in the future.
			if sched == nil {
				unscheduled++
				continue
			}
			// A run that started moments ago may still be in flight.
			if reading.Sub(sched.Time) < cronJobFirstRunGrace {
				inFlight++
				continue
			}
			judged++
			hits = append(hits, hit{cj: cj, never: true})
			continue
		}
		judged++
		if last.Time.Before(cutoff) {
			hits = append(hits, hit{cj: cj, never: false})
		}
	}

	coverage := cronCoverageLine(judged, suspended, unscheduled, inFlight, window)
	out := make([]types.Finding, 0, len(hits))
	for _, h := range hits {
		cj := h.cj
		var title, description string
		evidence := []string{}

		if h.never {
			// FOUNDER CONDITION 2: a nil is not an old timestamp. This branch never prints a
			// successful-completion date, because there is none to print.
			title = fmt.Sprintf("CronJob %s/%s has never recorded a successful completion", cj.Namespace, cj.Name)
			description = fmt.Sprintf(
				"CronJob %s/%s carries no status.lastSuccessfulTime at all, and the controller has recorded a "+
					"status.lastScheduleTime — so it has been scheduled and no completion has ever been "+
					"recorded. This is a different statement from a schedule that stopped succeeding, and it is "+
					"reported separately for that reason. The observation window below applies to the second "+
					"case; this one is unbounded by construction.",
				cj.Namespace, cj.Name)
			evidence = append(evidence,
				fmt.Sprintf("CronJob %s/%s: status.lastSuccessfulTime is absent; status.lastScheduleTime=%s",
					cj.Namespace, cj.Name, stamp(cj.Status.LastScheduleTime.Time)),
				fmt.Sprintf("a run scheduled within %s of the reading is treated as possibly in flight and is "+
					"not reported; this one was scheduled %s earlier",
					cronJobFirstRunGrace, reading.Sub(cj.Status.LastScheduleTime.Time).Round(time.Minute)))
		} else {
			age := reading.Sub(cj.Status.LastSuccessfulTime.Time)
			title = fmt.Sprintf("CronJob %s/%s recorded no success inside the %s window", cj.Namespace, cj.Name, window)
			description = fmt.Sprintf(
				"The most recent status.lastSuccessfulTime on CronJob %s/%s is %s before this reading, which "+
					"is outside the %s observation window. The timestamp is the controller's own record. No "+
					"verdict follows from it: a schedule whose period is longer than the window reads exactly "+
					"the same way, which is why the schedule is quoted rather than interpreted.",
				cj.Namespace, cj.Name, dayCount(age), window)
			evidence = append(evidence,
				fmt.Sprintf("CronJob %s/%s: status.lastSuccessfulTime=%s, which is %s before this reading (%s)",
					cj.Namespace, cj.Name, stamp(cj.Status.LastSuccessfulTime.Time), dayCount(age), stamp(reading)),
				fmt.Sprintf("observation window: %s — no successful completion is recorded inside it", window))
			if cj.Status.LastScheduleTime != nil {
				evidence = append(evidence, fmt.Sprintf("status.lastScheduleTime=%s, so the controller is still "+
					"creating runs", stamp(cj.Status.LastScheduleTime.Time)))
			}
		}

		// FOUNDER CONDITION 3: the window is named, the schedule is quoted, and no verdict is drawn.
		evidence = append(evidence,
			fmt.Sprintf("spec.schedule=%q — cron expressions are NOT parsed by this rule, so compare the "+
				"period yourself: a schedule that runs less often than every %s cannot have a success inside "+
				"the window and is not a defect", cj.Spec.Schedule, window))
		if n := len(cj.Status.Active); n > 0 {
			evidence = append(evidence, fmt.Sprintf("status.active lists %s at the moment of this reading", nWord(n, "run", "runs")))
		}
		evidence = append(evidence, coverage)

		out = append(out, types.Finding{
			ID:           findingID(r.ID(), "CronJob", cj.Namespace, cj.Name),
			IDBasis:      &types.ResourceRef{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name},
			RuleID:       r.ID(),
			RuleVersion:  r.Version(),
			Title:        title,
			Description:  description,
			WhyItMatters: "A scheduled job that stops completing reports nothing anywhere: the CronJob object stays healthy, the workload it maintains simply stops being maintained.",
			Evidence:     evidence,
			Severity:     types.SeverityMedium,
			Category:     types.CategoryReliability,
			AffectedResources: []types.ResourceRef{
				{Kind: "CronJob", Namespace: cj.Namespace, Name: cj.Name},
			},
			EstimatedEffort: types.EffortLow,
			// The timestamps are exact; whether the reading is a problem depends on the schedule's
			// period and the job's purpose, neither of which this rule interprets.
			Confidence: 0.6,
			Provenance: provenance(),
		})
	}
	return out
}

func cronCoverageLine(judged, suspended, unscheduled, inFlight int, window string) string {
	var parts []string
	if suspended > 0 {
		parts = append(parts, fmt.Sprintf("%d with spec.suspend=true (a deliberate pause, never counted here)", suspended))
	}
	if unscheduled > 0 {
		parts = append(parts, fmt.Sprintf("%d with no status.lastScheduleTime (the controller has recorded no run)", unscheduled))
	}
	if inFlight > 0 {
		parts = append(parts, fmt.Sprintf("%d scheduled within %s of the reading (a run may be in flight)", inFlight, cronJobFirstRunGrace))
	}
	total := judged + suspended + unscheduled + inFlight
	if len(parts) == 0 {
		return fmt.Sprintf("coverage: judged all %s against a %s window", nWord(total, "CronJob", "CronJobs"), window)
	}
	return fmt.Sprintf("coverage: judged %d of %s against a %s window; not judged: %s",
		judged, nWord(total, "CronJob", "CronJobs"), window, strings.Join(parts, ", "))
}
