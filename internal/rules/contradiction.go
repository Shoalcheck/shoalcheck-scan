package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// contradiction.go — TWO THINGS THE OPERATOR DECLARED THAT CANNOT BOTH BE SATISFIED.
//
// From Sweep 4 of the exhaustive-coverage epic (docs/qa/2026-08-29-sweep4-cross-object.md). The distinction
// from Sweep 2 is the whole wording of this family: a dangling reference is a typo or a deletion, and a
// CONTRADICTION is two decisions that were each reasonable on their own. Nothing here is anyone's mistake,
// so nothing here says so — contradiction_test.go enforces that mechanically.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS FAMILY CLAIMS, AND WHERE IT STOPS
//
//	THE DECLARATIONS, NEVER THE OUTCOME. Three replicas sharing a ReadWriteOnce volume is a fact about
//	two objects. Whether anything is currently failing depends on where the scheduler put them — all
//	three on one node works, by accident — and on whether the situation the arithmetic describes has
//	been reached at all. The autoscaler rule is entirely about a state the cluster is NOT in yet.
//
//	SILENCE WHEN THE DENOMINATOR IS NOT OURS TO COMPUTE. B-098 is the precedent: a budget's denominator
//	is the SET of pods its selector matches, not one workload. Where a budget covers more than one
//	workload this family says nothing rather than doing arithmetic over half the inputs.
//
//	NO DOLLARS.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// FOUR OF SWEEP 4'S NINE ROWS ARE DELIBERATELY NOT BUILT HERE
//
//	`PDB.minAvailable` GREATER THAN THE WORKLOAD'S REPLICAS is already reported, from the other side.
//	PDBBlocksDrains reads status.disruptionsAllowed, which is the number the eviction admission plugin
//	actually acts on, and a budget demanding more pods than exist resolves to zero there. Re-deriving it
//	from spec would state one problem twice.
//
//	`topologySpreadConstraints.maxSkew` and REQUIRED `podAntiAffinity` SATISFIABILITY both need the
//	feasibility engine's predicate model to answer honestly, and both are placement claims — they belong
//	beside feasibility.go, not here, and joining the two files for one row each would blur both.
//
//	THE ALERTMANAGER PAIR is a stack analyzer over a CRD this product does not collect. Recorded in
//	Sweep 4 and in the addendum-B section of the Sweep 0 table, not started.

// ── Rule: several replicas, one volume that permits one node ─────────────────────────────────────

// SharedRWOVolume reports workloads with more than one replica whose pod template names a
// ReadWriteOnce PersistentVolumeClaim.
//
// THE STATEFULSET CASE IS HANDLED BY CONSTRUCTION, AND THE CONSTRUCTION IS WORTH NAMING. A StatefulSet's
// `volumeClaimTemplates` produce one claim PER POD, which is the correct and intended use of ReadWriteOnce
// — and the controller synthesises that volume onto the pod, so the POD TEMPLATE never names it. Walking
// `spec.template.spec.volumes` therefore finds only claims named explicitly, which is exactly the set that
// is shared. A later refactor that started reading volumeClaimTemplates would report every StatefulSet in
// existence, so contradiction_test.go asserts the exclusion rather than trusting it.
type SharedRWOVolume struct{}

func (SharedRWOVolume) ID() string      { return "k8s.reliability.rwo-volume-shared" }
func (SharedRWOVolume) Version() string { return "1.0.0" }

// RequiredKinds — the workload kinds are what is walked, and `persistentvolumeclaims` is what the access
// mode is read from. Without the claim list there is no mode, so the rule cannot fire at all.
func (SharedRWOVolume) RequiredKinds() []string { return withWorkloads("persistentvolumeclaims") }

func (r SharedRWOVolume) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "persistentvolumeclaims") {
		return nil
	}
	byKey := map[string]*corev1.PersistentVolumeClaim{}
	for i := range inv.PVCs {
		byKey[inv.PVCs[i].Namespace+"/"+inv.PVCs[i].Name] = &inv.PVCs[i]
	}

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		if !observed(inv, workloadKindToList(w.Kind)) {
			continue
		}
		// HOW MANY PODS THIS WORKLOAD ACTUALLY RUNS, which for a DaemonSet is not its replica count.
		//
		// B-142, found by §8.1's adversarial pass: a DaemonSet carries Replicas == -1 by convention, and
		// the first version read that as "many". A DaemonSet with a nodeSelector matching ONE node — a GPU
		// node, a dedicated ingress node — runs exactly one pod and shares nothing, and on a single-node
		// cluster EVERY DaemonSet with a volume would have fired. The controller publishes the real number
		// in status.desiredNumberScheduled, so ask it rather than inferring.
		pods := w.Replicas
		if w.Kind == "DaemonSet" {
			pods = daemonSetDesired(inv, w.Namespace, w.Name)
		}
		if pods < 2 {
			// Under two, nothing is shared. A DaemonSet whose controller has not written a count yet
			// reads as 0 here, and an unwritten count is unknown rather than many.
			continue
		}
		var shared []string
		for _, v := range w.PodSpec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			pvc := byKey[w.Namespace+"/"+v.PersistentVolumeClaim.ClaimName]
			if pvc == nil {
				// A CLAIM THIS READING DID NOT FIND HAS NO MODE TO READ. Whether it exists at all is
				// Sweep 2's question and the volume pair there is deferred; it is not answered here.
				continue
			}
			if !onlySingleNodeAccess(pvc.Spec.AccessModes) {
				continue
			}
			shared = append(shared, v.PersistentVolumeClaim.ClaimName)
		}
		if len(shared) == 0 {
			continue
		}
		sort.Strings(shared)

		count := fmt.Sprintf("%d replicas", pods)
		mechanism := fmt.Sprintf("spec.replicas = %d", pods)
		if w.Kind == "DaemonSet" {
			count = fmt.Sprintf("one pod on each of %d nodes", pods)
			mechanism = fmt.Sprintf("status.desiredNumberScheduled = %d, one pod per selected node", pods)
		}

		refs := []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}}
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s %s/%s: %s, and the pod template names %s that permit one node at a "+
				"time: %s", w.Kind, w.Namespace, w.Name, mechanism, nWord(len(shared), "claim", "claims"), strings.Join(shared, ", ")),
		}
		for _, name := range shared {
			pvc := byKey[w.Namespace+"/"+name]
			refs = append(refs, types.ResourceRef{
				Kind: "PersistentVolumeClaim", Namespace: w.Namespace, Name: name})
			evidence = append(evidence, fmt.Sprintf("PVC %s/%s: spec.accessModes = %s",
				w.Namespace, name, accessModesText(pvc.Spec.AccessModes)))
		}
		evidence = append(evidence, "where those pods are running now is not part of this claim: pods that "+
			"all landed on one node share the volume without difficulty, and this reading does not say "+
			"which arrangement is in front of it")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s/%s runs %s against a volume that permits one node",
				w.Kind, w.Namespace, w.Name, count),
			Description: fmt.Sprintf("%s %s/%s declares %s and its pod template names %s, whose "+
				"spec.accessModes permit attachment by a single node at a time. Both declarations are "+
				"ordinary on their own; together they mean every pod of this workload has to be on "+
				"whichever node currently holds the volume.",
				w.Kind, w.Namespace, w.Name, mechanism, strings.Join(shared, " and ")),
			WhyItMatters: "ReadWriteOnce is a property of the volume, not of the workload, so nothing " +
				"reconciles the two. It is also invisible while the replicas happen to share a node, and " +
				"becomes visible the first time the scheduler spreads them or a node is drained.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// onlySingleNodeAccess reports whether every mode on this claim is one that binds it to a single node.
//
// AN EMPTY LIST IS UNKNOWN, NEVER ReadWriteOnce — §2's discipline, and here it matters because a claim
// created before the field was defaulted, or read through a converting proxy, would otherwise be reported.
// ReadWriteOncePod is included: it is STRICTER than ReadWriteOnce, permitting one POD rather than one node.
func onlySingleNodeAccess(modes []corev1.PersistentVolumeAccessMode) bool {
	if len(modes) == 0 {
		return false
	}
	for _, m := range modes {
		if m != corev1.ReadWriteOnce && m != corev1.ReadWriteOncePod {
			return false
		}
	}
	return true
}

// daemonSetDesired returns the controller's own count of nodes it wants a pod on, or 0 when it has not
// written one. Zero is UNKNOWN here, and the caller treats it as "not several".
func daemonSetDesired(inv *collect.Inventory, ns, name string) int32 {
	for i := range inv.DaemonSets {
		d := &inv.DaemonSets[i]
		if d.Namespace == ns && d.Name == name {
			return d.Status.DesiredNumberScheduled
		}
	}
	return 0
}

func accessModesText(modes []corev1.PersistentVolumeAccessMode) string {
	if len(modes) == 0 {
		return "(none recorded)"
	}
	parts := make([]string, 0, len(modes))
	for _, m := range modes {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, ",")
}

// workloadKindToList maps a workload's Kind back to the collector step name it came from, so a rule can
// honour the structural denial property — no finding may name a resource of a kind this reading did not
// read — without every rule
// keeping its own copy of the mapping.
func workloadKindToList(kind string) string {
	switch kind {
	case "Deployment":
		return "deployments"
	case "StatefulSet":
		return "statefulsets"
	case "DaemonSet":
		return "daemonsets"
	}
	return ""
}

// ── Rule: an autoscaler allowed to go below what a budget requires ───────────────────────────────

// AutoscalerFloorBelowBudget reports an HPA whose minReplicas is at or below the minAvailable of a
// PodDisruptionBudget covering the same pods.
//
// THIS ONE IS INVISIBLE TO STATUS, WHICH IS THE ARGUMENT FOR IT. With the workload at ten replicas and a
// budget of three, status.disruptionsAllowed reads seven and PDBBlocksDrains is correctly silent: nothing
// is blocked right now. The contradiction only appears at the autoscaler's floor — a quiet Sunday, or the
// night before an upgrade — and by then whoever is draining the node is reading an error, not a report.
type AutoscalerFloorBelowBudget struct{}

func (AutoscalerFloorBelowBudget) ID() string      { return "k8s.reliability.autoscaler-floor-below-budget" }
func (AutoscalerFloorBelowBudget) Version() string { return "1.0.0" }

// RequiredKinds — all four are load-bearing. The workload kinds resolve the autoscaler's target to a set
// of pod labels, which is the only way to know whether the budget and the autoscaler are talking about the
// same pods.
func (AutoscalerFloorBelowBudget) RequiredKinds() []string {
	// `pods` is declared because B-143 made it load-bearing: it is what tells a budget covering exactly
	// one workload from a budget also covering a pod nobody owns. Over-declaration is free here, per
	// deps.go — an unread pod list makes the comparison over-cautious rather than wrong.
	return sortedKinds([]string{"deployments", "horizontalpodautoscalers", "pods",
		"poddisruptionbudgets", "statefulsets"})
}

func (r AutoscalerFloorBelowBudget) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "horizontalpodautoscalers") || !observed(inv, "poddisruptionbudgets") {
		return nil
	}
	all := workloads(inv, opts)

	var out []types.Finding
	for i := range inv.HPAs {
		hpa := &inv.HPAs[i]
		if !opts.IncludeSystem && isSystemNamespace(hpa.Namespace) {
			continue
		}
		ref := hpa.Spec.ScaleTargetRef
		if ref.Kind != "Deployment" && ref.Kind != "StatefulSet" {
			// An Argo Rollout or a KEDA ScaledObject is scalable and uncollected — the same exclusion
			// DanglingScaleTarget makes, for the same reason.
			continue
		}
		list := workloadKindToList(ref.Kind)
		if !observed(inv, list) {
			continue
		}
		var target *workload
		for j := range all {
			if all[j].Kind == ref.Kind && all[j].Namespace == hpa.Namespace && all[j].Name == ref.Name {
				target = &all[j]
				break
			}
		}
		if target == nil {
			// A target this reading did not find is DanglingScaleTarget's claim, not this one's.
			continue
		}
		// AN UNSET minReplicas DEFAULTS TO 1 AT THE API SERVER. Reading nil as "no floor" would miss the
		// tightest case there is.
		floor := int32(1)
		if hpa.Spec.MinReplicas != nil {
			floor = *hpa.Spec.MinReplicas
		}

		for k := range inv.PDBs {
			pdb := &inv.PDBs[k]
			if pdb.Namespace != hpa.Namespace {
				continue
			}
			// A maxUnavailable budget expresses a ceiling on disruption rather than a floor on
			// availability, so a replica floor cannot contradict it by arithmetic.
			if pdb.Spec.MinAvailable == nil || pdb.Spec.MaxUnavailable != nil {
				continue
			}
			// A PERCENTAGE SCALES WITH THE WORKLOAD and therefore cannot contradict a floor: at two
			// replicas 50% demands one, at ten it demands five. Resolving the percentage against the floor
			// and comparing would fire on every proportional budget in existence.
			if pdb.Spec.MinAvailable.Type != intstr.Int {
				continue
			}
			required := pdb.Spec.MinAvailable.IntValue()
			sel := pdbSelector(pdb)
			if sel == nil || !sel.Matches(labels.Set(target.PodLabels)) {
				continue
			}
			// B-098's LESSON, ENFORCED: the denominator of a budget is the SET of pods it selects. If this
			// budget also covers another workload, the floor at which it binds is the sum of their floors
			// and only one of them may have an autoscaler. Silence beats arithmetic over half the inputs.
			if covered := workloadsMatching(all, pdb.Namespace, sel); len(covered) != 1 {
				continue
			}
			// B-143, ONE LEVEL BELOW B-098: the denominator is the set of PODS the selector matches, and a
			// workload is only the usual way to produce them. A pod carrying these labels with no
			// controller at all still counts toward minAvailable at the autoscaler's floor, so the budget
			// may be satisfiable and this rule has no way to say by how much.
			if strays, known := straysUnder(inv, pdb.Namespace, sel, target); known && strays > 0 {
				continue
			}
			if int(floor) > required {
				continue
			}

			out = append(out, types.Finding{
				ID:          findingID(r.ID(), "HorizontalPodAutoscaler", hpa.Namespace, hpa.Name+"/"+pdb.Name),
				IDBasis:     &types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: hpa.Namespace, Name: hpa.Name + "/" + pdb.Name},
				RuleID:      r.ID(),
				RuleVersion: r.Version(),
				Title: fmt.Sprintf("HPA %s/%s may scale %s to %d while PDB %s requires %d available",
					hpa.Namespace, hpa.Name, target.Name, floor, pdb.Name, required),
				Description: fmt.Sprintf("HorizontalPodAutoscaler %s/%s sets minReplicas = %d for %s %s/%s, "+
					"and PodDisruptionBudget %s/%s requires minAvailable = %d over the same pods. At the "+
					"autoscaler's floor the budget permits no voluntary disruption at all, because the pods "+
					"it requires to stay available are every pod there is. Right now the workload may be "+
					"well above that floor, and this reading is about the floor rather than about now.",
					hpa.Namespace, hpa.Name, floor, target.Kind, target.Namespace, target.Name,
					pdb.Namespace, pdb.Name, required),
				WhyItMatters: "A disruption budget and an autoscaler are usually written by different " +
					"people at different times, and neither object refers to the other. The arithmetic " +
					"between them only becomes visible when traffic is low enough for the autoscaler to " +
					"reach its floor — which is also when maintenance tends to be scheduled.",
				Evidence: []string{
					snapshotNote(inv),
					fmt.Sprintf("HPA %s/%s: spec.minReplicas = %d, spec.scaleTargetRef = %s/%s",
						hpa.Namespace, hpa.Name, floor, ref.Kind, ref.Name),
					fmt.Sprintf("PDB %s/%s: spec.minAvailable = %d, selector as written: %s",
						pdb.Namespace, pdb.Name, required, selectorText(pdb.Spec.Selector)),
					fmt.Sprintf("that selector matches exactly one workload in this reading, %s %s/%s, so "+
						"the pods it counts and the pods the autoscaler sizes are the same set",
						target.Kind, target.Namespace, target.Name),
					straysNote(inv),
					"whether the workload has ever been at its floor is not readable here; the two " +
						"declarations are what this reports",
				},
				Severity: types.SeverityMedium,
				Category: types.CategoryReliability,
				AffectedResources: []types.ResourceRef{
					{Kind: "HorizontalPodAutoscaler", Namespace: hpa.Namespace, Name: hpa.Name},
					{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
					{Kind: target.Kind, Namespace: target.Namespace, Name: target.Name},
				},
				EstimatedEffort: types.EffortLow,
				Confidence:      1.0,
				Provenance:      provenance(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// straysUnder counts pods the selector matches that this workload does not own. `known` is false when the
// pod list was not read, in which case the caller proceeds and says so rather than falling silent — a pod
// under a budget with no controller is rare, and withholding the whole claim over an unread list would
// trade a rare false positive for a common false negative.
func straysUnder(inv *collect.Inventory, ns string, sel labels.Selector, target *workload) (int, bool) {
	if !observed(inv, "pods") {
		return 0, false
	}
	n := 0
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Namespace != ns || !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		if labels.Set(target.PodLabels) != nil && sel.Matches(labels.Set(target.PodLabels)) {
			// Owned by the target if its controller chain leads there; a pod with no controller never is.
			if controllerRef(*p) != nil {
				continue
			}
		}
		n++
	}
	return n, true
}

func straysNote(inv *collect.Inventory) string {
	if observed(inv, "pods") {
		return "no pod outside this workload carries the budget's labels, so the pods it counts are the " +
			"pods the autoscaler sizes"
	}
	return "the pod list was not read in this run, so this comparison comes from the workload " +
		"declarations alone; a pod carrying these labels with no controller would also count toward the budget"
}

// workloadsMatching returns every workload in ns whose pod labels the selector matches. It is the
// denominator B-098 was about, computed once so the rule can refuse when it is not one.
func workloadsMatching(all []workload, ns string, sel labels.Selector) []workload {
	var out []workload
	for _, w := range all {
		if w.Namespace != ns {
			continue
		}
		if sel.Matches(labels.Set(w.PodLabels)) {
			out = append(out, w)
		}
	}
	return out
}
