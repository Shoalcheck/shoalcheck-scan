package rules

import (
	"fmt"
	"sort"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// hpa_burst.go — WHAT EVERY AUTOSCALER IS ALLOWED TO ASK FOR AT ONCE, AGAINST WHAT THE CLUSTER HAS.
//
// POP-602–605. Checked against the registry before writing: `hpa-pinned-at-max` fires only when ONE
// autoscaler's status.currentReplicas equals its own maxReplicas AND it carries a ScalingLimited condition —
// one HPA's present state. This is arithmetic over EVERY autoscaler's ceiling against cluster allocatable,
// which is a claim about the cluster's capacity. Different subject, so a new rule rather than a branch.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS DOES NOT SAY, AND THE LIST IS LONG BECAUSE THE ARITHMETIC IS SIMPLE AND THE WORLD IS NOT
//
//	NOT THAT IT WILL HAPPEN. Every HPA reaching maxReplicas simultaneously is the worst case, not a
//	forecast. Whether these workloads' load is correlated is not in the snapshot.
//
//	NOT THAT PODS WOULD BE REFUSED. The cluster autoscaler may add nodes; this reading does not know
//	whether one is installed, what its ceiling is, or whether the cloud has capacity. So the claim is
//	about the CURRENT node set and says so.
//
//	NOT A DOLLAR. Pricing a hypothetical burst would be pricing something that has not happened, which
//	is the cost half B-5 refused.
//
//	IT IS SKIPPED ENTIRELY where the arithmetic would be built on a guess: an HPA whose target this
//	reading cannot resolve, or a workload whose containers request nothing, contributes an unknown rather
//	than a zero — and a single unknown makes the total a floor, which is stated.
type HPABurstExceedsAllocatable struct{}

func (HPABurstExceedsAllocatable) ID() string      { return "k8s.reliability.hpa-burst-exceeds-allocatable" }
func (HPABurstExceedsAllocatable) Version() string { return "1.0.0" }

func (HPABurstExceedsAllocatable) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "horizontalpodautoscalers", "nodes", "pods", "statefulsets"})
}

func (r HPABurstExceedsAllocatable) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "horizontalpodautoscalers") || !observed(inv, "nodes") || !observed(inv, "pods") {
		return nil
	}
	all := workloads(inv, opts)

	var (
		burstCPU, burstMem int64
		lines              []string
		unknown            int
		hpas               []types.ResourceRef
	)
	for i := range inv.HPAs {
		h := &inv.HPAs[i]
		if !opts.IncludeSystem && isSystemNamespace(h.Namespace) {
			continue
		}
		ref := h.Spec.ScaleTargetRef
		if ref.Kind != "Deployment" && ref.Kind != "StatefulSet" {
			unknown++
			continue
		}
		var target *workload
		for j := range all {
			if all[j].Kind == ref.Kind && all[j].Namespace == h.Namespace && all[j].Name == ref.Name {
				target = &all[j]
				break
			}
		}
		if target == nil {
			unknown++
			continue
		}
		cpu, mem := podRequestSum(target.PodSpec)
		if cpu == 0 && mem == 0 {
			// A workload requesting nothing contributes an UNKNOWN, never a zero: it will still occupy a
			// node, and counting it as free capacity would understate the burst.
			unknown++
			continue
		}
		headroom := int64(h.Spec.MaxReplicas) - int64(currentReplicasOf(h))
		if headroom <= 0 {
			continue
		}
		burstCPU += cpu * headroom
		burstMem += mem * headroom
		hpas = append(hpas, types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name})
		lines = append(lines, fmt.Sprintf(
			"HPA %s/%s: %s allowed (max %d, currently %d) of %s %s/%s, which requests "+
				"%dm CPU and %d MiB each",
			h.Namespace, h.Name, nWord(headroom, "more replica", "more replicas"), h.Spec.MaxReplicas, currentReplicasOf(h),
			target.Kind, target.Namespace, target.Name, cpu, mem/(1024*1024)))
	}
	if len(lines) == 0 {
		return nil
	}

	// FREE ALLOCATABLE IS WHAT IS LEFT AFTER WHAT IS ALREADY REQUESTED — not total capacity. Comparing a
	// burst against total allocatable would ignore everything already running and overstate the headroom.
	var allocCPU, allocMem, usedCPU, usedMem int64
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		allocCPU += n.Status.Allocatable.Cpu().MilliValue()
		allocMem += n.Status.Allocatable.Memory().Value()
	}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		c, m := podRequestSum(p.Spec)
		usedCPU += c
		usedMem += m
	}
	freeCPU := allocCPU - usedCPU
	freeMem := allocMem - usedMem
	if burstCPU <= freeCPU && burstMem <= freeMem {
		return nil
	}

	sort.Strings(lines)
	evidence := append([]string{
		snapshotNote(inv),
		fmt.Sprintf("if every autoscaler reached its maxReplicas at once, the additional pods would "+
			"request %dm CPU and %d MiB", burstCPU, burstMem/(1024*1024)),
		fmt.Sprintf("the current node set has %dm CPU and %d MiB allocatable, of which %dm and %d MiB "+
			"are already requested, leaving %dm and %d MiB",
			allocCPU, allocMem/(1024*1024), usedCPU, usedMem/(1024*1024), freeCPU, freeMem/(1024*1024)),
	}, lines...)
	if unknown > 0 {
		evidence = append(evidence, fmt.Sprintf("%s were EXCLUDED from the total because "+
			"their target could not be resolved or its containers request nothing — so the burst figure "+
			"above is a floor rather than a total", nWord(unknown, "autoscaler", "autoscalers")))
	}
	evidence = append(evidence,
		"this is the worst case and not a forecast: whether these workloads' load is correlated is not "+
			"in this reading",
		"whether a cluster autoscaler would add nodes, what its ceiling is, and whether the cloud has "+
			"capacity are all outside this reading — the comparison is against the CURRENT node set")

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "hpa-burst"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "hpa-burst"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("Autoscalers may request %dm CPU more than the current nodes have free",
			burstCPU-freeCPU),
		Description: fmt.Sprintf("The %s counted here are together allowed to add pods "+
			"requesting %dm CPU and %d MiB. The current node set has %dm and %d MiB unrequested. Reaching "+
			"every ceiling at once is the worst case rather than a prediction, and whether new nodes would "+
			"appear is outside this reading.", nWord(len(lines), "autoscaler", "autoscalers"), burstCPU, burstMem/(1024*1024), freeCPU, freeMem/(1024*1024)),
		WhyItMatters: "Each autoscaler's ceiling is chosen on its own and the sum is nobody's decision. " +
			"It is the number that decides what happens when several services get busy together, and it " +
			"appears in no manifest.",
		Evidence:          evidence,
		Severity:          types.SeverityMedium,
		Category:          types.CategoryReliability,
		AffectedResources: hpas,
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

func currentReplicasOf(h *autoscalingv2.HorizontalPodAutoscaler) int32 {
	if h.Status.CurrentReplicas > 0 {
		return h.Status.CurrentReplicas
	}
	if h.Spec.MinReplicas != nil {
		return *h.Spec.MinReplicas
	}
	return 1
}

// podRequestSum totals a pod template's container requests. Init containers are excluded: they run before
// the app containers and do not add to the steady-state footprint, which is what a burst is measured in.
func podRequestSum(spec corev1.PodSpec) (cpuMilli, memBytes int64) {
	for _, c := range spec.Containers {
		cpuMilli += c.Resources.Requests.Cpu().MilliValue()
		memBytes += c.Resources.Requests.Memory().Value()
	}
	return cpuMilli, memBytes
}
