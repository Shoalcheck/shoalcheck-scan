package analyzers

import (
	"fmt"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (HPASanity) ID() string { return "stack.hpa.sanity" }
func (HPASanity) FindingIDs() []string {
	return []string{"stack.hpa.no-headroom", "stack.hpa.pinned-at-max"}
}
func (HPASanity) Version() string                             { return "1.1.0" }
func (HPASanity) RequiredGVRs() []schema.GroupVersionResource { return nil } // judges inv.HPAs; no CRD

// Analyze judges the autoscaling/v2 HPAs Phase-0/collect.go already collected
// (inv.HPAs) but which no rule scores today. Every finding is an arithmetic
// fact about collected spec/status — confidence 0.85, never Critical.
func (a HPASanity) Analyze(inv *collect.Inventory) []types.Finding {
	var out []types.Finding
	for _, h := range inv.HPAs {
		ns, name := h.Namespace, h.Name
		min := int32(1)
		if h.Spec.MinReplicas != nil {
			min = *h.Spec.MinReplicas
		}
		max := h.Spec.MaxReplicas
		cur := h.Status.CurrentReplicas

		switch {
		case min == max:
			out = append(out, a.finding(
				"stack.hpa.no-headroom", ns, name,
				fmt.Sprintf("HorizontalPodAutoscaler %s/%s has minReplicas==maxReplicas (%d) — it cannot scale", ns, name, min),
				"An HPA whose min equals max never adds or removes replicas: it is autoscaling in name only, so load spikes have no headroom and the HPA object is misleading.",
				[]string{fmt.Sprintf("%s/%s: minReplicas=%d maxReplicas=%d (equal — no scaling range)", ns, name, min, max)},
			))
		case max == 1:
			out = append(out, a.finding(
				"stack.hpa.no-headroom", ns, name,
				fmt.Sprintf("HorizontalPodAutoscaler %s/%s caps at maxReplicas=1 — no scale-out possible", ns, name),
				"With maxReplicas=1 the HPA can never scale out under load; this is almost always a misconfiguration of an autoscaled workload.",
				[]string{fmt.Sprintf("%s/%s: maxReplicas=1 (single-replica ceiling)", ns, name)},
			))
		// ONE FACT, ONE FINDING. `k8s.reliability.hpa-pinned-at-max` in internal/rules makes this claim
		// whenever the autoscaler also published ScalingLimited=True — its own statement that it wanted a
		// count it may not reach — and that is strictly the stronger evidence. Two registries that cannot
		// see each other both fired on such an HPA, so one reading printed the same fact about the same
		// object twice; see internal/pipeline/hpa_duplicate_claim_test.go, which is the only place that
		// imports both and could catch it.
		//
		// WHAT IS LEFT HERE IS NOT A LEFTOVER. Without a metrics source the HPA controller never writes the
		// condition at all, so on a cluster with no metrics-server the registry rule is structurally silent
		// and the arithmetic is the only thing anyone can be told. That case is this one.
		case cur == max && max > 1 && !scalingLimited(&h):
			out = append(out, a.finding(
				"stack.hpa.pinned-at-max", ns, name,
				fmt.Sprintf("HorizontalPodAutoscaler %s/%s is pinned at maxReplicas (%d)", ns, name, max),
				"currentReplicas equals maxReplicas: the workload is at its scaling ceiling. The autoscaler published no ScalingLimited condition, so this is the arithmetic on its own numbers and not its own report about itself.",
				[]string{
					fmt.Sprintf("%s/%s: currentReplicas=%d == maxReplicas=%d", ns, name, cur, max),
					"status.conditions carries no ScalingLimited=True — commonly because no metrics source is installed, in which case the HPA controller never writes it",
				},
			))
		}
	}
	return out
}

// scalingLimited reports whether the autoscaler itself published ScalingLimited=True.
//
// READ THE SAME WAY internal/rules/silent_failures.go READS IT — type ScalingLimited, status True — because
// the two must agree about which HPAs belong to which claim. A copy is unavoidable: this package does not
// import internal/rules, and pulling in a rule registry to read one condition would be the larger wrong.
func scalingLimited(h *autoscalingv2.HorizontalPodAutoscaler) bool {
	for i := range h.Status.Conditions {
		c := &h.Status.Conditions[i]
		if c.Type == autoscalingv2.ScalingLimited && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (a HPASanity) finding(ruleID, ns, name, title, why string, evidence []string) types.Finding {
	return types.Finding{
		ID:                findingID(ruleID, "HorizontalPodAutoscaler", ns, name),
		IDBasis:           &types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: ns, Name: name},
		RuleID:            ruleID,
		RuleVersion:       a.Version(),
		Title:             title,
		Description:       title + ".",
		WhyItMatters:      why,
		Evidence:          evidence,
		Severity:          types.SeverityMedium,
		Category:          types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "HorizontalPodAutoscaler", Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        0.85, // arithmetic facts on collected data
		Provenance:        provenance(),
	}
}

// RequiredCoreKinds — this analyzer declares no CRD; its findings rest entirely on the core HPA list, so
// without this declaration they would appear to rest on nothing at all.
func (HPASanity) RequiredCoreKinds() []string { return []string{"horizontalpodautoscalers"} }
