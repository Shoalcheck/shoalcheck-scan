package rules

import (
	"fmt"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// AutoscalerBehaviour reports where a HorizontalPodAutoscaler spent the window (ENG-54): at its ceiling, where load
// past it is not met by more pods; never off its floor, where the floor and not the load sets the size; or changing
// size so often that each change is a pod started or stopped. From kube-state-metrics over the window.
//
// What it does not establish: whether the load was served. At the ceiling, the pods may have coped; at the floor,
// the floor may be deliberate (a quorum, a warm pool).
type AutoscalerBehaviour struct{}

func (AutoscalerBehaviour) ID() string              { return "k8s.observed.autoscaler-behaviour" }
func (AutoscalerBehaviour) Version() string         { return "1.0.0" }
func (AutoscalerBehaviour) RequiredKinds() []string { return []string{"horizontalpodautoscalers"} }
func (AutoscalerBehaviour) RequiresUsage() bool     { return true }

const (
	hpaCeilingShare = 0.2  // a fifth of the window at maxReplicas
	hpaFloorShare   = 0.99 // never measurably off minReplicas
	hpaChangesDay   = 48   // more than one change every half hour, on average
)

func (r AutoscalerBehaviour) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	if t == nil || len(t.Autoscalers) == 0 || !observed(inv, "horizontalpodautoscalers") {
		return nil
	}
	days := t.Window.Hours() / 24
	if t.CoverageKnown && t.Covered < t.Window {
		days = t.Covered.Hours() / 24
	}
	if days < 1 {
		return nil // under a day says nothing about a daily cycle
	}
	var out []types.Finding
	for i := range inv.HPAs {
		h := &inv.HPAs[i]
		if !opts.IncludeSystem && isSystemNamespace(h.Namespace) {
			continue
		}
		hist, ok := t.Autoscalers[h.Namespace+"/"+h.Name]
		if !ok {
			continue
		}
		min := int32(1)
		if h.Spec.MinReplicas != nil {
			min = *h.Spec.MinReplicas
		}
		target := h.Spec.ScaleTargetRef.Kind + " " + h.Namespace + "/" + h.Spec.ScaleTargetRef.Name
		var lines []string
		facts := []types.Fact{types.NewFact("hpa.at.max", hist.AtMaxShare), types.NewFact("hpa.at.min", hist.AtMinShare),
			types.NewFact("hpa.changes", hist.Changes)}
		sev := types.SeverityLow
		title := ""
		if hist.AtMaxShare >= hpaCeilingShare {
			sev = types.SeverityMedium
			title = fmt.Sprintf("%s spent %.0f%% of the window at its maximum of %d replicas", h.Name, 100*hist.AtMaxShare, h.Spec.MaxReplicas)
			lines = append(lines, fmt.Sprintf("at maxReplicas (%d) for %.0f%% of the window's 5-minute steps: while it is there, load past "+
				"it is met by the same pods, not more of them", h.Spec.MaxReplicas, 100*types.FactNum(facts, "hpa.at.max")))
		}
		if hist.AtMinShare >= hpaFloorShare && min > 1 {
			if title == "" {
				title = fmt.Sprintf("%s never left its minimum of %d replicas over the window", h.Name, min)
			}
			lines = append(lines, fmt.Sprintf("at minReplicas (%d) for %.0f%% of the window: the floor, not the load, set its size; "+
				"the floor may be deliberate — a quorum, a warm pool — and nothing here says it is not", min, 100*types.FactNum(facts, "hpa.at.min")))
		}
		if hist.Changes/days >= hpaChangesDay {
			if title == "" {
				title = fmt.Sprintf("%s changed its replica count %.0f times over the window", h.Name, hist.Changes)
			}
			lines = append(lines, fmt.Sprintf("the replica count changed %.0f times, about %.0f a day: each change starts or stops pods, and "+
				"a scale-down policy or a stabilisation window is what holds it still", types.FactNum(facts, "hpa.changes"), hist.Changes/days))
		}
		if len(lines) == 0 {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "HorizontalPodAutoscaler", h.Namespace, h.Name),
			IDBasis:     &types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       title,
			Description: fmt.Sprintf("kube-state-metrics shows where the autoscaler of %s spent the %s. Its declared range "+
				"is the same; how it used the range is what this adds.", target, t.WindowText()),
			WhyItMatters: "An autoscaler pinned at its ceiling has stopped autoscaling; one that never leaves its floor costs its " +
				"floor; one that changes size every few minutes restarts work it just started.",
			Evidence:          append([]string{snapshotNote(inv)}, lines...),
			Facts:             facts,
			Severity:          sev,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.9,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
