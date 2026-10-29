package rules

import (
	"fmt"
	"strings"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// PDBBlocksDrains flags PodDisruptionBudgets that permit zero voluntary
// disruptions — the inverse failure mode of single-replica-no-pdb: protection
// so tight it breaks operations. Two shapes: maxUnavailable=0, or
// minAvailable >= replicas of every pod the selector matches. Either way the
// eviction API can never approve a drain, so node maintenance, cluster
// upgrades, and autoscaler consolidation stall forever on these pods.
type PDBBlocksDrains struct{}

func (PDBBlocksDrains) ID() string      { return "k8s.reliability.pdb-blocks-drains" }
func (PDBBlocksDrains) Version() string { return "1.0.0" }

func (r PDBBlocksDrains) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	ws := workloads(inv, opts)
	for _, pdb := range inv.PDBs {
		if !opts.IncludeSystem && isSystemNamespace(pdb.Namespace) {
			continue
		}
		sel := pdbSelector(&pdb)
		if sel == nil {
			continue
		}
		var matched []workload
		for _, w := range ws {
			if w.Namespace == pdb.Namespace && sel.Matches(labels.Set(w.PodLabels)) {
				matched = append(matched, w)
			}
		}

		// Only flag when the PDB actually guards collected workloads — an
		// orphan PDB (selector matches nothing in inventory) cannot block a
		// drain of pods that don't exist, and "these pods" evidence would lie.
		if len(matched) == 0 {
			continue
		}

		var evidence []string
		if mu := pdb.Spec.MaxUnavailable; mu != nil && intOrStringIsZero(*mu) {
			evidence = append(evidence, fmt.Sprintf(
				"PDB %s/%s: maxUnavailable=%s — node drains stall forever on its %s",
				pdb.Namespace, pdb.Name, mu.String(), nWord(len(matched), "matched workload",

					// minAvailable IS RESOLVED AGAINST THE PDB'S OWN SCOPE, NOT ONE WORKLOAD'S spec.replicas.
					//
					// This loop used to run per matched workload and resolve minAvailable against that workload's
					// replicas. A PDB's scope is whatever its selector matches, and the eviction API's arithmetic is over
					// the whole set. Two 3-replica Deployments sharing a label under one minAvailable=5 gave 5 >= 3 twice
					// and emitted "zero disruption budget" twice — while the API saw 6 pods, kept 5, published
					// disruptionsAllowed=1, and let a drain through. Telling an operator that drains stall forever on a
					// cluster where they do not is an overclaim, which ranks above a crash here.
					//
					// status.disruptionsAllowed is not a better estimate of the answer; it IS the answer. It is what the
					// eviction API will act on, computed by the disruption controller over the same set. node_drain.go:343
					// already reads it — this file was the outlier reading spec, and the correct value was in the same
					// inventory the whole time.
					//
					// The spec value is still printed, because it is what the SRE has in their YAML and the finding has to
					// be findable from it. It is evidence, not the arithmetic.
					"matched workloads")))
		}

		if ma := pdb.Spec.MinAvailable; ma != nil && pdbStatusIsFresh(&pdb) {
			st := pdb.Status
			if st.DisruptionsAllowed == 0 && st.ExpectedPods > 0 {
				minStr := ma.String()
				resolved := ""
				if scaled, err := intstr.GetScaledValueFromIntOrPercent(ma, int(st.ExpectedPods), true); err == nil {
					if minStr != fmt.Sprintf("%d", scaled) {
						resolved = fmt.Sprintf(" (resolves to %d)", scaled)
					}
				}
				names := make([]string, 0, len(matched))
				for _, w := range matched {
					names = append(names, fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name))
				}
				evidence = append(evidence, fmt.Sprintf(
					"PDB %s/%s: minAvailable=%s%s over expectedPods=%d (currentHealthy=%d, desiredHealthy=%d) "+
						"— the eviction API reports disruptionsAllowed=0 across %s",
					pdb.Namespace, pdb.Name, minStr, resolved, st.ExpectedPods,
					st.CurrentHealthy, st.DesiredHealthy, strings.Join(names, ", ")))
			}
		}
		if len(evidence) == 0 {
			continue
		}

		affected := []types.ResourceRef{{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name}}
		for _, w := range matched {
			affected = append(affected, types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PodDisruptionBudget", pdb.Namespace, pdb.Name),
			IDBasis:     &types.ResourceRef{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("PodDisruptionBudget blocks node drains: %s/%s", pdb.Namespace, pdb.Name),
			Description: fmt.Sprintf(
				"PodDisruptionBudget %s/%s allows zero voluntary disruptions, so the eviction API can never approve a drain of its pods. Node maintenance, Kubernetes upgrades, and autoscaler consolidation all stall until someone force-deletes pods by hand. Allowing one pod of disruption restores drains at the cost of briefly running one replica short during maintenance — add a replica if that margin is too thin.",
				pdb.Namespace, pdb.Name),
			WhyItMatters:      "A disruption budget of zero turns routine node operations into paged incidents and silently blocks cluster upgrades.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium, // TODO(founder): severity policy
			Category:          types.CategoryReliability,
			AffectedResources: affected,
			EstimatedEffort:   types.EffortLow,
			RemediationCommand: fmt.Sprintf(
				`kubectl -n %s patch pdb %s --type merge -p '{"spec":{"maxUnavailable":1}}'`,
				pdb.Namespace, pdb.Name),
			Confidence: 1.0, // pure arithmetic on collected spec fields
			Provenance: provenance(),
		})
	}
	return out
}

// pdbSelector compiles a PDB's selector, mirroring pdbCovers' matching rules:
// nil, invalid, and empty selectors yield nil (treated as matching nothing —
// conservative on both rules' sides).
func pdbSelector(pdb *policyv1.PodDisruptionBudget) labels.Selector {
	if pdb.Spec.Selector == nil {
		return nil
	}
	sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil || sel.Empty() {
		return nil
	}
	return sel
}

// intOrStringIsZero reports whether v is the literal zero budget: int 0,
// "0", or "0%".
func intOrStringIsZero(v intstr.IntOrString) bool {
	if v.Type == intstr.Int {
		return v.IntVal == 0
	}
	return v.StrVal == "0" || v.StrVal == "0%"
}

// RequiredKinds — The budget IS the finding.
// See deps.go for what belongs in this list.
func (r PDBBlocksDrains) RequiredKinds() []string { return withWorkloads("poddisruptionbudgets") }

// pdbStatusIsFresh reports whether this PDB's status has been computed for the spec we are reading.
//
// THE DENIAL GUARD FOR A status FIELD. A PDB created seconds before the audit has an empty status, and an
// empty status is not "zero disruptions allowed" — it is "the disruption controller has not answered yet".
// Reading it as a zero would invent the strongest claim this rule makes out of a missing reading, which is
// the absence-versus-denial trap one level down: the object was collected, the answer was not.
//
// ObservedGeneration must have caught up to the object's Generation, or the status describes a spec that is
// no longer the one in front of us. Both are zero on a brand-new object, which the ExpectedPods check at the
// call site rejects.
func pdbStatusIsFresh(pdb *policyv1.PodDisruptionBudget) bool {
	return pdb.Status.ObservedGeneration >= pdb.Generation
}
