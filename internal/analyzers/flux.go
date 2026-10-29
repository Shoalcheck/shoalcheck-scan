package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (FluxSync) ID() string                                  { return "stack.flux.sync" }
func (FluxSync) FindingIDs() []string                        { return []string{"stack.flux.not-ready"} }
func (FluxSync) Version() string                             { return "1.0.0" }
func (FluxSync) RequiredGVRs() []schema.GroupVersionResource { return fluxGVRs() }

// Analyze flags Flux Kustomization / HelmRelease objects whose Ready condition
// is False — the reconcile is not converging. A momentary not-ready can be
// mid-reconcile, so phrasing is conditional, but a persistent Ready=False is a
// real GitOps failure (High, confidence 0.8).
func (a FluxSync) Analyze(inv *collect.Inventory) []types.Finding {
	const group1 = "kustomize.toolkit.fluxcd.io"
	const group2 = "helm.toolkit.fluxcd.io"

	var out []types.Finding
	out = append(out, a.notReady(inv, group1, "kustomizations", "Kustomization")...)
	out = append(out, a.notReady(inv, group2, "helmreleases", "HelmRelease")...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a FluxSync) notReady(inv *collect.Inventory, group, resource, kind string) []types.Finding {
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, o := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(o.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(o.Object, "metadata", "name")
		st, found := readyCondition(o.Object)
		if !found || st != "False" {
			continue // Ready=True, or no Ready condition observed yet → no finding
		}
		out = append(out, types.Finding{
			ID:           findingID("stack.flux.not-ready", kind, ns, name),
			IDBasis:      &types.ResourceRef{Kind: kind, Namespace: ns, Name: name},
			RuleID:       "stack.flux.not-ready",
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("Flux %s %s/%s is not Ready", kind, ns, name),
			Description:  fmt.Sprintf("Flux %s %s/%s reports a Ready condition with status=False — the reconcile is not converging. If it is mid-reconcile this may clear shortly; a persistent Ready=False means the desired state from Git is not applied.", kind, ns, name),
			WhyItMatters: "A non-Ready Flux resource means the GitOps-managed config is not in the cluster as declared; confirm whether it is transiently reconciling or genuinely stuck on an apply/build error.",
			Evidence: []string{
				fmt.Sprintf("%s/%s (%s): status.conditions Ready=False", ns, name, kind),
			},
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: kind, Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.8,
			Provenance:        provenance(),
		})
	}
	return out
}
