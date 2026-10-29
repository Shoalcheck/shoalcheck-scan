package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (ArgoSync) ID() string { return "stack.argocd.sync" }
func (ArgoSync) FindingIDs() []string {
	return []string{"stack.argocd.degraded", "stack.argocd.outofsync"}
}
func (ArgoSync) Version() string                             { return "1.0.0" }
func (ArgoSync) RequiredGVRs() []schema.GroupVersionResource { return argoGVRs() }

// Analyze reads Argo Application status. Degraded is an OBSERVED failure
// (headline, High). OutOfSync drift can be intentional, so it is phrased
// conditionally at lower severity/confidence.
func (a ArgoSync) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "argoproj.io"
		resource = "applications"
	)
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, app := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(app.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(app.Object, "metadata", "name")
		health, _, _ := unstructured.NestedString(app.Object, "status", "health", "status")
		sync, _, _ := unstructured.NestedString(app.Object, "status", "sync", "status")

		switch {
		case health == "Degraded":
			out = append(out, types.Finding{
				ID:           findingID("stack.argocd.degraded", "Application", ns, name),
				IDBasis:      &types.ResourceRef{Kind: "Application", Namespace: ns, Name: name},
				RuleID:       "stack.argocd.degraded",
				RuleVersion:  a.Version(),
				Title:        fmt.Sprintf("Argo CD Application %s/%s is Degraded", ns, name),
				Description:  fmt.Sprintf("Argo Application %s/%s reports status.health.status=Degraded — Argo observes the managed resources as unhealthy.", ns, name),
				WhyItMatters: "A Degraded Application is an observed failure of the GitOps-managed workload, not a drift preference — the desired state is not running healthily.",
				Evidence: []string{
					fmt.Sprintf("%s/%s: status.health.status=Degraded, status.sync.status=%s", ns, name, sync),
				},
				Severity:          types.SeverityHigh,
				Category:          types.CategoryReliability,
				AffectedResources: []types.ResourceRef{{Kind: "Application", Namespace: ns, Name: name}},
				EstimatedEffort:   types.EffortMedium,
				Confidence:        0.85,
				Provenance:        provenance(),
			})
		case sync == "OutOfSync":
			out = append(out, types.Finding{
				ID:           findingID("stack.argocd.outofsync", "Application", ns, name),
				IDBasis:      &types.ResourceRef{Kind: "Application", Namespace: ns, Name: name},
				RuleID:       "stack.argocd.outofsync",
				RuleVersion:  a.Version(),
				Title:        fmt.Sprintf("Argo CD Application %s/%s is OutOfSync", ns, name),
				Description:  fmt.Sprintf("Argo Application %s/%s reports status.sync.status=OutOfSync — the live state differs from Git. This may be intentional (a manual hotfix, a paused rollout); confirm before treating it as drift to reconcile.", ns, name),
				WhyItMatters: "OutOfSync means live config has drifted from the Git source of truth; whether that is a problem depends on intent, so it is reported conditionally.",
				Evidence: []string{
					fmt.Sprintf("%s/%s: status.sync.status=OutOfSync, status.health.status=%s", ns, name, health),
				},
				Severity:          types.SeverityLow,
				Category:          types.CategoryConfig,
				AffectedResources: []types.ResourceRef{{Kind: "Application", Namespace: ns, Name: name}},
				EstimatedEffort:   types.EffortLow,
				Confidence:        0.6,
				Provenance:        provenance(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
