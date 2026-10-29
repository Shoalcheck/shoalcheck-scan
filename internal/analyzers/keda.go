package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (KEDAScaledObject) ID() string                                  { return "stack.keda.scaledobject" }
func (KEDAScaledObject) FindingIDs() []string                        { return []string{"stack.keda.not-ready"} }
func (KEDAScaledObject) Version() string                             { return "1.0.0" }
func (KEDAScaledObject) RequiredGVRs() []schema.GroupVersionResource { return kedaGVRs() }

// Analyze flags KEDA ScaledObjects whose Ready condition is False — KEDA could
// not wire the scaler (bad trigger auth, unreachable source), so the workload
// is not being autoscaled as declared.
func (a KEDAScaledObject) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "keda.sh"
		resource = "scaledobjects"
	)
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, o := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(o.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(o.Object, "metadata", "name")
		st, found := readyCondition(o.Object)
		if !found || st != "False" {
			continue
		}
		out = append(out, types.Finding{
			ID:           findingID("stack.keda.not-ready", "ScaledObject", ns, name),
			IDBasis:      &types.ResourceRef{Kind: "ScaledObject", Namespace: ns, Name: name},
			RuleID:       "stack.keda.not-ready",
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("KEDA ScaledObject %s/%s is not Ready", ns, name),
			Description:  fmt.Sprintf("KEDA ScaledObject %s/%s reports a Ready condition with status=False — KEDA could not establish the scaler (e.g. a trigger source is unreachable or its auth is invalid), so the target workload is not being event-autoscaled as declared.", ns, name),
			WhyItMatters: "A not-Ready ScaledObject means the workload's autoscaling is inactive: it will not scale to its event load, which can stall queues or starve throughput.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: status.conditions Ready=False", ns, name),
			},
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "ScaledObject", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.8,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
