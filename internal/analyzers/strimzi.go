package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (StrimziKafka) ID() string                                  { return "stack.strimzi.kafka" }
func (StrimziKafka) FindingIDs() []string                        { return []string{"stack.strimzi.not-ready"} }
func (StrimziKafka) Version() string                             { return "1.0.0" }
func (StrimziKafka) RequiredGVRs() []schema.GroupVersionResource { return strimziGVRs() }

// Analyze flags Strimzi Kafka clusters whose Ready condition is False — the
// operator reports the Kafka cluster as not reconciled/healthy.
func (a StrimziKafka) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "kafka.strimzi.io"
		resource = "kafkas"
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
			ID:           findingID("stack.strimzi.not-ready", "Kafka", ns, name),
			IDBasis:      &types.ResourceRef{Kind: "Kafka", Namespace: ns, Name: name},
			RuleID:       "stack.strimzi.not-ready",
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("Strimzi Kafka %s/%s is not Ready", ns, name),
			Description:  fmt.Sprintf("Strimzi Kafka %s/%s reports a Ready condition with status=False — the Strimzi operator could not bring the Kafka cluster to a healthy reconciled state (e.g. a broker is down or a config change failed to roll out).", ns, name),
			WhyItMatters: "A not-Ready Kafka cluster means the message backbone is degraded or unavailable; every producer and consumer depending on it is at risk of stalling or losing throughput.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: status.conditions Ready=False", ns, name),
			},
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Kafka", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortHigh,
			Confidence:        0.8,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
