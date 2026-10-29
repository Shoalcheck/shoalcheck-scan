package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// B-108: the finding ID hashed the ANALYZER's registration ID while the card printed this one, so a
// customer following the published recipe — findingID(ruleID, kind, ns, name) — recomputed a different
// hash and the re-derivation claim was falsifiable on every finding from this analyzer. One constant now,
// used for both, so the two cannot drift apart again.
const ruleIstioPermissiveMTLS = "stack.istio.permissive-mtls"

func (IstioMTLS) ID() string                                  { return "stack.istio.mtls" }
func (IstioMTLS) FindingIDs() []string                        { return []string{"stack.istio.permissive-mtls"} }
func (IstioMTLS) Version() string                             { return "1.0.0" }
func (IstioMTLS) RequiredGVRs() []schema.GroupVersionResource { return istioGVRs() }

// Analyze flags PeerAuthentication mtls.mode in {PERMISSIVE,DISABLE}. PERMISSIVE
// is a VALID mid-migration state, so it is phrased conditionally at confidence
// 0.6 and never Critical — declared/transitional, not an observed breach.
func (a IstioMTLS) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "security.istio.io"
		resource = "peerauthentications"
	)
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, pa := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(pa.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(pa.Object, "metadata", "name")
		mode, _, _ := unstructured.NestedString(pa.Object, "spec", "mtls", "mode")
		if mode != "PERMISSIVE" && mode != "DISABLE" {
			continue // STRICT or unset (mesh default) — no finding
		}
		out = append(out, types.Finding{
			ID:           findingID(ruleIstioPermissiveMTLS, "PeerAuthentication", ns, name),
			IDBasis:      &types.ResourceRef{Kind: "PeerAuthentication", Namespace: ns, Name: name},
			RuleID:       ruleIstioPermissiveMTLS,
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("Istio PeerAuthentication %s/%s allows non-mTLS traffic (mode=%s)", ns, name, mode),
			Description:  fmt.Sprintf("PeerAuthentication %s/%s sets spec.mtls.mode=%s, which accepts plaintext alongside mTLS. This is intended ONLY during an mTLS rollout — confirm this namespace is not mid-migration before treating it as steady-state.", ns, name, mode),
			WhyItMatters: "PERMISSIVE/DISABLE mTLS lets unauthenticated plaintext into the mesh; if the migration is complete, it is a real exposure — if it is mid-rollout, it is expected. We cannot tell which from the object alone.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: spec.mtls.mode=%s", ns, name, mode),
				"PERMISSIVE/DISABLE is a legitimate transitional state during mTLS adoption — verify intent",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: "PeerAuthentication", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.6, // transitional/declared — conditional, not a definite breach
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
