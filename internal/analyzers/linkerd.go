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
const ruleLinkerdOpaquePort = "stack.linkerd.opaque-port"

func (LinkerdMTLS) ID() string                                  { return "stack.linkerd.mtls" }
func (LinkerdMTLS) FindingIDs() []string                        { return []string{"stack.linkerd.opaque-port"} }
func (LinkerdMTLS) Version() string                             { return "1.0.0" }
func (LinkerdMTLS) RequiredGVRs() []schema.GroupVersionResource { return linkerdGVRs() }

// Analyze flags Linkerd Server objects whose spec.proxyProtocol is EXPLICITLY
// "opaque". An opaque port forwards raw bytes, so the proxy cannot apply its
// protocol-aware (L7) routing, retries, per-route policy, or HTTP metrics — but
// it is NOT an mTLS gap: Linkerd still mTLS-encrypts opaque traffic between
// meshed pods. An unset/default proxyProtocol is automatic protocol detection
// (the normal meshed state), so it is NOT flagged. This is therefore a
// config/observability note, not a security exposure: phrased conditionally at
// confidence 0.6 and never Critical.
func (a LinkerdMTLS) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "policy.linkerd.io"
		resource = "servers"
	)
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, s := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(s.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(s.Object, "metadata", "name")
		proto, found, _ := unstructured.NestedString(s.Object, "spec", "proxyProtocol")
		// ONLY an explicit "opaque" is flagged. Unset/default = automatic protocol
		// detection (the normal meshed state); any explicit non-opaque value
		// (HTTP/1, HTTP/2, gRPC, TLS) is protocol-aware. Neither is a gap, and
		// neither affects mTLS.
		if !found || proto != "opaque" {
			continue
		}
		out = append(out, types.Finding{
			ID:           findingID(ruleLinkerdOpaquePort, "Server", ns, name),
			IDBasis:      &types.ResourceRef{Kind: "Server", Namespace: ns, Name: name},
			RuleID:       ruleLinkerdOpaquePort,
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("Linkerd Server %s/%s is opaque (proxyProtocol=opaque) — no L7 visibility for that port", ns, name),
			Description:  fmt.Sprintf("Linkerd Server %s/%s has spec.proxyProtocol=opaque, so the proxy forwards raw bytes for that port: no protocol-aware (L7) routing, retries, per-route policy, or HTTP metrics. mTLS between meshed pods is unaffected — opaque traffic is still encrypted. This is intended for genuinely non-HTTP protocols or during a rollout; confirm the port is meant to be opaque rather than a misconfiguration.", ns, name),
			WhyItMatters: "An opaque Server port loses the mesh's L7 features (route policy, retries, per-route metrics) for that port. It is NOT an mTLS exposure — opaque traffic between meshed pods is still encrypted — so this is an observability/configuration note, reported conditionally.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: spec.proxyProtocol=opaque", ns, name),
				"opaque is a legitimate choice for non-HTTP protocols or during Linkerd adoption — verify intent; mTLS between meshed pods is not affected",
			},
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "Server", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.6,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
