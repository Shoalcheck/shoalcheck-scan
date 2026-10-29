package analyzers

import (
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (GatewayAPI) ID() string                                  { return "stack.gateway.programmed" }
func (GatewayAPI) FindingIDs() []string                        { return []string{"stack.gateway.not-programmed"} }
func (GatewayAPI) Version() string                             { return "1.0.0" }
func (GatewayAPI) RequiredGVRs() []schema.GroupVersionResource { return gatewayGVRs() }

// Analyze flags Gateway API Gateways and HTTPRoutes whose Accepted or Programmed
// condition is False — the controller rejected or could not program the route,
// so traffic it should carry is not flowing. Gateways and HTTPRoutes may be
// cluster- or namespace-scoped per Phase-0 discovery; stackObjects is
// scope-agnostic so no branch is needed.
func (a GatewayAPI) Analyze(inv *collect.Inventory) []types.Finding {
	const group = "gateway.networking.k8s.io"

	var out []types.Finding
	out = append(out, a.notProgrammed(inv, group, "gateways", "Gateway")...)
	out = append(out, a.notProgrammed(inv, group, "httproutes", "HTTPRoute")...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a GatewayAPI) notProgrammed(inv *collect.Inventory, group, resource, kind string) []types.Finding {
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	var out []types.Finding
	for _, o := range stackObjects(inv, group, resource) {
		ns, _, _ := unstructured.NestedString(o.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(o.Object, "metadata", "name")
		// HTTPRoutes carry conditions under status.parents[].conditions; Gateways
		// under status.conditions and per-listener status.listeners[].conditions.
		// Scan all of them for an Accepted/Programmed=False so either shape is
		// covered without a typed branch.
		bad, cond := gatewayBadCondition(o.Object)
		if !bad {
			continue
		}
		out = append(out, types.Finding{
			ID:           findingID("stack.gateway.not-programmed", kind, ns, name),
			IDBasis:      &types.ResourceRef{Kind: kind, Namespace: ns, Name: name},
			RuleID:       "stack.gateway.not-programmed",
			RuleVersion:  a.Version(),
			Title:        fmt.Sprintf("Gateway API %s %s/%s has %s=False", kind, ns, name, cond),
			Description:  fmt.Sprintf("Gateway API %s %s/%s reports a %s condition with status=False — the controller did not accept or could not program it. If it is mid-reconcile this may clear; a persistent False means the route/listener is not carrying traffic as declared.", kind, ns, name, cond),
			WhyItMatters: "A Gateway/HTTPRoute that is not Accepted/Programmed is not routing the traffic it declares; confirm whether the controller is transiently reconciling or rejecting the spec (bad listener, missing TLS, unresolved backendRef).",
			Evidence: []string{
				fmt.Sprintf("%s/%s (%s): status condition %s=False", ns, name, kind, cond),
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

// gatewayBadCondition scans the well-known Gateway API condition locations for
// an "Accepted" or "Programmed" condition whose status is "False", returning the
// condition type that failed. It inspects status.conditions, status.listeners[]
// .conditions (Gateway), and status.parents[].conditions (HTTPRoute) — all via
// Nested* discipline so a JSON-decoded CR cannot panic the read.
func gatewayBadCondition(obj map[string]interface{}) (bad bool, condType string) {
	scan := func(conds []interface{}) (bool, string) {
		for _, ci := range conds {
			cm, ok := ci.(map[string]interface{})
			if !ok {
				continue
			}
			typ, _, _ := unstructured.NestedString(cm, "type")
			if typ != "Accepted" && typ != "Programmed" {
				continue
			}
			st, _, _ := unstructured.NestedString(cm, "status")
			if st == "False" {
				return true, typ
			}
		}
		return false, ""
	}

	if conds, ok, _ := unstructured.NestedSlice(obj, "status", "conditions"); ok {
		if b, t := scan(conds); b {
			return true, t
		}
	}
	if listeners, ok, _ := unstructured.NestedSlice(obj, "status", "listeners"); ok {
		for _, li := range listeners {
			lm, ok := li.(map[string]interface{})
			if !ok {
				continue
			}
			if conds, ok, _ := unstructured.NestedSlice(lm, "conditions"); ok {
				if b, t := scan(conds); b {
					return true, t
				}
			}
		}
	}
	if parents, ok, _ := unstructured.NestedSlice(obj, "status", "parents"); ok {
		for _, pi := range parents {
			pm, ok := pi.(map[string]interface{})
			if !ok {
				continue
			}
			if conds, ok, _ := unstructured.NestedSlice(pm, "conditions"); ok {
				if b, t := scan(conds); b {
					return true, t
				}
			}
		}
	}
	return false, ""
}
