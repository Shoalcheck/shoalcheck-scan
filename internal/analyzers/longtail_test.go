package analyzers

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// readyObj builds an unstructured CR with a status.conditions Ready entry.
func readyObj(apiVersion, kind, ns, name, readyStatus string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"status": map[string]interface{}{
			"conditions": []interface{}{
				map[string]interface{}{"type": "Ready", "status": readyStatus},
			},
		},
	}}
}

func invWith(gvr schema.GroupVersionResource, objs ...unstructured.Unstructured) *collect.Inventory {
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: objs},
		Meta:         collect.Meta{Collected: []string{"cr:" + gvr.GroupResource().String()}},
	}
}

// --- Cilium counts ---------------------------------------------------------

func cnpObjA(ns, name string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
	}}
}

func TestCiliumPolicyCounts(t *testing.T) {
	g := schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
	inv := invWith(g, cnpObjA("app", "deny-all"))
	perNS, cw, ok := CiliumPolicyCounts(inv)
	if !ok {
		t.Fatal("CiliumPolicyCounts ok=false when the CRD was present+collected")
	}
	if perNS["app"] != 1 {
		t.Errorf("perNS[app] = %d, want 1", perNS["app"])
	}
	if cw != 0 {
		t.Errorf("clusterWide = %d, want 0", cw)
	}
	// Absent GVR ⇒ ok=false (netpol keeps its 0.45 fallback).
	if _, _, ok := CiliumPolicyCounts(&collect.Inventory{}); ok {
		t.Error("CiliumPolicyCounts must return ok=false when the Cilium GVR is absent")
	}
	// Cilium analyzer itself emits NO findings (counts feed netpol.go).
	if fs := (CiliumPolicy{}).Analyze(inv); len(fs) != 0 {
		t.Errorf("CiliumPolicy.Analyze must emit no findings, got %+v", fs)
	}
}

func TestCalicoPolicyCounts(t *testing.T) {
	g := schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}
	np := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "projectcalico.org/v3", "kind": "NetworkPolicy",
		"metadata": map[string]interface{}{"namespace": "app", "name": "deny"},
	}}
	perNS, _, ok := CalicoPolicyCounts(invWith(g, np))
	if !ok || perNS["app"] != 1 {
		t.Fatalf("CalicoPolicyCounts ok=%v perNS=%v", ok, perNS)
	}
	if _, _, ok := CalicoPolicyCounts(&collect.Inventory{}); ok {
		t.Error("CalicoPolicyCounts must return ok=false when the Calico GVR is absent")
	}
}

// --- Linkerd ---------------------------------------------------------------

func linkerdServer(ns, name string, proto interface{}) unstructured.Unstructured {
	spec := map[string]interface{}{}
	if proto != nil {
		spec["proxyProtocol"] = proto
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "policy.linkerd.io/v1beta1", "kind": "Server",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     spec,
	}}
}

func TestLinkerdOpaqueIsConditional(t *testing.T) {
	g := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"}
	fs := LinkerdMTLS{}.Analyze(invWith(g, linkerdServer("prod", "web", "opaque")))
	if len(fs) != 1 || fs[0].RuleID != "stack.linkerd.opaque-port" {
		t.Fatalf("explicit-opaque Server must yield one conditional finding, got %+v", fs)
	}
	if fs[0].Severity == types.SeverityCritical {
		t.Errorf("opaque is a valid choice — must not be Critical: %+v", fs[0])
	}
	if fs[0].Confidence > 0.65 {
		t.Errorf("confidence = %v, want ~0.6", fs[0].Confidence)
	}
	// Honesty: opaque is NOT an mTLS exposure (Linkerd still encrypts opaque
	// traffic between meshed pods), so it must NOT be framed as an mTLS/security
	// finding. It is a config/observability note about lost L7 visibility.
	if fs[0].Category == types.CategorySecurity {
		t.Errorf("opaque must NOT be a Security finding (mTLS is unaffected): %+v", fs[0])
	}
	body := strings.ToLower(fs[0].Title + " " + fs[0].Description + " " + fs[0].WhyItMatters)
	if !strings.Contains(body, "l7") && !strings.Contains(body, "visibility") && !strings.Contains(body, "metrics") {
		t.Errorf("opaque finding must be framed around lost L7/observability, got: %q", fs[0].Description)
	}
	if !strings.Contains(body, "encrypted") && !strings.Contains(body, "not affect") && !strings.Contains(body, "unaffected") {
		t.Errorf("opaque finding must state mTLS is unaffected, got: %q", fs[0].Description)
	}
}

func TestLinkerdHTTPNoFinding(t *testing.T) {
	g := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"}
	if fs := (LinkerdMTLS{}).Analyze(invWith(g, linkerdServer("prod", "web", "HTTP/2"))); len(fs) != 0 {
		t.Errorf("an explicit meshed protocol must produce no finding, got %+v", fs)
	}
}

// TestLinkerdUnsetProxyProtocolNoFinding pins the honesty fix: an unset/default
// proxyProtocol is automatic protocol detection — the NORMAL meshed state — and
// must NOT be flagged. The old rule treated unset as "opaque" and emitted a
// false Security finding on every default Server.
func TestLinkerdUnsetProxyProtocolNoFinding(t *testing.T) {
	g := schema.GroupVersionResource{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"}
	if fs := (LinkerdMTLS{}).Analyze(invWith(g, linkerdServer("prod", "web", nil))); len(fs) != 0 {
		t.Errorf("unset/default proxyProtocol is automatic detection (normal) — must produce no finding, got %+v", fs)
	}
}

// --- Flux ------------------------------------------------------------------

func TestFluxHelmReleaseNotReady(t *testing.T) {
	g := schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}
	fs := FluxSync{}.Analyze(invWith(g, readyObj("helm.toolkit.fluxcd.io/v2", "HelmRelease", "apps", "web", "False")))
	if len(fs) != 1 || fs[0].RuleID != "stack.flux.not-ready" {
		t.Fatalf("Ready=False HelmRelease must yield one not-ready finding, got %+v", fs)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("Flux not-ready severity = %q, want high", fs[0].Severity)
	}
}

func TestFluxReadyNoFinding(t *testing.T) {
	g := schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	if fs := (FluxSync{}).Analyze(invWith(g, readyObj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "apps", "infra", "True"))); len(fs) != 0 {
		t.Errorf("Ready=True Kustomization must produce no finding, got %+v", fs)
	}
}

// --- KEDA ------------------------------------------------------------------

func TestKEDAScaledObjectNotReady(t *testing.T) {
	g := schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	fs := KEDAScaledObject{}.Analyze(invWith(g, readyObj("keda.sh/v1alpha1", "ScaledObject", "apps", "consumer", "False")))
	if len(fs) != 1 || fs[0].RuleID != "stack.keda.not-ready" {
		t.Fatalf("Ready=False ScaledObject must yield one not-ready finding, got %+v", fs)
	}
}

func TestKEDAReadyNoFinding(t *testing.T) {
	g := schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	if fs := (KEDAScaledObject{}).Analyze(invWith(g, readyObj("keda.sh/v1alpha1", "ScaledObject", "apps", "ok", "True"))); len(fs) != 0 {
		t.Errorf("Ready=True ScaledObject must produce no finding, got %+v", fs)
	}
}

// --- Strimzi ---------------------------------------------------------------

func TestStrimziKafkaNotReady(t *testing.T) {
	g := schema.GroupVersionResource{Group: "kafka.strimzi.io", Version: "v1beta2", Resource: "kafkas"}
	fs := StrimziKafka{}.Analyze(invWith(g, readyObj("kafka.strimzi.io/v1beta2", "Kafka", "data", "events", "False")))
	if len(fs) != 1 || fs[0].RuleID != "stack.strimzi.not-ready" {
		t.Fatalf("Ready=False Kafka must yield one not-ready finding, got %+v", fs)
	}
}

// --- Gateway API -----------------------------------------------------------

func gatewayObj(ns, name, condType, status string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"status": map[string]interface{}{
			"conditions": []interface{}{
				map[string]interface{}{"type": condType, "status": status},
			},
		},
	}}
}

func TestGatewayNotProgrammed(t *testing.T) {
	g := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	fs := GatewayAPI{}.Analyze(invWith(g, gatewayObj("infra", "public", "Programmed", "False")))
	if len(fs) != 1 || fs[0].RuleID != "stack.gateway.not-programmed" {
		t.Fatalf("Programmed=False Gateway must yield one finding, got %+v", fs)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "Programmed") {
		t.Errorf("evidence must cite the failed condition: %v", fs[0].Evidence)
	}
}

func TestGatewayAcceptedTrueNoFinding(t *testing.T) {
	g := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	gw := gatewayObj("infra", "public", "Accepted", "True")
	// add a Programmed=True so neither well-known condition is False
	conds, _, _ := unstructured.NestedSlice(gw.Object, "status", "conditions")
	conds = append(conds, map[string]interface{}{"type": "Programmed", "status": "True"})
	_ = unstructured.SetNestedSlice(gw.Object, conds, "status", "conditions")
	if fs := (GatewayAPI{}).Analyze(invWith(g, gw)); len(fs) != 0 {
		t.Errorf("Accepted+Programmed=True Gateway must produce no finding, got %+v", fs)
	}
}

// --- Denial guard across the long tail -------------------------------------

func TestLongTailDeniedListNoFabrication(t *testing.T) {
	g := schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}
	inv := &collect.Inventory{
		PresentGVRs:  collect.GVRSet{g: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{},
		Meta:         collect.Meta{Denied: []string{"cr:" + g.GroupResource().String() + ": forbidden"}},
	}
	if fs := (KEDAScaledObject{}).Analyze(inv); len(fs) != 0 {
		t.Errorf("denied ScaledObject list must not fabricate a finding, got %+v", fs)
	}
}
