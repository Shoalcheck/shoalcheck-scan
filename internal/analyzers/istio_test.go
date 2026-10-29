package analyzers

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func peerAuth(ns, name, mode string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "security.istio.io/v1",
		"kind":       "PeerAuthentication",
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"spec":       map[string]interface{}{"mtls": map[string]interface{}{"mode": mode}},
	}}
}

func istioInv(pas ...unstructured.Unstructured) *collect.Inventory {
	pa := schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}
	ap := schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}
	dr := schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"}
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{pa: struct{}{}, ap: struct{}{}, dr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{pa: pas},
		Meta: collect.Meta{Collected: []string{
			"cr:" + pa.GroupResource().String(),
			"cr:" + ap.GroupResource().String(),
			"cr:" + dr.GroupResource().String(),
		}},
	}
}

func TestIstioPermissiveIsConditional(t *testing.T) {
	fs := IstioMTLS{}.Analyze(istioInv(peerAuth("prod", "default", "PERMISSIVE")))
	if len(fs) != 1 {
		t.Fatalf("PERMISSIVE PeerAuthentication must yield one finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity == types.SeverityCritical {
		t.Errorf("PERMISSIVE is a valid mid-migration state — must not be Critical: %+v", f)
	}
	if f.Confidence > 0.65 {
		t.Errorf("PERMISSIVE confidence = %v, want ~0.6 (transitional, conditional)", f.Confidence)
	}
	body := strings.ToLower(f.Title + " " + f.Description + " " + f.WhyItMatters)
	if !strings.Contains(body, "migration") && !strings.Contains(body, "confirm") {
		t.Errorf("PERMISSIVE must be phrased conditionally (mid-migration / confirm): %q", f.Description)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "PERMISSIVE") {
		t.Errorf("evidence must cite the observed mode: %v", f.Evidence)
	}
}

func TestIstioStrictNoFinding(t *testing.T) {
	if fs := (IstioMTLS{}).Analyze(istioInv(peerAuth("prod", "default", "STRICT"))); len(fs) != 0 {
		t.Errorf("STRICT mTLS must produce no finding, got %+v", fs)
	}
}
