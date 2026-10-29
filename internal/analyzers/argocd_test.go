package analyzers

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func argoApp(ns, name, sync, health string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"status": map[string]interface{}{
			"sync":   map[string]interface{}{"status": sync},
			"health": map[string]interface{}{"status": health},
		},
	}}
}

func argoInv(apps ...unstructured.Unstructured) *collect.Inventory {
	gvr := schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: apps},
		Meta:         collect.Meta{Collected: []string{"cr:" + gvr.GroupResource().String()}},
	}
}

func TestArgoDegradedIsHeadline(t *testing.T) {
	fs := ArgoSync{}.Analyze(argoInv(argoApp("argocd", "payments", "Synced", "Degraded")))
	if len(fs) != 1 || fs[0].RuleID != "stack.argocd.degraded" {
		t.Fatalf("Degraded app must be one degraded finding, got %+v", fs)
	}
	if fs[0].Severity != types.SeverityHigh {
		t.Errorf("Degraded health severity = %q, want high (observed failure)", fs[0].Severity)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "Degraded") {
		t.Errorf("evidence must cite status.health.status: %v", fs[0].Evidence)
	}
}

func TestArgoOutOfSyncIsConditional(t *testing.T) {
	fs := ArgoSync{}.Analyze(argoInv(argoApp("argocd", "web", "OutOfSync", "Healthy")))
	if len(fs) != 1 || fs[0].RuleID != "stack.argocd.outofsync" {
		t.Fatalf("OutOfSync+Healthy must be one outofsync finding, got %+v", fs)
	}
	body := strings.ToLower(fs[0].Description + " " + fs[0].WhyItMatters)
	if !strings.Contains(body, "may be intentional") && !strings.Contains(body, "confirm") {
		t.Errorf("OutOfSync must be phrased conditionally (drift can be intentional): %q", fs[0].Description)
	}
	if fs[0].Severity == types.SeverityCritical {
		t.Errorf("OutOfSync must not be Critical: %+v", fs[0])
	}
}

func TestArgoHealthySyncedNoFinding(t *testing.T) {
	if fs := (ArgoSync{}).Analyze(argoInv(argoApp("argocd", "ok", "Synced", "Healthy"))); len(fs) != 0 {
		t.Errorf("Synced+Healthy app must produce no finding, got %+v", fs)
	}
}
