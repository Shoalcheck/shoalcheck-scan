package analyzers

import (
	"strings"
	"testing"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func hpa(ns, name string, min *int32, max, current int32) autoscalingv2.HorizontalPodAutoscaler {
	return autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: min, MaxReplicas: max},
		Status:     autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: current},
	}
}

func i32(v int32) *int32 { return &v }

func TestHPAMinEqualsMax(t *testing.T) {
	inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa("app", "api", i32(3), 3, 3)}}
	fs := HPASanity{}.Analyze(inv)
	if len(fs) != 1 || fs[0].RuleID != "stack.hpa.no-headroom" {
		t.Fatalf("min==max HPA must be one no-headroom finding, got %+v", fs)
	}
	if fs[0].Confidence != 0.85 {
		t.Errorf("HPA arithmetic confidence = %v, want 0.85", fs[0].Confidence)
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("stack finding must carry no dollars, got %v", fs[0].DollarImpactMonthly)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "minReplicas=3") {
		t.Errorf("evidence must cite the observed min/max: %v", fs[0].Evidence)
	}
}

func TestHPAStuckAtMax(t *testing.T) {
	inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa("app", "web", i32(2), 5, 5)}}
	fs := HPASanity{}.Analyze(inv)
	if len(fs) != 1 || fs[0].RuleID != "stack.hpa.pinned-at-max" {
		t.Fatalf("currentReplicas==max must be one pinned-at-max finding, got %+v", fs)
	}
}

func TestHPAHealthyNoFinding(t *testing.T) {
	inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa("app", "ok", i32(2), 10, 4)}}
	if fs := (HPASanity{}).Analyze(inv); len(fs) != 0 {
		t.Errorf("healthy HPA must produce no finding, got %+v", fs)
	}
}

func TestHPASeverityIsNotCritical(t *testing.T) {
	inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa("app", "api", i32(3), 3, 3)}}
	for _, f := range (HPASanity{}).Analyze(inv) {
		if f.Severity == types.SeverityCritical {
			t.Errorf("HPA hygiene must not be Critical: %+v", f)
		}
	}
}
