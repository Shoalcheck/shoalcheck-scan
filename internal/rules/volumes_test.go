package rules

import (
	"strings"
	"testing"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
)

func week7() *prom.Temporal {
	return &prom.Temporal{Window: 7 * 24 * time.Hour, Covered: 7 * 24 * time.Hour, CoverageKnown: true}
}

// A VOLUME THAT FILLS WITHIN A MONTH IS REPORTED WITH ITS RATE; A LARGE ONE THAT NEVER HELD A FIFTH OF ITSELF IS A
// LEAD AT $0; ONE ABSENT FROM THE SERIES IS NOT ASSESSED (ENG-50).
func TestVolumes_FillingAndOversized(t *testing.T) {
	pvc := func(name string) corev1.PersistentVolumeClaim {
		return corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: name}}
	}
	inv := &collect.Inventory{PVCs: []corev1.PersistentVolumeClaim{pvc("pg-0"), pvc("logs"), pvc("archive"), pvc("unseen")}}
	inv.Meta.Collected = []string{"persistentvolumeclaims"}
	tp := week7()
	gib := float64(1 << 30)
	tp.Volumes = map[string]prom.VolumeFill{
		"data/pg-0":    {Namespace: "data", Claim: "pg-0", CapacityBytes: 100 * gib, UsedNowBytes: 80 * gib, UsedMaxBytes: 80 * gib, GrowthPerDay: 4 * gib},
		"data/logs":    {Namespace: "data", Claim: "logs", CapacityBytes: 100 * gib, UsedNowBytes: 30 * gib, UsedMaxBytes: 31 * gib},
		"data/archive": {Namespace: "data", Claim: "archive", CapacityBytes: 500 * gib, UsedNowBytes: 20 * gib, UsedMaxBytes: 25 * gib},
	}
	fs := VolumeFilling{}.Evaluate(inv, Options{Temporal: tp})
	if len(fs) != 1 || fs[0].IDBasis.Name != "pg-0" || fs[0].Severity != "high" ||
		!strings.Contains(fs[0].Title, "fills in about 5 days") {
		t.Fatalf("filling: %+v", fs)
	}
	if ev := strings.Join(fs[0].Evidence, "\n"); !strings.Contains(ev, "80.0 GiB used of 100.0 GiB (80%)") || !strings.Contains(ev, "grew by 4.0 GiB a day") {
		t.Errorf("evidence:\n%s", ev)
	}
	os := VolumeOversized{}.Evaluate(inv, Options{Temporal: tp})
	if len(os) != 1 || os[0].IDBasis.Name != "archive" || os[0].DollarImpactMonthly != 0 {
		t.Fatalf("oversized: %+v", os)
	}
	if fs := (VolumeFilling{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatal("no series, and a finding")
	}
}

// AN AUTOSCALER AT ITS CEILING, ONE NEVER OFF ITS FLOOR AND ONE THAT KEEPS CHANGING ARE EACH SAID (ENG-54).
func TestAutoscalerBehaviour_CeilingFloorAndRestlessness(t *testing.T) {
	two, ten := int32(2), int32(10)
	h := func(name string) autoscalingv2.HorizontalPodAutoscaler {
		return autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: &two, MaxReplicas: ten,
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: name}}}
	}
	inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{h("api"), h("worker"), h("web"), h("calm")}}
	inv.Meta.Collected = []string{"horizontalpodautoscalers"}
	tp := week7()
	tp.Autoscalers = map[string]prom.AutoscalerHistory{
		"shop/api":    {AtMaxShare: 0.34, Changes: 20},
		"shop/worker": {AtMinShare: 1, Changes: 0},
		"shop/web":    {AtMinShare: 0.4, Changes: 700},
		"shop/calm":   {AtMinShare: 0.6, AtMaxShare: 0.05, Changes: 30},
	}
	fs := AutoscalerBehaviour{}.Evaluate(inv, Options{Temporal: tp})
	got := map[string]string{}
	for _, f := range fs {
		got[f.IDBasis.Name] = f.Title
	}
	if len(fs) != 3 || !strings.Contains(got["api"], "34% of the window at its maximum of 10") ||
		!strings.Contains(got["worker"], "never left its minimum of 2") || !strings.Contains(got["web"], "700 times") {
		t.Fatalf("titles: %v", got)
	}
}
