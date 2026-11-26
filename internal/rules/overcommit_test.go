package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A NODE WHOSE PODS' MEMORY LIMITS ARE TWICE ITS ALLOCATABLE IS REPORTED WITH ITS QOS MIX; ONE AT 1.2× IS NOT (ENG-31).
func TestNodeMemoryOvercommit_StatesTheRatioAndWhoGoesFirst(t *testing.T) {
	node := func(name, mem string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceMemory: qty(mem), corev1.ResourceCPU: qty("4")}}}
	}
	pod := func(name, nodeName, limit string) corev1.Pod {
		c := corev1.Container{Name: "c"}
		if limit != "" {
			c.Resources = corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: qty("1Gi")},
				Limits: corev1.ResourceList{corev1.ResourceMemory: qty(limit)}}
		}
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
			Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{c}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	inv := &collect.Inventory{
		Nodes: []corev1.Node{node("hot", "8Gi"), node("calm", "8Gi")},
		Pods: []corev1.Pod{pod("a", "hot", "8Gi"), pod("b", "hot", "8Gi"), pod("c", "hot", ""),
			pod("d", "calm", "4Gi"), pod("e", "calm", "5Gi")},
	}
	inv.Meta.Collected = []string{"nodes", "pods"}
	fs := NodeMemoryOvercommit{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].IDBasis.Name != "hot" {
		t.Fatalf("want only node hot (2.0×), got %d findings", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	for _, want := range []string{"add up to 16384Mi against 8192Mi allocatable — 2.00×", "0 Guaranteed, 2 Burstable, 1 BestEffort",
		"1 container has no memory limit at all, so the sum above is a floor"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
}
