package pipeline

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// THE TIER-2 AND TIER-3 SOURCES COME FROM THE READ OBJECTS (ENG-07): a VPA's recommendation reaches the containers of
// the Deployment it targets, and a metrics-server sample its own container; the caller's own lister still wins.
func TestUsageTiers_FromTheReadObjects(t *testing.T) {
	ctrl := true
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-7d4f8b9c5d-xk2vq",
		Labels:          map[string]string{"pod-template-hash": "7d4f8b9c5d"},
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-7d4f8b9c5d", Controller: &ctrl}}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	vpa := unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"targetRef": map[string]any{"kind": "Deployment", "name": "api"}},
		"status": map[string]any{"recommendation": map[string]any{"containerRecommendations": []any{map[string]any{
			"containerName": "app", "target": map[string]any{"cpu": "250m", "memory": "256Mi"},
			"upperBound": map[string]any{"cpu": "1", "memory": "512Mi"}}}}}}}
	vpa.SetNamespace("shop")
	pm := unstructured.Unstructured{Object: map[string]any{"containers": []any{map[string]any{"name": "app",
		"usage": map[string]any{"cpu": "120m", "memory": "100Mi"}}}}}
	pm.SetNamespace("shop")
	pm.SetName(pod.Name)
	inv := &collect.Inventory{Pods: []corev1.Pod{pod}, StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{
		vpaGVR: {vpa}, podMetricsGVR: {pm}}}

	v, m := tierListers(Options{}, inv)
	if v == nil || m == nil {
		t.Fatal("the read objects did not become listers")
	}
	key := "shop/" + pod.Name + "/app"
	u, _ := v.ListTargets(context.Background())
	if got := u[key]; got.CPUCoresP95 != 0.25 || got.MemBytesP95 != 256<<20 || got.MemBytesMax != 512<<20 {
		t.Fatalf("VPA usage: %+v", got)
	}
	s, _ := m.ListSnapshot(context.Background())
	if got := s[key]; got.CPUCoresP95 != 0.12 || got.MemBytesP95 != 100<<20 {
		t.Fatalf("metrics usage: %+v", got)
	}
	if v, m := tierListers(Options{}, &collect.Inventory{}); v != nil || m != nil {
		t.Fatal("nothing read, and a lister anyway")
	}
}
