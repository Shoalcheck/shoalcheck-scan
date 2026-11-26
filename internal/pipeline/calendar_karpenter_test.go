package pipeline

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// KARPENTER'S NODES EXPIRE ON A DATE THE READING CAN STATE (ENG-43): one row per pool and day, counting its nodes; a
// pool that never expires adds none; Karpenter's nodes with the NodePools unread are a clock not assessed.
func TestCalendar_KarpenterExpiry(t *testing.T) {
	at := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	node := func(name, pool string, created time.Time) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"karpenter.sh/nodepool": pool},
			CreationTimestamp: metav1.NewTime(created)}}
	}
	pool := func(name, expire string) unstructured.Unstructured {
		u := unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"template": map[string]any{
			"spec": map[string]any{"expireAfter": expire}}}}}
		u.SetName(name)
		return u
	}
	inv := &collect.Inventory{Nodes: []corev1.Node{
		node("a", "general", at.Add(-10*24*time.Hour)), node("b", "general", at.Add(-10*24*time.Hour)),
		node("c", "batch", at.Add(-2*24*time.Hour)),
	}}
	inv.Meta.StartedAt = at
	if _, reason := karpenterRows(inv, at, true); !strings.Contains(reason, "NodePools were not read") {
		t.Fatalf("unread pools: %q", reason)
	}
	inv.StackObjects = map[schema.GroupVersionResource][]unstructured.Unstructured{nodePoolsGVR: {pool("general", "720h"), pool("batch", "Never")}}
	inv.Meta.Collected = []string{"cr:nodepools.karpenter.sh"}
	rows, reason := karpenterRows(inv, at, true)
	if reason != "" || len(rows) != 1 {
		t.Fatalf("rows %+v, reason %q", rows, reason)
	}
	r := rows[0]
	if r.Date != "2026-12-09" || !strings.Contains(r.Observation, "2 nodes it launched reach that age on 2026-12-09") || r.Passed {
		t.Fatalf("row: %+v", r)
	}
}
