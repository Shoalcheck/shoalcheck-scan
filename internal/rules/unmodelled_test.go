package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// PODS UNDER A CONTROLLER NO RULE MODELS ARE COUNTED, BY KIND (ENG-12). A Rollout's ReplicaSet (no Deployment of
// that name), a CloudNativePG Cluster's pods and a Deployment's own pods: the first two are disclosed with their
// counts, the third is not; with deployments unread, a ReplicaSet's owner is unknown, not unmodelled.
func TestUnmodelledControllers_AreCountedByKind(t *testing.T) {
	ctrl := true
	pod := func(name, kind, owner string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name,
			OwnerReferences: []metav1.OwnerReference{{Kind: kind, Name: owner, Controller: &ctrl}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web"}}},
		Pods: []corev1.Pod{
			pod("web-6d4f8b9c5d-a", "ReplicaSet", "web-6d4f8b9c5d"),
			pod("canary-7c9d-a", "ReplicaSet", "canary-7c9d8b6f5d"), pod("canary-7c9d-b", "ReplicaSet", "canary-7c9d8b6f5d"),
			pod("pg-1", "Cluster", "pg"), pod("pg-2", "Cluster", "pg"), pod("pg-3", "Cluster", "pg"),
		},
		Meta: collect.Meta{Collected: []string{"deployments", "pods"}},
	}
	got := UnmodelledControllers(inv, Options{})
	if len(got) != 2 || got[0].Kind != "Cluster" || got[0].Pods != 3 || got[0].Controllers != 1 ||
		got[1].Kind != "ReplicaSet" || got[1].Pods != 2 || got[1].Controllers != 1 {
		t.Fatalf("unmodelled = %+v, want Cluster (1 controller, 3 pods) and ReplicaSet (1, 2); the Deployment's pod is modelled", got)
	}
	s := UnmodelledSentence(got)
	if !strings.HasPrefix(s, "5 pods under 2 controllers of kinds this reading does not model: Cluster ×1, ReplicaSet with no Deployment") {
		t.Errorf("sentence: %s", s)
	}
	inv.Meta = collect.Meta{Collected: []string{"pods"}, Denied: []string{"deployments: forbidden"}}
	for _, u := range UnmodelledControllers(inv, Options{}) {
		if u.Kind == "ReplicaSet" {
			t.Fatal("with deployments unread, a ReplicaSet's owner is unknown, not unmodelled")
		}
	}
}
