package rules

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// ownedPod builds a pod with a single controller owner reference.
func ownedPod(ns, name, ownerKind, ownerName string) corev1.Pod {
	ctrl := true
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:      name,
		Namespace: ns,
		OwnerReferences: []metav1.OwnerReference{{
			Kind:       ownerKind,
			Name:       ownerName,
			UID:        k8stypes.UID("uid-" + ownerName),
			Controller: &ctrl,
		}},
	}}
}

func TestOwnerChain_DeploymentVerified(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("app", "web", 2, nil)}}
	pod := ownedPod("app", "web-7d4f8b9c5d-x2k9q", "ReplicaSet", "web-7d4f8b9c5d")

	chain := ownerChain(inv, pod)
	if len(chain) != 2 {
		t.Fatalf("want 2 links (Deployment, ReplicaSet), got %d: %+v", len(chain), chain)
	}
	if chain[0].Kind != "Deployment" || chain[0].Name != "web" {
		t.Errorf("outermost owner must come FIRST, got %+v", chain[0])
	}
	if chain[1].Kind != "ReplicaSet" || chain[1].Name != "web-7d4f8b9c5d" {
		t.Errorf("ReplicaSet must be the second link, got %+v", chain[1])
	}
	if chain[1].UID != "uid-web-7d4f8b9c5d" {
		t.Errorf("ReplicaSet link must carry the ownerRef UID, got %q", chain[1].UID)
	}
}

func TestOwnerChain_RSWithoutMatchingDeployment(t *testing.T) {
	// Deployment "web" exists, but in a DIFFERENT namespace — the RS→Deployment
	// inference must not cross namespaces. Honest answer: the RS link alone.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("other", "web", 2, nil)}}
	pod := ownedPod("app", "web-7d4f8b9c5d-x2k9q", "ReplicaSet", "web-7d4f8b9c5d")

	chain := ownerChain(inv, pod)
	if len(chain) != 1 || chain[0].Kind != "ReplicaSet" || chain[0].Name != "web-7d4f8b9c5d" {
		t.Fatalf("unverified RS must yield the single honest ReplicaSet link, got %+v", chain)
	}
}

func TestOwnerChain_RSNameWithoutHashSuffix(t *testing.T) {
	// A ReplicaSet name with no "-" segment cannot encode a Deployment name —
	// never guess; emit the RS link alone.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("app", "web", 2, nil)}}
	pod := ownedPod("app", "web-x2k9q", "ReplicaSet", "standalone")

	chain := ownerChain(inv, pod)
	if len(chain) != 1 || chain[0].Kind != "ReplicaSet" || chain[0].Name != "standalone" {
		t.Fatalf("dash-less RS name must yield single RS link, got %+v", chain)
	}
}

func TestOwnerChain_StatefulSetOwned(t *testing.T) {
	chain := ownerChain(&collect.Inventory{}, ownedPod("app", "redis-0", "StatefulSet", "redis"))
	if len(chain) != 1 || chain[0].Kind != "StatefulSet" || chain[0].Name != "redis" {
		t.Fatalf("StatefulSet owner must be a single link, got %+v", chain)
	}
}

func TestOwnerChain_DaemonSetAndJobOwned(t *testing.T) {
	for _, kind := range []string{"DaemonSet", "Job"} {
		chain := ownerChain(&collect.Inventory{}, ownedPod("app", "p", kind, "owner"))
		if len(chain) != 1 || chain[0].Kind != kind || chain[0].Name != "owner" {
			t.Errorf("%s owner must be a single link, got %+v", kind, chain)
		}
	}
}

func TestOwnerChain_UnownedPod(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "naked", Namespace: "app"}}
	if chain := ownerChain(&collect.Inventory{}, pod); len(chain) != 0 {
		t.Fatalf("unowned pod must yield empty chain, got %+v", chain)
	}
}
