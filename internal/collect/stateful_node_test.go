package collect

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A NODE THAT HOLDS PERSISTENT DATA IS MARKED, AND THE MARK HAD NO PRODUCER.
//
// `types.NodeRef.Stateful` is read in FOUR places in the node diagram: it picks a distinct colour class
// (`node-type-stateful`), adds `diagram-node-stateful` to the node group, reserves 50px of name padding for
// a badge, and draws a 30×19 "DB" badge with its own raised label-floor reasoning. All of it was built,
// styled, and had NEVER RENDERED ONCE, because nothing ever set the flag.
//
// Found by TestSchema_EveryFieldHasAProducer — and nearly deleted instead, on a grep whose `head -3` hid
// the four readers. The compiler caught what the probe hid: this is the same shape as
// Methodology.Illustrative (M-61), a field with readers and no writer, which is four branches that never
// fire rather than dead weight.
//
// WHAT THE BADGE CLAIMS, and therefore what the derivation must be. The badge says: evicting this node
// moves persistent data. Two facts read straight from a pod spec satisfy that, and neither is an inference:
//
//	a pod OWNED BY A STATEFULSET     — StatefulSets own their pods directly, one hop, no ReplicaSet
//	a pod MOUNTING A PVC             — a Deployment with a claim is stateful in the way that matters
//
// The field's original comment proposed exactly these two ("StatefulSet presence or storage-class mounts").
// What it never had was code.
//
// WHAT IT DOES NOT CLAIM: that the data is a database, that eviction loses it, or that the workload cannot
// tolerate a move. A PVC may be ReadWriteMany and a StatefulSet may be a cache. The badge marks where
// persistent data is BOUND, which is the fact a drain has to reckon with.
func TestBuildArchitecture_MarksNodesHoldingPersistentData(t *testing.T) {
	node := func(name string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"topology.kubernetes.io/zone": "eu-central-1a"},
		}}
	}
	pod := func(name, nodeName string, opts ...func(*corev1.Pod)) corev1.Pod {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
			Spec:       corev1.PodSpec{NodeName: nodeName},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		for _, o := range opts {
			o(&p)
		}
		return p
	}
	ownedByStatefulSet := func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet", Name: "pg", APIVersion: "apps/v1"}}
	}
	ownedByReplicaSet := func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-7f4", APIVersion: "apps/v1"}}
	}
	withPVC := func(p *corev1.Pod) {
		p.Spec.Volumes = []corev1.Volume{{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-0"},
			},
		}}
	}
	withEmptyDir := func(p *corev1.Pod) {
		p.Spec.Volumes = []corev1.Volume{{
			Name:         "scratch",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		}}
	}

	inv := &Inventory{
		Nodes: []corev1.Node{node("n-sts"), node("n-pvc"), node("n-plain"), node("n-emptydir")},
		Pods: []corev1.Pod{
			pod("pg-0", "n-sts", ownedByStatefulSet),
			pod("api-a", "n-pvc", ownedByReplicaSet, withPVC),
			pod("api-b", "n-plain", ownedByReplicaSet),
			pod("cache-a", "n-emptydir", ownedByReplicaSet, withEmptyDir),
		},
		StatefulSets: []appsv1.StatefulSet{{ObjectMeta: metav1.ObjectMeta{Name: "pg", Namespace: "app"}}},
	}

	arch := buildArchitecture(inv, nil, "eu-central-1", "eks", pricing.Embedded())
	if arch == nil {
		t.Fatal("buildArchitecture returned nil")
	}
	got := map[string]bool{}
	seen := 0
	for _, az := range arch.AZs {
		for _, n := range az.Nodes {
			got[n.Name] = n.Stateful
			seen++
		}
	}
	if seen != 4 {
		t.Fatalf("expected 4 nodes in the architecture, got %d — the fixture did not build and every "+
			"assertion below would pass over an absence", seen)
	}
	for _, tc := range []struct {
		node string
		want bool
		why  string
	}{
		{"n-sts", true, "hosts a pod owned by a StatefulSet"},
		{"n-pvc", true, "hosts a pod mounting a PersistentVolumeClaim"},
		{"n-plain", false, "hosts a ReplicaSet pod with no claim"},
		{"n-emptydir", false, "an emptyDir dies with the pod; it is not persistent data bound to this node"},
	} {
		if got[tc.node] != tc.want {
			t.Errorf("node %s: Stateful = %v, want %v — %s", tc.node, got[tc.node], tc.want, tc.why)
		}
	}
	_ = types.NodeRef{}
}
