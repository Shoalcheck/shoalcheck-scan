package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// setFixture is the mesh testbed's shape: a control plane tainted NoSchedule and two workers with room, and a
// Deployment pod on each worker. Losing either worker alone leaves the other; losing both leaves only the tainted
// control plane, which no workload pod tolerates.
func setFixture(workerCPU, podCPU string) *collect.Inventory {
	node := func(name string, taints []corev1.Taint) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/hostname": name}},
			Spec:       corev1.NodeSpec{Taints: taints},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: qty(workerCPU), corev1.ResourceMemory: qty("8Gi")},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			},
		}
	}
	ctrl := true
	pod := func(name, nodeName string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs", Controller: &ctrl}}},
			Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "app",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU: qty(podCPU), corev1.ResourceMemory: qty("64Mi")}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}
	return &collect.Inventory{
		Nodes: []corev1.Node{
			node("cp", []corev1.Taint{{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}}),
			node("w1", nil), node("w2", nil), node("w3", nil),
		},
		Pods: []corev1.Pod{pod("api-1", "w1"), pod("api-2", "w2")},
		Meta: collect.Meta{Collected: []string{"nodes", "pods", "persistentvolumes", "persistentvolumeclaims"}},
	}
}

// DRAINING SEVERAL NODES IS ONE SCENARIO, not several. NodeLossFeasibility asks about one node at a time, and the
// drain preflight used to union those answers — so draining both workers of a cluster whose only other node is a
// tainted control plane was "nothing this model checks stops the drain", while every workload would be left with
// no node at all. NodeSetLoss removes the whole set at once.
func TestNodeSetLoss_TheSetIsAssessedTogether(t *testing.T) {
	inv := setFixture("4", "500m")
	inv.Nodes = inv.Nodes[:3] // cp, w1, w2 — no spare worker

	for _, single := range []string{"w1", "w2"} {
		if got := NodeSetLoss(inv, []string{single}, Options{}); len(got) != 0 {
			t.Errorf("losing %s alone leaves the other worker, but NodeSetLoss reported: %s", single, got[0].Title)
		}
	}
	got := NodeSetLoss(inv, []string{"w1", "w2"}, Options{})
	if len(got) != 1 {
		t.Fatalf("losing both workers leaves only a tainted control plane, and NodeSetLoss reported %d findings", len(got))
	}
	f := got[0]
	if len(f.AffectedResources) != 2 {
		t.Errorf("both displaced pods should be named, got %v", f.AffectedResources)
	}
	for _, want := range []string{"w1", "w2", "2 pods"} {
		if !strings.Contains(f.Title+f.Description, want) {
			t.Errorf("the finding does not say %q: %s / %s", want, f.Title, f.Description)
		}
	}
	assertNoSchedulerVerdict(t, f)
}

// THE PODS OF ALL NAMED NODES MUST FIT TOGETHER. Each displaced pod fitting somewhere on its own is not the
// question when several leave at once: two pods of 3 CPU each, and one surviving node with 4 CPU free, is room for
// one of them. The aggregate test is sound in the direction this model may speak — if the total asked for exceeds
// the total free, no packing finds room, whatever order the scheduler tries.
func TestNodeSetLoss_TheDisplacedWorkMustFitTogether(t *testing.T) {
	inv := setFixture("4", "3") // w3 is the spare: 4 CPU free, and each displaced pod asks for 3
	got := NodeSetLoss(inv, []string{"w1", "w2"}, Options{})
	if len(got) != 1 {
		t.Fatalf("6 CPU of displaced requests against 4 CPU free was accepted (%d findings)", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "free") {
		t.Errorf("the finding does not state the aggregate it rests on: %v", got[0].Evidence)
	}
	assertNoSchedulerVerdict(t, got[0])

	roomy := setFixture("8", "3") // w3 has 8 CPU free: 6 fits
	if got := NodeSetLoss(roomy, []string{"w1", "w2"}, Options{}); len(got) != 0 {
		t.Errorf("6 CPU against 8 CPU free was refused: %s", got[0].Title)
	}
}

func assertNoSchedulerVerdict(t *testing.T, f types.Finding) {
	t.Helper()
	blob := strings.ToLower(strings.Join(append([]string{f.Title, f.Description, f.WhyItMatters}, f.Evidence...), "\n"))
	for _, phrase := range bannedFeasibilityPhrases {
		if strings.Contains(blob, phrase) {
			t.Errorf("the set finding says %q, which this model cannot support", phrase)
		}
	}
}
