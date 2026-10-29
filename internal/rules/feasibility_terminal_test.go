package rules

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A FINISHED POD HOLDS NO ROOM. A Job's pod that has Succeeded (or Failed) stays bound to its node until it is
// garbage-collected — a CronJob keeps its last few on purpose — and its requests are still in its spec. The
// scheduler does not count them: a terminal pod is not in its cache, and the kubelet's own admission counts active
// pods only. So a candidate node's free room is allocatable minus the requests of the pods still running or waiting
// on it, and a model that also subtracts finished ones reports "nowhere to go" for a pod the scheduler would place.
//
// Measured on the engine bench before this was written: see docs/engine/benchmark.md, "terminal pods".
func TestFeasibility_AFinishedPodHoldsNoRoom(t *testing.T) {
	node := func(name, zone, cpu string) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				"topology.kubernetes.io/zone": zone, "kubernetes.io/hostname": name}},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: qty(cpu), corev1.ResourceMemory: qty("8Gi")},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			},
		}
	}
	pod := func(name, nodeName, cpu string, phase corev1.PodPhase, owner metav1.OwnerReference) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, OwnerReferences: []metav1.OwnerReference{owner}},
			Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{
				Name: "c",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU: qty(cpu), corev1.ResourceMemory: qty("64Mi")}},
			}}},
			Status: corev1.PodStatus{Phase: phase},
		}
	}
	one := int32(1)
	inv := &collect.Inventory{
		Nodes: []corev1.Node{node("node-a", "zone-a", "2"), node("node-b", "zone-b", "2")},
		Pods: []corev1.Pod{
			// The workload that would move when zone-a goes: one core.
			pod("api-0", "node-a", "1", corev1.PodRunning, metav1.OwnerReference{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "api"}),
			// What zone-b holds: a report Job that finished hours ago, which asked for a core and a half.
			pod("report-28123-x7k2p", "node-b", "1500m", corev1.PodSucceeded, metav1.OwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: "report-28123"}),
			pod("import-28123-q9w4z", "node-b", "1500m", corev1.PodFailed, metav1.OwnerReference{APIVersion: "batch/v1", Kind: "Job", Name: "import-28123"}),
		},
		StatefulSets: []appsv1.StatefulSet{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"}, Spec: appsv1.StatefulSetSpec{Replicas: &one}}},
	}
	inv.Meta.Collected = []string{"nodes", "pods", "persistentvolumes", "persistentvolumeclaims"}

	for _, f := range realFindings((ZoneLossFeasibility{}).Evaluate(inv, Options{})) {
		t.Errorf("zone-loss reports %s: %s — node-b has two cores free; its only pods have finished", f.ID, f.Title)
	}
}
