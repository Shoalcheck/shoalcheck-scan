package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A NODE THE AUTOSCALER WILL NOT REMOVE, WITH EACH REASON CITED AND ITS PRICE NEVER A SAVING (ENG-32). With no
// autoscaler in the cluster the rule is silent: nothing removes a node anyway.
func TestNodeScaleDownBlocked_CitesTheAutoscalersRulesAndBanksNothing(t *testing.T) {
	ctrl := true
	owned := []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-6d4f8b9c5d", Controller: &ctrl}}
	pod := func(name, node string, ann map[string]string, owners []metav1.OwnerReference, vols []corev1.Volume) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, Annotations: ann, OwnerReferences: owners,
			Labels: map[string]string{"app": name}},
			Spec: corev1.PodSpec{NodeName: node, Volumes: vols}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	inv := &collect.Inventory{
		Nodes: []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi"), rsNode("n2", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Pods: []corev1.Pod{
			pod("pinned", "n1", map[string]string{"cluster-autoscaler.kubernetes.io/safe-to-evict": "false"}, owned, nil),
			pod("bare", "n1", nil, nil, nil),
			pod("scratch", "n1", nil, owned, []corev1.Volume{{Name: "t", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}),
			pod("fine", "n2", nil, owned, nil),
		},
		PDBs: []policyv1.PodDisruptionBudget{},
	}
	inv.Meta.Collected = []string{"nodes", "pods", "poddisruptionbudgets", "deployments", "statefulsets", "daemonsets"}
	if fs := (NodeScaleDownBlocked{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("no autoscaler runs, and %d findings", len(fs))
	}
	inv.Deployments = []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "cluster-autoscaler"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web"}}}
	fs := NodeScaleDownBlocked{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].IDBasis.Name != "n1" {
		t.Fatalf("want node n1 only, got %d", len(fs))
	}
	f := fs[0]
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{"safe-to-evict: \"false\" (CA FAQ", "managed by no controller", "local storage, emptyDir or hostPath",
		"bills while blocked, not a saving"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	if f.DollarImpactMonthly != 0 {
		t.Fatalf("a blocked node's price was banked as a saving: $%.2f", f.DollarImpactMonthly)
	}
}
