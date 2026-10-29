package pipeline

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// change_test.go — one reading, two inventories, one set of rules.
//
// `shoalcheck gate --with` asks what the cluster would look like with a pull request's manifests in it. The answer
// is only worth having if the two halves of the comparison differ by the change and by nothing else: the same
// read, the same clock, the same usage, the same rules. Two separate audits a few seconds apart would differ by
// whatever the cluster did in between, and by whatever a second Prometheus query returned.

func changeCluster() *fake.Clientset {
	replicas := int32(2)
	return fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: k8stypes.UID("kube-system-uid")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "deployer"}},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"},
			Spec: appsv1.DeploymentSpec{Replicas: &replicas, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				ServiceAccountName: "deployer",
				Containers:         []corev1.Container{{Name: "web", Image: "nginx:1.27"}},
			}}},
		},
	)
}

func grantClusterAdmin(inv *collect.Inventory) error {
	inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "deployer-admin"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "shop", Name: "deployer"}},
	})
	return nil
}

func hasRule(fs []types.Finding, rule string) bool {
	for _, f := range fs {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

// THE CLUSTER IS READ ONCE. Counted at the client: a second collection would mean the two halves were read at
// two moments, which is the difference this whole mode exists to remove.
func TestRunWithChange_ReadsTheClusterOnce(t *testing.T) {
	cs := changeCluster()
	lists := map[string]int{}
	cs.PrependReactor("list", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		lists[a.GetResource().Resource]++
		return false, nil, nil
	})
	now, with, err := RunWithChange(context.Background(), Options{Collector: collect.NewWithClient(cs), ClusterName: "c"}, grantClusterAdmin)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if lists["deployments"] != 1 || lists["clusterrolebindings"] != 1 {
		t.Errorf("the cluster was listed %d time(s) for deployments and %d for clusterrolebindings; once each",
			lists["deployments"], lists["clusterrolebindings"])
	}
	if !now.GeneratedAt.Equal(with.GeneratedAt) {
		t.Errorf("the two halves are dated %s and %s; they are one reading", now.GeneratedAt, with.GeneratedAt)
	}
	if now.Methodology.RunBasis.ClusterUID != "kube-system-uid" || with.Methodology.RunBasis.ClusterUID != "kube-system-uid" {
		t.Errorf("the halves do not carry the cluster's identity: %q / %q",
			now.Methodology.RunBasis.ClusterUID, with.Methodology.RunBasis.ClusterUID)
	}
}

// THE CHANGE IS JUDGED BY THE SAME RULES, AND ONLY ITS HALF SEES IT. The grant appears in the reading with the
// change and not in the reading of the cluster as it is — so the change was applied to a copy.
func TestRunWithChange_TheChangeReachesOnlyItsOwnHalf(t *testing.T) {
	const rule = "k8s.rbac.cluster-admin-serviceaccount"
	now, with, err := RunWithChange(context.Background(), Options{Collector: collect.NewWithClient(changeCluster()), ClusterName: "c"}, grantClusterAdmin)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if hasRule(now.Findings, rule) {
		t.Error("the reading of the cluster as it is carries the change's grant: the change was applied to the original")
	}
	if !hasRule(with.Findings, rule) {
		t.Errorf("the reading with the change does not carry %s; the change was not judged", rule)
	}
}

// AN UNCHANGED INVENTORY IS THE READING Run TAKES: same findings, in the same order. If the split had dropped a
// step the two halves would differ before any change touched them.
func TestRunWithChange_NoChangeIsTheReadingRunTakes(t *testing.T) {
	now, with, err := RunWithChange(context.Background(), Options{Collector: collect.NewWithClient(changeCluster()), ClusterName: "c"},
		func(*collect.Inventory) error { return nil })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	single, err := Run(context.Background(), Options{Collector: collect.NewWithClient(changeCluster()), ClusterName: "c"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	a, b, c := idsOf(now.Findings), idsOf(with.Findings), idsOf(single.Findings)
	if len(a) == 0 {
		t.Fatal("no findings at all; there is nothing here to compare")
	}
	if len(a) != len(b) || len(a) != len(c) {
		t.Fatalf("%d / %d / %d findings; an unchanged inventory must read the same three ways", len(a), len(b), len(c))
	}
	for i := range a {
		if a[i] != b[i] || a[i] != c[i] {
			t.Errorf("finding %d differs: %s / %s / %s", i, a[i], b[i], c[i])
		}
	}
}
