package rules

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// replica_health_test.go — the two OBSERVABLE-ELSEWHERE rows, and the bug the fixture found in one of them.

// TestReplicasBelowDesired_AnUnwrittenStatusIsUnknownNotZero pins B-153.
//
// The first version tested only `generation != 0 && observed != generation`, which let the ZERO-VERSUS-ZERO
// case straight through — an object whose controller has written no status at all reads as "0 ready of N".
// That is the exact ambiguity Sweep 3 named, and it fired on TWELVE healthy workloads in the shipped
// fixture before the golden regeneration caught it.
func TestReplicasBelowDesired_AnUnwrittenStatusIsUnknownNotZero(t *testing.T) {
	three := int32(3)
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets"}},
		Deployments: []appsv1.Deployment{{
			// No Status at all, and no Generation — the shape every hand-written manifest has before a
			// controller touches it, and the shape the entire golden fixture had.
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "never-observed"},
			Spec:       appsv1.DeploymentSpec{Replicas: &three},
		}},
	}
	assertSilent(t, (ReplicasBelowDesired{}).Evaluate(inv, Options{IncludeSystem: true}))
}

func TestReplicasBelowDesired_TheWaysItWouldBeWrong(t *testing.T) {
	mk := func(name string, want, ready int32, gen, observedGen int64) appsv1.Deployment {
		w := want
		return appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, Generation: gen},
			Spec:       appsv1.DeploymentSpec{Replicas: &w},
			Status: appsv1.DeploymentStatus{ObservedGeneration: observedGen, Replicas: want,
				ReadyReplicas: ready},
		}
	}
	inv := func(ds ...appsv1.Deployment) *collect.Inventory {
		return &collect.Inventory{
			Meta:        collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets"}},
			Deployments: ds,
		}
	}

	t.Run("scaled to zero on purpose is not a shortfall", func(t *testing.T) {
		assertSilent(t, (ReplicasBelowDesired{}).Evaluate(inv(mk("parked", 0, 0, 3, 3)),
			Options{IncludeSystem: true}))
	})
	t.Run("a rollout the controller has not observed yet is not an outage", func(t *testing.T) {
		// generation 5, observedGeneration 4: the spec changed a moment ago and the counts beside it
		// describe the PREVIOUS spec.
		assertSilent(t, (ReplicasBelowDesired{}).Evaluate(inv(mk("mid-rollout", 3, 1, 5, 4)),
			Options{IncludeSystem: true}))
	})
	t.Run("fully ready is silent", func(t *testing.T) {
		assertSilent(t, (ReplicasBelowDesired{}).Evaluate(inv(mk("healthy", 3, 3, 2, 2)),
			Options{IncludeSystem: true}))
	})
	t.Run("observed and short is reported", func(t *testing.T) {
		got := (ReplicasBelowDesired{}).Evaluate(inv(mk("degraded", 3, 1, 2, 2)), Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(got[0].Title, "1 of 3") {
			t.Errorf("the counts are not in the title: %q", got[0].Title)
		}
		if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "observedGeneration") {
			t.Error("the evidence does not state what makes the counts trustworthy")
		}
	})
}

// A restart TOTAL is not a rate, and the pod's age is what makes it readable. Both must be in the finding.
func TestContainerRestartTotal_StatesTheAgeBesideTheCount(t *testing.T) {
	yes := true
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods", "deployments", "statefulsets", "daemonsets"},
			StartedAt: fixedReading},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-7d9f-aa",
				CreationTimestamp: metav1.NewTime(fixedReading.Add(-30 * 24 * time.Hour)),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-7d9f", Controller: &yes}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "api", RestartCount: 41}}},
		}},
	}
	got := (ContainerRestartTotal{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(blob, "41") {
		t.Error("the count is missing")
	}
	if !strings.Contains(blob, "30 day") {
		t.Errorf("the pod's age is not stated beside the total, so the reader cannot tell forty restarts "+
			"over a month from forty over a morning:\n%s", blob)
	}
	if !strings.Contains(blob, "TOTAL") && !strings.Contains(blob, "total") {
		t.Error("the finding does not say the count is cumulative")
	}
}

func TestContainerRestartTotal_BelowTheFloorIsSilent(t *testing.T) {
	yes := true
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods", "deployments", "statefulsets", "daemonsets"},
			StartedAt: fixedReading},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-1",
				CreationTimestamp: metav1.NewTime(fixedReading.Add(-365 * 24 * time.Hour)),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-7d9f", Controller: &yes}}},
			// A year-old pod restarted a handful of times by node drains and evictions. A low floor would
			// report every long-lived pod in the cluster.
			Status: corev1.PodStatus{Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{Name: "api", RestartCount: restartFloor - 1}}},
		}},
	}
	assertSilent(t, (ContainerRestartTotal{}).Evaluate(inv, Options{IncludeSystem: true}))
}
