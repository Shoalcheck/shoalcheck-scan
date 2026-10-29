package rules

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// pod_unready_test.go — the kind-3 rule, and the assertions that keep it kind 3.
//
// The overlap census classified "a pod Waiting with the kubelet's reason" and "pod not ready" as ONE new
// rule about the same subject as condition-unchanged, separated by the TIME axis. What makes that honest
// rather than convenient is two things a test can check: the new rule must report what the seven-day
// threshold refuses, and BOTH cards must name the other rule so a reader does not count one problem twice.

var bannedUnreadyPhrases = []string{
	// The kubelet's reason is quoted, never interpreted.
	"registry is down", "image does not exist", "the secret", "network is",
	"has been failing for", "has been down for", "for the last", "since",
	"will not recover", "outage", "users cannot", "guaranteed", "certainly",
}

func TestPodNotReady_QuotesTheKubeletAndInterpretsNothing(t *testing.T) {
	out := (PodNotReady{}).Evaluate(unreadyFixture(), Options{IncludeSystem: true})
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters,
		}, f.Evidence...), "\n"))
		for _, p := range bannedUnreadyPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — the kubelet's word is a fact, what it means is not:\n%s",
					f.ID, p, blob)
			}
		}
	}
}

// THE KIND-3 CONTRACT, BOTH DIRECTIONS. Either card without the other's name lets a reader count one
// problem twice, which is precisely what the census's rule exists to prevent.
func TestPodNotReady_CrossReferencesConditionUnchangedAndIsCrossReferencedBack(t *testing.T) {
	inv := unreadyFixture()
	fwd := (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(fwd) == 0 {
		t.Fatal("no pod-not-ready finding")
	}
	if !strings.Contains(strings.Join(fwd[0].Evidence, "\n"), "k8s.reliability.condition-unchanged") {
		t.Error("pod-not-ready does not name condition-unchanged, so a reader seeing both counts two problems")
	}

	// The reverse: a pod stuck long enough for condition-unchanged must carry the pointer back.
	old := metav1.NewTime(fixedReading.Add(-40 * 24 * time.Hour))
	stuck := healthyStuckFixture()
	stuck.Pods = append(stuck.Pods, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "long-broken",
			CreationTimestamp: old},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse, LastTransitionTime: old}}},
	})
	back := (StuckCondition{}).Evaluate(stuck, Options{IncludeSystem: true})
	if len(back) == 0 {
		t.Fatal("condition-unchanged did not fire on a pod unready for forty days")
	}
	if !strings.Contains(strings.Join(back[0].Evidence, "\n"), "k8s.reliability.pod-not-ready") {
		t.Error("condition-unchanged does not name pod-not-ready — the cross-reference is one-way, which " +
			"leaves the reader of THAT card counting two problems")
	}
}

// THE FIVE WAYS THIS RULE WOULD BE WRONG.
func TestPodNotReady_TheWaysItWouldBeWrong(t *testing.T) {
	base := func() *collect.Inventory {
		return &collect.Inventory{
			Meta: collect.Meta{Collected: []string{"pods", "deployments", "statefulsets", "daemonsets"},
				StartedAt: fixedReading},
		}
	}
	old := metav1.NewTime(fixedReading.Add(-2 * time.Hour))

	t.Run("a pod created moments ago is starting, not failing", func(t *testing.T) {
		// Every rollout creates these in batches. A rule without the floor reports its own cluster's
		// normal operation — B-131's defect.
		inv := base()
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "just-created",
				CreationTimestamp: metav1.NewTime(fixedReading.Add(-20 * time.Second))},
			Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
		})
		assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a finished pod is not an unready one", func(t *testing.T) {
		inv := base()
		for _, ph := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
			inv.Pods = append(inv.Pods, corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "job-" + string(ph),
					CreationTimestamp: old},
				Status: corev1.PodStatus{Phase: ph, Conditions: []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
			})
		}
		assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("an ABSENT Ready condition is unknown, not false", func(t *testing.T) {
		inv := base()
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "no-condition-yet",
				CreationTimestamp: old},
			Status: corev1.PodStatus{Phase: corev1.PodPending},
		})
		assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a pod being deleted is mid-operation", func(t *testing.T) {
		inv := base()
		del := metav1.NewTime(fixedReading)
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "terminating",
				CreationTimestamp: old, DeletionTimestamp: &del},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
		})
		assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a ready pod is silent however unhappy its phase looks", func(t *testing.T) {
		inv := base()
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "healthy", CreationTimestamp: old},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		})
		assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
}

// Pods of one workload are ONE card. Six replicas of a broken Deployment are one problem.
func TestPodNotReady_GroupsByWorkload(t *testing.T) {
	got := (PodNotReady{}).Evaluate(unreadyFixture(), Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("three unready pods of one Deployment produced %d findings, want 1", len(got))
	}
	if n := len(got[0].AffectedResources); n != 3 {
		t.Errorf("the card names %d pods, want 3", n)
	}
	if !strings.Contains(got[0].Title, "3 pod") {
		t.Errorf("the count is not in the title: %q", got[0].Title)
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "ImagePullBackOff") {
		t.Error("the kubelet's reason is not quoted")
	}
}

func TestPodNotReady_NeverCarriesDollars(t *testing.T) {
	for _, f := range (PodNotReady{}).Evaluate(unreadyFixture(), Options{IncludeSystem: true}) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

func TestPodNotReady_ADeniedPodListIsSilence(t *testing.T) {
	inv := unreadyFixture()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "pods")
	inv.Meta.Denied = append(inv.Meta.Denied, "pods: forbidden")
	assertSilent(t, (PodNotReady{}).Evaluate(inv, Options{IncludeSystem: true}))
}

func unreadyFixture() *collect.Inventory {
	yes := true
	old := metav1.NewTime(fixedReading.Add(-3 * time.Hour))
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods", "deployments", "statefulsets", "daemonsets"},
			StartedAt: fixedReading},
	}
	for _, n := range []string{"aa", "bb", "cc"} {
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "app", Name: "api-7d9f-" + n, CreationTimestamp: old,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-7d9f", Controller: &yes}},
			},
			Status: corev1.PodStatus{
				Phase:      corev1.PodPending,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}},
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "api",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
						Reason: "ImagePullBackOff", Message: "Back-off pulling image acme/api:v9"}},
				}},
			},
		})
	}
	return inv
}

var _ = types.Finding{}
