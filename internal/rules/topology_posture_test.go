package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// topology_posture_test.go — three structural rules, and every adversarial case is a shape that LOOKS like
// the finding and is not: a managed control plane with zero visible nodes, a static pod owned by a file, a
// completed Job pod outliving its owner, and a malformed PDB selector.

var bannedPosturePhrases = []string{
	"single point of failure", "will fail", "cannot be evicted", "will be lost", "data loss",
	"is unmanaged and will", "outage", "guaranteed", "certainly",
}

func TestTopologyPosture_ClaimsTheStructureAndNotTheOutcome(t *testing.T) {
	out := allPostureFindings(postureFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters,
		}, f.Evidence...), "\n"))
		for _, p := range bannedPosturePhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestSingleControlPlane_ZeroIsNotOne(t *testing.T) {
	// A MANAGED cluster shows no control-plane nodes at all. Reporting that as a single point of failure
	// would fire on every EKS, AKS and GKE cluster in existence — the largest possible false positive.
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"nodes"}},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "aks-worker-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "aks-worker-2"}},
		},
	}
	assertSilent(t, (SingleControlPlaneNode{}).Evaluate(inv, Options{IncludeSystem: true}))
}

func TestSingleControlPlane_ReadsBothLabelSpellings(t *testing.T) {
	// The older label survives on clusters upgraded in place. Reading only the current one would report a
	// three-node control plane as having none.
	for _, label := range controlPlaneLabels {
		inv := &collect.Inventory{
			Meta: collect.Meta{Collected: []string{"nodes"}},
			Nodes: []corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{label: ""}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}},
			},
		}
		if got := (SingleControlPlaneNode{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 1 {
			t.Errorf("label %q was not recognised as a control-plane role", label)
		}
	}
	// Three control-plane nodes is the healthy shape and must be silent.
	inv := &collect.Inventory{Meta: collect.Meta{Collected: []string{"nodes"}}}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		inv.Nodes = append(inv.Nodes, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n,
			Labels: map[string]string{controlPlaneLabels[0]: ""}}})
	}
	assertSilent(t, (SingleControlPlaneNode{}).Evaluate(inv, Options{IncludeSystem: true}))
}

func TestUnmanagedPod_TheThreeShapesThatLookUnmanagedAndAreNot(t *testing.T) {
	yes := true
	base := func(ps ...corev1.Pod) *collect.Inventory {
		return &collect.Inventory{Meta: collect.Meta{Collected: []string{"pods"}}, Pods: ps}
	}
	t.Run("a static (mirror) pod is owned by a file on disk", func(t *testing.T) {
		assertSilent(t, (UnmanagedPod{}).Evaluate(base(corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "kube-apiserver-node1",
				Annotations: map[string]string{corev1.MirrorPodAnnotationKey: "abc"}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}), Options{IncludeSystem: true}))
	})
	t.Run("a finished pod outliving its owner is garbage collection", func(t *testing.T) {
		assertSilent(t, (UnmanagedPod{}).Evaluate(base(corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "backup-xyz"},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
		}), Options{IncludeSystem: true}))
	})
	t.Run("a pod with a controller is managed", func(t *testing.T) {
		assertSilent(t, (UnmanagedPod{}).Evaluate(base(corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-1",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-abc", Controller: &yes}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}), Options{IncludeSystem: true}))
	})
	t.Run("a genuinely unowned running pod is reported", func(t *testing.T) {
		got := (UnmanagedPod{}).Evaluate(base(corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "debug-shell"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}), Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "debug-shell") {
			t.Error("the pod is not named")
		}
	})
}

func TestTwoPDBs_AMalformedSelectorMatchesNothing(t *testing.T) {
	// pdbSelector returns nil for an absent or unparseable selector. Treating that as "matches all" would
	// report every pod in the namespace as doubly covered off ONE malformed object.
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods", "poddisruptionbudgets"}},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-1",
				Labels: map[string]string{"app": "api"}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}},
		PDBs: []policyv1.PodDisruptionBudget{
			pdbFor("app", "real", "api", ptrIOS(intstr.FromInt32(1)), nil),
			{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "no-selector"}},
		},
	}
	assertSilent(t, (PodCoveredByTwoPDBs{}).Evaluate(inv, Options{IncludeSystem: true}))
}

func TestTwoPDBs_TwoRealBudgetsOverOnePodAreReported(t *testing.T) {
	ma := intstr.FromInt32(1)
	inv := &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods", "poddisruptionbudgets"}},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-1",
				Labels: map[string]string{"app": "api", "tier": "web"}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}},
		PDBs: []policyv1.PodDisruptionBudget{
			pdbFor("app", "by-app", "api", &ma, nil),
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "by-tier"},
				Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &ma,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}}},
			},
		},
	}
	got := (PodCoveredByTwoPDBs{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	for _, want := range []string{"by-app", "by-tier", "api-1"} {
		if !strings.Contains(blob, want) {
			t.Errorf("%q is not named in the evidence:\n%s", want, blob)
		}
	}
}

func TestTopologyPosture_NeverCarryDollars(t *testing.T) {
	for _, f := range allPostureFindings(postureFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

func ptrIOS(v intstr.IntOrString) *intstr.IntOrString { return &v }

func postureFixture() *collect.Inventory {
	ma := intstr.FromInt32(1)
	return &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"nodes", "pods", "poddisruptionbudgets"}},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1",
				Labels: map[string]string{controlPlaneLabels[0]: ""}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
		},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "debug-shell",
				Labels: map[string]string{"app": "api", "tier": "web"}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}},
		PDBs: []policyv1.PodDisruptionBudget{
			pdbFor("app", "by-app", "api", &ma, nil),
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "by-tier"},
				Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &ma,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}}},
			},
		},
	}
}

func allPostureFindings(inv *collect.Inventory) []types.Finding {
	o := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (SingleControlPlaneNode{}).Evaluate(inv, o)...)
	out = append(out, (UnmanagedPod{}).Evaluate(inv, o)...)
	out = append(out, (PodCoveredByTwoPDBs{}).Evaluate(inv, o)...)
	return out
}
