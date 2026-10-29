package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// bannedDanglingPhrases — a dangling reference is a contradiction inside the operator's own configuration,
// and every phrase here claims a CONSEQUENCE the snapshot cannot see.
//
// The strongest temptation in this family is the one B-133 punished: reading a field correctly and then
// asserting what it means. "The pod will not start" is true for a pod created after the ServiceAccount went
// away, and false for the pod that has been running for a month under a token it already holds.
var bannedDanglingPhrases = []string{
	"will not start", "cannot start", "will fail", "is broken", "is down",
	"has no permissions", "grants nothing", "scales nothing", "is not scaling",
	"will be deleted", "has been deleted", "was deleted",
	"guaranteed", "certainly", "must have been",
}

func TestDanglingRules_ClaimTheReferenceAndNotItsConsequence(t *testing.T) {
	out := allDanglingFindings(t, danglingFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing — and this family's normal " +
			"output on a healthy cluster is silence, which makes a planted positive the only thing that " +
			"distinguishes correct from asleep")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, p := range bannedDanglingPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — the snapshot shows a name that resolves to nothing, not what "+
					"that will do:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestDanglingRules_NeverCarryDollars(t *testing.T) {
	for _, f := range allDanglingFindings(t, danglingFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f — a name that resolves to nothing has no price", f.ID, f.DollarImpactMonthly)
		}
	}
}

// THE DENIAL GUARD, AND IT IS THE WHOLE RULE. Every claim in this family is "X names Y and Y does not exist",
// which is an ABSENCE claim over the target list. A denied list makes every reference look dangling, so a
// rule without this guard reports the entire cluster as broken the moment RBAC narrows.
//
// ASSERTED PER RULE, AGAINST ITS OWN RequiredKinds. The first version of this test matched the DENIED KIND'S
// NAME against the finding's text, and failed for two reasons that had nothing to do with the guard:
// snapshotNote's sentence contains the word "pod", and a roleRef finding legitimately names a ServiceAccount
// as the binding's subject. The assertion was reading prose where the property is a dependency.
func TestDangling_ADeniedTargetListIsSilence(t *testing.T) {
	type ruleUnderTest struct {
		name string
		eval func(*collect.Inventory) []types.Finding
		deps []string
	}
	rules := []ruleUnderTest{
		{"DanglingServiceAccount",
			func(i *collect.Inventory) []types.Finding {
				return (DanglingServiceAccount{}).Evaluate(i, Options{IncludeSystem: true})
			},
			(DanglingServiceAccount{}).RequiredKinds()},
		{"DanglingRoleRef",
			func(i *collect.Inventory) []types.Finding {
				return (DanglingRoleRef{}).Evaluate(i, Options{IncludeSystem: true})
			},
			(DanglingRoleRef{}).RequiredKinds()},
		{"DanglingScaleTarget",
			func(i *collect.Inventory) []types.Finding {
				return (DanglingScaleTarget{}).Evaluate(i, Options{IncludeSystem: true})
			},
			(DanglingScaleTarget{}).RequiredKinds()},
	}

	for _, r := range rules {
		if len(r.deps) == 0 {
			t.Fatalf("%s declares no RequiredKinds, so there is nothing to deny", r.name)
		}
		// NON-VACUITY, per rule: it must fire on the fixture before any denial, or its silence below proves
		// nothing about the guard.
		if len(realDangling(r.eval(danglingFixture()))) == 0 {
			t.Errorf("%s produces nothing on the planted fixture", r.name)
			continue
		}
		for _, denied := range r.deps {
			inv := danglingFixture()
			var kept []string
			for _, c := range inv.Meta.Collected {
				if c != denied {
					kept = append(kept, c)
				}
			}
			inv.Meta.Collected = kept
			inv.Meta.Denied = []string{denied + ": forbidden"}

			if got := r.eval(inv); len(got) != 0 {
				t.Errorf("%s produced %d finding(s) with its declared dependency %q denied — an absence from a "+
					"list we could not read is not an absence: %s", r.name, len(got), denied, got[0].Title)
			}
		}
	}
}

// SPEC §8.1 — construct a cluster where the rule fires and is WRONG. Three shapes, all real.
func TestDangling_TheThreeWaysThisFamilyWouldBeWrong(t *testing.T) {
	t.Run("an empty serviceAccountName means default, not missing", func(t *testing.T) {
		inv := healthyFixture()
		// The overwhelmingly common case: no serviceAccountName at all.
		inv.Deployments[0].Spec.Template.Spec.ServiceAccountName = ""
		for _, f := range realDangling((DanglingServiceAccount{}).Evaluate(inv, Options{IncludeSystem: true})) {
			t.Errorf("a workload with no serviceAccountName was reported: %s", f.Title)
		}
	})

	t.Run("a RoleBinding may reference a ClusterRole, and that is not a dangle", func(t *testing.T) {
		inv := healthyFixture()
		inv.RoleBindings = []rbacv1.RoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "rb"},
			// kind ClusterRole inside a RoleBinding is the normal way to reuse a cluster role in one
			// namespace. Looking it up in the Roles list would report every one of them as dangling.
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}}
		inv.ClusterRoles = append(inv.ClusterRoles, rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}})
		for _, f := range realDangling((DanglingRoleRef{}).Evaluate(inv, Options{IncludeSystem: true})) {
			t.Errorf("a RoleBinding referencing an existing ClusterRole was reported: %s", f.Title)
		}
	})

	t.Run("an HPA target of a kind we do not collect is excluded and counted", func(t *testing.T) {
		inv := healthyFixture()
		// Argo Rollout, KEDA ScaledObject, a bare ReplicaSet — all scalable, none collected. Reporting them
		// as missing would fire on every cluster running a progressive-delivery controller.
		inv.HPAs = []autoscalingv2.HorizontalPodAutoscaler{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "hpa-rollout"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				MaxReplicas:    5,
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout", Name: "api"},
			},
		}}
		out := (DanglingScaleTarget{}).Evaluate(inv, Options{IncludeSystem: true})
		for _, f := range realDangling(out) {
			t.Errorf("an HPA targeting an uncollected kind was reported as dangling: %s", f.Title)
		}
		// AND COUNTED. Excluding silently is the defect — a reader would conclude every HPA was checked.
		blob := ""
		for _, f := range out {
			blob += f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n")
		}
		if !strings.Contains(blob, "Rollout") {
			t.Errorf("the exclusion is not disclosed anywhere:\n%s", blob)
		}
	})
}

// Each rule fires on its own planted positive, and names both halves of the reference.
func TestDangling_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := danglingFixture()

	for _, tc := range []struct {
		name  string
		out   []types.Finding
		names []string
	}{
		{"a workload naming a ServiceAccount that does not exist",
			realDangling((DanglingServiceAccount{}).Evaluate(inv, Options{IncludeSystem: true})),
			[]string{"api/orphan-app", "missing-sa"}},
		{"a binding naming a role that does not exist",
			realDangling((DanglingRoleRef{}).Evaluate(inv, Options{IncludeSystem: true})),
			[]string{"orphan-binding", "missing-role"}},
		{"an autoscaler naming a workload that does not exist",
			realDangling((DanglingScaleTarget{}).Evaluate(inv, Options{IncludeSystem: true})),
			[]string{"orphan-hpa", "missing-deploy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.out) == 0 {
				t.Fatal("no finding")
			}
			blob := ""
			for _, f := range tc.out {
				blob += f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n") + "\n"
			}
			// BOTH HALVES NAMED. A finding that says only "a reference is dangling" is unactionable, and one
			// that names only the target cannot be found by the reader.
			for _, want := range tc.names {
				if !strings.Contains(blob, want) {
					t.Errorf("the finding does not name %q:\n%s", want, blob)
				}
			}
		})
	}
}

// A HEALTHY CLUSTER IS SILENT. This family's whole claim is that its findings are unarguable, and a rule
// that fires on a correct cluster has no such property.
func TestDangling_AHealthyClusterProducesNothing(t *testing.T) {
	if out := allDanglingFindings(t, healthyFixture()); len(out) != 0 {
		for _, f := range out {
			t.Errorf("a healthy cluster produced: %s\n  %s", f.Title, strings.Join(f.Evidence, "\n  "))
		}
	}
	// NON-VACUITY: the same fixture with one reference broken must fire, or "silence" is true because the
	// rules never speak.
	broken := healthyFixture()
	broken.Deployments[0].Spec.Template.Spec.ServiceAccountName = "no-such-sa"
	if out := realDangling((DanglingServiceAccount{}).Evaluate(broken, Options{IncludeSystem: true})); len(out) == 0 {
		t.Error("breaking one reference produced nothing, so the silence above proves nothing")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────

func allDanglingFindings(t *testing.T, inv *collect.Inventory) []types.Finding {
	t.Helper()
	var out []types.Finding
	out = append(out, realDangling((DanglingServiceAccount{}).Evaluate(inv, Options{IncludeSystem: true}))...)
	out = append(out, realDangling((DanglingRoleRef{}).Evaluate(inv, Options{IncludeSystem: true}))...)
	out = append(out, realDangling((DanglingScaleTarget{}).Evaluate(inv, Options{IncludeSystem: true}))...)
	return out
}

func realDangling(in []types.Finding) []types.Finding {
	var out []types.Finding
	for _, f := range in {
		if f.Confidence > 0 {
			out = append(out, f)
		}
	}
	return out
}

func healthyFixture() *collect.Inventory {
	one := int32(1)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "good-app"},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{ServiceAccountName: "app-sa", Containers: []corev1.Container{{Name: "c"}}},
			}},
		}},
		ServiceAccounts: []corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "app-sa"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "default"}},
		},
		HPAs: []autoscalingv2.HorizontalPodAutoscaler{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "good-hpa"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				MaxReplicas:    5,
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "good-app"},
			},
		}},
		ClusterRoles: []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "view"}}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "good-binding"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "api", Name: "app-sa"}},
		}},
	}
	inv.Meta.Collected = danglingKinds()
	return inv
}

// danglingFixture is healthy plus one planted positive per rule, and nothing else — so a finding that
// appears without a plant behind it is a false positive with a name.
func danglingFixture() *collect.Inventory {
	inv := healthyFixture()
	one := int32(1)
	inv.Deployments = append(inv.Deployments, appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "orphan-app"},
		Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{ServiceAccountName: "missing-sa", Containers: []corev1.Container{{Name: "c"}}},
		}},
	})
	inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "missing-role"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "api", Name: "app-sa"}},
	})
	inv.HPAs = append(inv.HPAs, autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "api", Name: "orphan-hpa"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			MaxReplicas:    5,
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: "missing-deploy"},
		},
	})
	return inv
}

func danglingKinds() []string {
	return []string{"clusterrolebindings", "clusterroles", "daemonsets", "deployments",
		"horizontalpodautoscalers", "pods", "rolebindings", "roles", "serviceaccounts", "services", "statefulsets"}
}
