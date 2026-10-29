package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func saAutomountBool(b bool) *bool { return &b }

// rbacCollectedMeta marks both binding kinds as collected so the rule's denial
// guard treats the RBAC picture as known.
func rbacCollectedMeta() collect.Meta {
	return collect.Meta{Collected: []string{"rolebindings", "clusterrolebindings"}}
}

// defaultSARoleBinding binds the namespace's default SA to a (Cluster)Role.
func defaultSARoleBinding(name, ns, roleKind, roleName string) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{Kind: roleKind, Name: roleName},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "default", Namespace: ns}},
	}
}

func TestDefaultSATokenAutomount(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "implicit", 2, nil), // no SA set → default SA, automount unset
			deploy("app", "explicit-default", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.ServiceAccountName = "default"
			}),
			deploy("app", "opted-out", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.AutomountServiceAccountToken = saAutomountBool(false)
			}),
			deploy("app", "named-sa", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.ServiceAccountName = "payments-svc"
			}),
		},
		// RBAC collected, but nothing binds the "app" default SA → inert case.
		Meta: rbacCollectedMeta(),
	}
	fs := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (implicit + explicit-default), got %d: %+v", len(fs), fs)
	}
	names := map[string]bool{}
	for _, f := range fs {
		if f.RuleID != "k8s.workload.default-sa-token-automount" {
			t.Errorf("ruleID = %q", f.RuleID)
		}
		names[f.AffectedResources[0].Name] = true
	}
	if !names["implicit"] || !names["explicit-default"] {
		t.Errorf("flagged %v, want implicit + explicit-default", names)
	}
	f := fs[0]
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "Deployment app/") || !strings.Contains(ev, "default SA") || !strings.Contains(ev, "automounted") {
		t.Errorf("evidence must name the workload and state the automount fact: %v", f.Evidence)
	}
	if !strings.Contains(f.RemediationYAML, "automountServiceAccountToken: false") ||
		!strings.Contains(f.RemediationYAML, "kind: Deployment") ||
		!strings.Contains(f.RemediationYAML, "namespace: app") {
		t.Errorf("remediation must patch automount off on the pod template:\n%s", f.RemediationYAML)
	}
	// Honest behavior for the inert case: evidence must corroborate severity with
	// the RBAC fact (no binding), not just paraphrase the title; severity stays
	// low and the worst-case breakout framing is dropped.
	if !strings.Contains(ev, "no Role/ClusterRole binding observed references the default SA") {
		t.Errorf("inert case must cite the absence of bindings in evidence: %v", f.Evidence)
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("inert default SA must be low severity, got %q", f.Severity)
	}
	if strings.Contains(f.WhyItMatters, "breakout") || strings.Contains(strings.ToLower(f.Description), "opening move") {
		t.Errorf("inert case must drop worst-case breakout framing: why=%q desc=%q", f.WhyItMatters, f.Description)
	}
	// Remediation must carry the validate-before-applying / IRSA caveat.
	if !strings.Contains(f.RemediationYAML, "Validate before applying") || !strings.Contains(f.RemediationYAML, "IRSA") {
		t.Errorf("remediation must warn to validate (IRSA/Pod Identity) before disabling automount:\n%s", f.RemediationYAML)
	}
	// Description must carry the cloud-IAM exception caveat.
	if !strings.Contains(f.Description, "Workload Identity") {
		t.Errorf("description must note the cloud-IAM token-projection exception: %q", f.Description)
	}
}

func TestDefaultSATokenAutomount_SAObjectOptOut(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("safe", "quiet", 2, nil), // pod silent → SA-level false wins → no finding
			deploy("safe", "pod-wins", 2, func(d *appsv1.Deployment) {
				// pod-level explicit true overrides the SA-level opt-out
				d.Spec.Template.Spec.AutomountServiceAccountToken = saAutomountBool(true)
			}),
		},
		ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "safe"},
			AutomountServiceAccountToken: saAutomountBool(false),
		}},
	}
	fs := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (pod-wins only), got %d: %+v", len(fs), fs)
	}
	if fs[0].AffectedResources[0].Name != "pod-wins" {
		t.Errorf("flagged %q, want pod-wins", fs[0].AffectedResources[0].Name)
	}
}

// A default SA actually bound to a (Cluster)Role is a real breakout amplifier:
// medium severity, the bound role named in evidence, strong wording retained.
func TestDefaultSATokenAutomount_BoundDefaultSAIsGraded(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("privileged", "api", 2, nil)},
		RoleBindings: []rbacv1.RoleBinding{
			defaultSARoleBinding("api-admin", "privileged", "ClusterRole", "cluster-admin"),
		},
		Meta: rbacCollectedMeta(),
	}
	fs := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != types.SeverityMedium {
		t.Errorf("bound default SA must be medium severity, got %q", f.Severity)
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "bound to") || !strings.Contains(ev, "cluster-admin") {
		t.Errorf("evidence must name the bound role: %v", f.Evidence)
	}
	if !strings.Contains(f.Description, "cluster-admin") {
		t.Errorf("description must name the bound role when privileged: %q", f.Description)
	}
	if f.Confidence <= 0.5 {
		t.Errorf("confidence for a confirmed-privileged token should be higher than the inert case, got %v", f.Confidence)
	}
}

// DENIAL GUARD: when RBAC was not collected the rule must NOT assert that no
// binding references the default SA — it must state the privilege was not
// assessed and stay low/cautious.
func TestDefaultSATokenAutomount_RBACNotCollected(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		// Meta empty → rolebindings/clusterrolebindings not in Collected.
	}
	fs := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	ev := strings.Join(f.Evidence, " ")
	if strings.Contains(ev, "no Role/ClusterRole binding observed") {
		t.Errorf("must not assert observed-absence of bindings when RBAC was not collected: %v", f.Evidence)
	}
	if !strings.Contains(ev, "not collected") {
		t.Errorf("must state RBAC was not assessed: %v", f.Evidence)
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("unknown-privilege case stays low to avoid overclaiming, got %q", f.Severity)
	}
}

// A pod that declares a projected serviceAccountToken volume (the IRSA / token-
// projection shape) gets a verify-first caveat in evidence rather than a clean
// disable-automount recommendation.
func TestDefaultSATokenAutomount_ProjectedTokenCaveat(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("aws", "s3-reader", 2, func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Volumes = []corev1.Volume{{
				Name: "aws-iam-token",
				VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: "sts.amazonaws.com"},
					}},
				}},
			}}
		})},
		Meta: rbacCollectedMeta(),
	}
	fs := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "projected serviceAccountToken") || !strings.Contains(strings.ToLower(ev), "verify before applying") {
		t.Errorf("projected-token pod must carry a verify-before-applying caveat: %v", fs[0].Evidence)
	}
}

func TestDefaultSATokenAutomount_SystemNamespaces(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("kube-system", "coredns", 2, nil)}}
	if got := len(DefaultSATokenAutomount{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("system namespace must be skipped by default, got %d findings", got)
	}
	if got := len(DefaultSATokenAutomount{}.Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", got)
	}
}

func TestDefaultSATokenAutomount_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "a", 1, nil),
		deploy("app", "b", 1, nil),
	}}
	first := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	second := DefaultSATokenAutomount{}.Evaluate(inv, Options{})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want 2 findings per run, got %d and %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[0].ID == first[1].ID || !strings.HasPrefix(first[0].ID, "f-") {
		t.Errorf("IDs must be stable, distinct, f-prefixed: %q %q vs %q", first[0].ID, first[1].ID, second[0].ID)
	}
}
