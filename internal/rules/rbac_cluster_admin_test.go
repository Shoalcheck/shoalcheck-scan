package rules

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func crbFixture(name, refKind, refName string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: refKind, Name: refName},
		Subjects:   subjects,
	}
}

func rbFixture(ns, name, refKind, refName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: refKind, Name: refName},
		Subjects:   subjects,
	}
}

func saSubject(ns, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: ns, Name: name}
}

func TestClusterAdminServiceAccount(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("ca-bind", "ClusterRole", "cluster-admin",
				saSubject("app", "deployer"),
				rbacv1.Subject{Kind: "User", Name: "admin@corp"}, // non-SA subject — ignored
			),
			crbFixture("view-bind", "ClusterRole", "view", saSubject("app", "reader")), // not cluster-admin
			crbFixture("user-only", "ClusterRole", "cluster-admin",
				rbacv1.Subject{Kind: "Group", Name: "system:masters"}), // no SA subject → no finding
		},
	}
	fs := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (ca-bind only), got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.rbac.cluster-admin-serviceaccount" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	// The grant line must be present verbatim; an additional scope-honesty
	// caveat line is also expected (custom wildcard/aggregated roles out of scope).
	// ASCII, not U+2192: this evidence line is copied into tickets and rendered into a report whose two embedded
	// faces contain no right arrow, so the character would have been supplied by the reader's system.
	wantEv := "ClusterRoleBinding ca-bind: ServiceAccount app/deployer -> cluster-admin"
	if len(f.Evidence) != 2 || f.Evidence[0] != wantEv {
		t.Errorf("evidence = %v, want first line %q plus a scope-note line", f.Evidence, wantEv)
	}
	if !strings.Contains(strings.ToLower(f.Evidence[1]), "by name only") {
		t.Errorf("evidence must carry the wildcard/aggregated-role scope caveat: %v", f.Evidence)
	}
	if len(f.AffectedResources) != 2 ||
		f.AffectedResources[0].Kind != "ClusterRoleBinding" || f.AffectedResources[0].Name != "ca-bind" ||
		f.AffectedResources[1].Kind != "ServiceAccount" || f.AffectedResources[1].Namespace != "app" || f.AffectedResources[1].Name != "deployer" {
		t.Errorf("affected must list the binding and the SA: %+v", f.AffectedResources)
	}
	// A generic (non-operator) app SA with cluster-admin is a near-certain
	// over-privilege: Critical, high-but-not-1.0 confidence (the GRANT is a
	// fact, the PROBLEM is workload-dependent).
	if f.Severity != types.SeverityCritical {
		t.Errorf("generic app SA cluster-admin must be Critical, got %q", f.Severity)
	}
	if f.Confidence >= 1.0 || f.Confidence < 0.8 {
		t.Errorf("confidence must reflect problem-certainty (~0.9), not detection-certainty 1.0: %v", f.Confidence)
	}
	if !strings.Contains(f.Title, "Review") {
		t.Errorf("title should invite review, not a blanket replace: %q", f.Title)
	}
	// CRB origin → cluster-wide remediation (scoped ClusterRole + ClusterRoleBinding),
	// NOT a namespace-scoped RoleBinding that would shrink a controller's reach.
	if !strings.Contains(f.RemediationYAML, "fill with the verbs") ||
		!strings.Contains(f.RemediationYAML, "deployer") ||
		!strings.Contains(f.RemediationYAML, "kind: ClusterRoleBinding") {
		t.Errorf("CRB remediation must be a scoped ClusterRole + ClusterRoleBinding skeleton:\n%s", f.RemediationYAML)
	}
	if strings.Contains(f.RemediationYAML, "kind: RoleBinding") {
		t.Errorf("CRB origin must NOT silently downgrade to a namespace-scoped RoleBinding:\n%s", f.RemediationYAML)
	}
	if !strings.Contains(f.RemediationYAML, "DO NOT delete the original") {
		t.Errorf("remediation must warn against deleting the original binding before verification:\n%s", f.RemediationYAML)
	}
}

func TestClusterAdminServiceAccount_RoleBindingGrant(t *testing.T) {
	inv := &collect.Inventory{
		RoleBindings: []rbacv1.RoleBinding{
			rbFixture("team", "ci-admin", "ClusterRole", "cluster-admin", saSubject("team", "ci")),
			rbFixture("team", "normal", "Role", "deployer-role", saSubject("team", "ci")), // Role ref — fine
		},
	}
	fs := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (RoleBinding ci-admin only), got %d: %+v", len(fs), fs)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "RoleBinding") || !strings.Contains(ev, "ServiceAccount team/ci") || !strings.Contains(ev, "cluster-admin") {
		t.Errorf("evidence must name the RoleBinding, the SA, and cluster-admin: %v", fs[0].Evidence)
	}
	// RoleBinding origin keeps the remediation namespace-local — no cluster-wide
	// ClusterRoleBinding (its original scope was a single namespace).
	if !strings.Contains(fs[0].RemediationYAML, "kind: RoleBinding") {
		t.Errorf("RoleBinding origin must stay namespace-scoped:\n%s", fs[0].RemediationYAML)
	}
	if strings.Contains(fs[0].RemediationYAML, "kind: ClusterRoleBinding") {
		t.Errorf("RoleBinding origin must NOT be widened to cluster-wide:\n%s", fs[0].RemediationYAML)
	}
}

// A namespaced Role that merely happens to be NAMED "cluster-admin" is NOT the
// powerful built-in ClusterRole — the Kind==ClusterRole guard is the
// load-bearing check that must keep it out of the findings.
func TestClusterAdminServiceAccount_NamespacedRoleNamedClusterAdmin(t *testing.T) {
	inv := &collect.Inventory{
		RoleBindings: []rbacv1.RoleBinding{
			rbFixture("team", "rb", "Role", "cluster-admin", saSubject("team", "ci")),
		},
	}
	if got := len(ClusterAdminServiceAccount{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("a namespaced Role named 'cluster-admin' (Kind=Role) must NOT be flagged, got %d findings", got)
	}
}

// Well-known platform controllers (Argo CD, Flux, Calico, cert-manager, …)
// legitimately ship cluster-admin grants. They must still surface, but
// down-ranked (High, lower confidence) with a verify-don't-auto-remediate
// caveat — never presented identically to a hand-rolled app SA.
func TestClusterAdminServiceAccount_OperatorDownRank(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("argocd-app-controller", "ClusterRole", "cluster-admin",
				saSubject("argocd", "argocd-application-controller")),
		},
	}
	fs := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("operator SA must still surface as a finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != types.SeverityHigh {
		t.Errorf("known operator SA must be down-ranked to High, got %q", f.Severity)
	}
	if f.Confidence >= 0.8 {
		t.Errorf("known operator SA confidence must be lower than a generic app SA, got %v", f.Confidence)
	}
	blob := strings.ToLower(f.Description + " " + f.WhyItMatters)
	if !strings.Contains(blob, "verify") {
		t.Errorf("operator finding must carry a verify-don't-auto-remediate caveat: %q", f.Description)
	}
}

func TestClusterAdminServiceAccount_SystemNamespaces(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("sys-bind", "ClusterRole", "cluster-admin", saSubject("kube-system", "operator")),
		},
	}
	if got := len(ClusterAdminServiceAccount{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("system-namespace SA subjects must be skipped by default, got %d findings", got)
	}
	if got := len(ClusterAdminServiceAccount{}.Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", got)
	}
}

func TestClusterAdminServiceAccount_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("ca-bind", "ClusterRole", "cluster-admin", saSubject("app", "deployer")),
		},
		RoleBindings: []rbacv1.RoleBinding{
			rbFixture("team", "ca-bind", "ClusterRole", "cluster-admin", saSubject("team", "ci")),
		},
	}
	first := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
	second := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want 2 findings per run (CRB + RB), got %d and %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[1].ID != second[1].ID {
		t.Errorf("IDs must be stable across runs")
	}
	// Same binding name, different kinds — must not collide.
	if first[0].ID == first[1].ID {
		t.Errorf("ClusterRoleBinding and RoleBinding sharing a name collided on ID %q", first[0].ID)
	}
	if !strings.HasPrefix(first[0].ID, "f-") {
		t.Errorf("ID must be f-prefixed: %q", first[0].ID)
	}
}

// THE DOWN-RANK IS NOT FOR SALE BY NAMING. A cluster-admin grant to a ServiceAccount the rule recognises as a
// platform controller is reported at High with "treat as expected … do not auto-remove". It recognised one by
// PREFIX — a namespace beginning "argocd" or "vault", or an SA name beginning "cert-manager" anywhere — and
// down-ranked the whole binding when any one of its subjects matched. So an attacker's cluster-admin SA called
// cert-manager-sync in `default`, or any SA in a namespace called argocd-tools, was presented as expected by
// design. Found in the phase-2 pass over exclusions keyed on names a cluster's own users choose.
func TestClusterAdminServiceAccount_TheDownRankCannotBeBoughtWithAName(t *testing.T) {
	spoofs := map[string]rbacv1.Subject{
		"an operator-like SA name in an ordinary namespace": saSubject("default", "cert-manager-sync"),
		"any SA in a namespace that only begins like one":   saSubject("argocd-tools", "deployer"),
		"a vault-prefixed namespace":                        saSubject("vault-backup", "job"),
	}
	for why, sa := range spoofs {
		inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("b", "ClusterRole", "cluster-admin", sa)}}
		fs := ClusterAdminServiceAccount{}.Evaluate(inv, Options{})
		if len(fs) != 1 || fs[0].Severity != types.SeverityCritical {
			t.Errorf("%s (%s/%s): down-ranked to %v", why, sa.Namespace, sa.Name, fs[0].Severity)
		}
	}
	// One recognised controller does not vouch for the other subject on the same binding.
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("mixed", "ClusterRole", "cluster-admin",
			saSubject("argocd", "argocd-application-controller"), saSubject("team", "ci"))}}
	if fs := (ClusterAdminServiceAccount{}).Evaluate(inv, Options{}); len(fs) != 1 || fs[0].Severity != types.SeverityCritical {
		t.Errorf("a binding with one recognised controller and one app SA was down-ranked")
	}
	// The real controller in its real namespace is still recognised.
	inv = &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("argocd", "ClusterRole", "cluster-admin", saSubject("argocd", "argocd-application-controller"))}}
	if fs := (ClusterAdminServiceAccount{}).Evaluate(inv, Options{}); len(fs) != 1 || fs[0].Severity != types.SeverityHigh {
		t.Errorf("Argo CD's own controller in argocd is no longer recognised")
	}
}
