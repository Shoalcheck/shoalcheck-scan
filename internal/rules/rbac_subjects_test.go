package rules

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func crb(name, roleName string, subs ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
		Subjects:   subs,
	}
}

// bootstrapCRB is a binding carrying the label the API server's bootstrap policy writes and reconciles.
func bootstrapCRB(name, roleName string, subs ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	b := crb(name, roleName, subs...)
	b.Labels = map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	return b
}

// labelledCRB carries labels that are not the bootstrap marker.
func labelledCRB(name, roleName string, labels map[string]string, subs ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	b := crb(name, roleName, subs...)
	b.Labels = labels
	return b
}

func rb(name, ns, roleKind, roleName string, subs ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{Kind: roleKind, Name: roleName},
		Subjects:   subs,
	}
}

// A BINDING THAT NAMES A SUBJECT NOBODY SHOULD BE BINDING.
//
// Four subjects, and each is a different sentence. `system:masters` bypasses authorization entirely — the
// API server hard-codes it above RBAC — so a binding to it is a signal rather than the grant. `system:anonymous`
// and `system:unauthenticated` reach callers who presented no credential at all. `system:authenticated`
// reaches every identity in the cluster, which includes every ServiceAccount in every namespace.
//
// docs/qa/2026-08-31-provider-benchmark-measurement.md names these as GKE 4.1.6 and 4.1.8–4.1.10 and calls
// them the second most valuable unbuilt group. They are checks over bindings this reading already collects.
func TestRBACBuiltinSubject(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("break-glass", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:masters"}),
			crb("public-read", "view", rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}),
			crb("everyone-view", "view", rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
			// A normal binding is not a finding.
			crb("ops", "edit", rbacv1.Subject{Kind: "Group", Name: "platform-team"}),
			// THE BINDINGS KUBERNETES WRITES FOR ITSELF. Without this exclusion the rule fires six times on
			// every cluster in the world — measured on a live one: cluster-admin to system:masters,
			// system:discovery and system:basic-user to system:authenticated, system:public-info-viewer to
			// system:unauthenticated. The label is the object's own statement about who created it.
			bootstrapCRB("cluster-admin", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:masters"}),
			bootstrapCRB("system:discovery", "system:discovery", rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
			// LABELLED, AND NOT THE API SERVER'S. Helm labels everything it installs, so "carries a label"
			// and "Kubernetes wrote it" are different questions; a rule that confused them would go silent
			// on every chart-installed binding in the cluster.
			labelledCRB("chart-public-read", "view",
				map[string]string{"app.kubernetes.io/managed-by": "Helm", "helm.sh/chart": "portal-1.2.3"},
				rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}),
		},
		RoleBindings: []rbacv1.RoleBinding{
			rb("anon-in-one-ns", "sandbox", "Role", "reader",
				rbacv1.Subject{Kind: "User", Name: "system:anonymous"}),
		},
		Meta: collect.Meta{Collected: []string{"clusterrolebindings", "rolebindings"}},
	}

	fs := RBACBuiltinSubject{}.Evaluate(inv, Options{})
	by := map[string]types.Finding{}
	for _, f := range fs {
		by[f.AffectedResources[0].Name] = f
	}
	if len(fs) != 5 {
		t.Fatalf("want 5 findings, got %d: %v", len(fs), names(fs))
	}
	if _, ok := by["chart-public-read"]; !ok {
		t.Error("a Helm-labelled binding to system:unauthenticated was not reported: carrying a label is " +
			"not the same as having been written by the API server's bootstrap policy")
	}
	if _, ok := by["ops"]; ok {
		t.Error("a binding to an ordinary group is not a finding")
	}
	for _, def := range []string{"cluster-admin", "system:discovery"} {
		if _, ok := by[def]; ok {
			t.Errorf("%s carries kubernetes.io/bootstrapping=rbac-defaults and was still reported: the "+
				"objects Kubernetes writes at startup are on every cluster, and a rule that reports them "+
				"reports nothing about anybody's", def)
		}
	}

	// SCOPE DECIDES SEVERITY, except where the subject is not scoped by the binding at all.
	if got := by["break-glass"].Severity; got != types.SeverityHigh {
		t.Errorf("system:masters cluster-wide is %q, want high", got)
	}
	if got := by["anon-in-one-ns"].Severity; got != types.SeverityMedium {
		t.Errorf("system:anonymous inside one namespace is %q, want medium — the scope bounds it and the "+
			"subject does not stop being unauthenticated", got)
	}
	if a, b := by["public-read"].Severity, by["everyone-view"].Severity; a == b {
		t.Errorf("unauthenticated and authenticated are the same severity (%q): one reaches callers with no "+
			"credential and the other reaches every ServiceAccount, and those are different facts", a)
	}

	// THE FINDING NAMES THE BINDING, THE SUBJECT AND WHAT THE BINDING POINTS AT — never what anybody can do.
	m := by["break-glass"]
	ev := strings.Join(m.Evidence, " | ")
	for _, want := range []string{"break-glass", "system:masters", "cluster-admin"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence does not name %q: %s", want, ev)
		}
	}
	if m.RemediationCommand != "" || m.RemediationYAML != "" {
		t.Error("an RBAC finding must offer no mechanical change: removing a grant is a decision about who " +
			"needs what, and this tool cannot see who depends on it")
	}
	if m.DollarImpactMonthly != 0 {
		t.Error("a permission has no price")
	}

	// AND THE ABSENCE OF A BINDING IS NOT THE ABSENCE OF THE GROUP.
	all := strings.Join(m.ClaimBoundaries, " ") + " " + m.WhyItMatters + " " + m.Description
	if !strings.Contains(all, "certificate") {
		t.Errorf("nothing says a client certificate carrying O=system:masters is invisible to an API-only "+
			"reading, which is the one thing that stops this being read as a complete answer: %s", all)
	}
}

// A DENIED BINDING READ IS NOT A CLUSTER WITH NO SUCH BINDINGS.
func TestRBACBuiltinSubject_SilentWhenBindingsWereNotCollected(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("break-glass", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:masters"}),
		},
		Meta: collect.Meta{Denied: []string{"clusterrolebindings: forbidden"}},
	}
	if fs := (RBACBuiltinSubject{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a run that could not list bindings produced %d finding(s)", len(fs))
	}
}

// CLUSTER-ADMIN TO EVERYBODY IS CRITICAL. Bound to system:authenticated it is every identity the authenticator
// accepts, every ServiceAccount included; to system:unauthenticated or system:anonymous it is anyone who can reach the
// API server. Either is full control handed out, whatever the scope says — a RoleBinding of it in kube-system reads
// every controller's token. The same subjects bound to any other role keep their severities, and system:masters,
// which already does everything, stays high.
func TestRBACBuiltinSubject_ClusterAdminToEverybodyIsCritical(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("everyone-admin", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
			crb("public-admin", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}),
			crb("anon-admin", "cluster-admin", rbacv1.Subject{Kind: "User", Name: "system:anonymous"}),
			crb("break-glass", "cluster-admin", rbacv1.Subject{Kind: "Group", Name: "system:masters"}),
			crb("everyone-view", "view", rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
		},
		RoleBindings: []rbacv1.RoleBinding{
			rb("everyone-admin-here", "kube-system", "ClusterRole", "cluster-admin",
				rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
			rb("everyone-reads-here", "sandbox", "ClusterRole", "view",
				rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
			// A namespaced Role that happens to be called cluster-admin is not the built-in ClusterRole.
			rb("local-admin", "sandbox", "Role", "cluster-admin", rbacv1.Subject{Kind: "User", Name: "system:anonymous"}),
		},
		Meta: collect.Meta{Collected: []string{"clusterrolebindings", "rolebindings"}},
	}
	by := map[string]types.Severity{}
	for _, f := range (RBACBuiltinSubject{}).Evaluate(inv, Options{}) {
		by[f.AffectedResources[0].Name] = f.Severity
	}
	for name, want := range map[string]types.Severity{
		"everyone-admin": types.SeverityCritical, "public-admin": types.SeverityCritical,
		"anon-admin": types.SeverityCritical, "everyone-admin-here": types.SeverityCritical,
		"break-glass": types.SeverityHigh, "everyone-view": types.SeverityMedium,
		"everyone-reads-here": types.SeverityLow, "local-admin": types.SeverityMedium,
	} {
		if got, ok := by[name]; !ok || got != want {
			t.Errorf("%s: severity %q (reported %v), want %q", name, got, ok, want)
		}
	}
}
