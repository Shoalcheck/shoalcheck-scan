package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// rbac_cluster_admin_user_test.go — A USER OR A GROUP BOUND TO CLUSTER-ADMIN IS A FINDING.
//
// QA, v0.1.1 (defect 5): a ClusterRoleBinding granting cluster-admin to `User alice` produced no finding and did
// not fail `shoalcheck gate`, because the only rule that named the grant read ServiceAccount subjects. CIS 5.1.1 —
// "cluster-admin is only used where required" — is about every subject, and the compliance row mapped it to that
// rule alone. The rule is looked up in the registry rather than named as a type, so these tests also fail on a
// build that has the type and never runs it.

const clusterAdminUserRule = "k8s.rbac.cluster-admin-user-or-group"

func registeredRule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("no rule %s is registered, so a User or a Group bound to cluster-admin is judged by nothing", id)
	return nil
}

func userSubject(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: name}
}

func groupSubject(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: name}
}

func hasRef(refs []types.ResourceRef, kind, ns, name string) bool {
	for _, r := range refs {
		if r.Kind == kind && r.Namespace == ns && r.Name == name {
			return true
		}
	}
	return false
}

func TestClusterAdminUserOrGroup_AUserIsAFinding(t *testing.T) {
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("alice-admin", "ClusterRole", "cluster-admin", userSubject("alice")),
	}}
	fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for User alice bound to cluster-admin, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != clusterAdminUserRule || f.Severity != types.SeverityHigh || f.Category != types.CategorySecurity {
		t.Errorf("rule %q severity %q category %q; want %s, high, security", f.RuleID, f.Severity, f.Category, clusterAdminUserRule)
	}
	if !strings.Contains(f.Title, "User alice") {
		t.Errorf("the title does not name the subject: %q", f.Title)
	}
	if want := "ClusterRoleBinding alice-admin: User alice -> cluster-admin"; len(f.Evidence) == 0 || f.Evidence[0] != want {
		t.Errorf("evidence %v; want first line %q", f.Evidence, want)
	}
	// The binding is what an operator edits; the subject is named as a structured ref so --redact tokenizes a
	// person's name wherever the finding prints it.
	if !hasRef(f.AffectedResources, "ClusterRoleBinding", "", "alice-admin") || !hasRef(f.AffectedResources, "User", "", "alice") {
		t.Errorf("affected resources %+v; want the binding and User alice", f.AffectedResources)
	}
	if f.IDBasis == nil || f.IDBasis.Kind != "ClusterRoleBinding" || f.IDBasis.Name != "alice-admin" {
		t.Errorf("the id is not the binding's: %+v", f.IDBasis)
	}
	// Stable across two readings of the same cluster.
	again := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
	if len(again) != 1 || again[0].ID != f.ID {
		t.Errorf("the id moved between two evaluations of one inventory: %s, %+v", f.ID, again)
	}
}

func TestClusterAdminUserOrGroup_AGroupIsAFinding(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("platform-admins", "ClusterRole", "cluster-admin", groupSubject("platform-admins")),
			crbFixture("sre-admins", "ClusterRole", "cluster-admin", groupSubject("sre")),
		},
		RoleBindings: []rbacv1.RoleBinding{
			rbFixture("payments", "oncall-admin", "ClusterRole", "cluster-admin", groupSubject("payments-oncall")),
		},
	}
	fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
	if len(fs) != 3 {
		t.Fatalf("want 3 findings (two Groups cluster-wide, one inside payments), got %d: %+v", len(fs), fs)
	}
	byBinding := map[string]types.Finding{}
	for _, f := range fs {
		byBinding[f.AffectedResources[0].Name] = f
		if f.Severity != types.SeverityHigh {
			t.Errorf("%s: severity %q, want high", f.Title, f.Severity)
		}
	}
	if f := byBinding["platform-admins"]; !strings.Contains(f.Title, "Group platform-admins") ||
		!hasRef(f.AffectedResources, "Group", "", "platform-admins") {
		t.Errorf("the Group is not named: %q, %+v", f.Title, f.AffectedResources)
	}
	if f := byBinding["oncall-admin"]; !strings.Contains(f.Description, "namespace payments") ||
		!hasRef(f.AffectedResources, "RoleBinding", "payments", "oncall-admin") {
		t.Errorf("a RoleBinding's grant does not say it is scoped to its namespace: %q, %+v", f.Description, f.AffectedResources)
	}
}

// THE PLATFORM'S OWN BINDING IS NOT A FINDING — WHERE THE READING SHOWS THE PLATFORM. kubeadm (1.29 and later)
// binds cluster-admin to the group its admin.conf certificate carries, on every kubeadm cluster — read in the bench's
// kind capture, beside kubeadm's API server pod. A high finding on every such cluster is noise. A binding of that
// name to anybody else is a customer's grant wearing kubeadm's name, and is reported.
func TestClusterAdminUserOrGroup_ThePlatformsOwnBindingIsNotReported(t *testing.T) {
	kubeadmBinding := crbFixture("kubeadm:cluster-admins", "ClusterRole", "cluster-admin", groupSubject("kubeadm:cluster-admins"))
	inv := kubeadmShaped()
	inv.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{kubeadmBinding}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("kubeadm's own kubeadm:cluster-admins binding was reported on a kubeadm cluster: %+v", fs)
	}
	for name, subs := range map[string][]rbacv1.Subject{
		"another subject":   {userSubject("mallory")},
		"one more subject":  {groupSubject("kubeadm:cluster-admins"), userSubject("mallory")},
		"a User, same name": {userSubject("kubeadm:cluster-admins")},
	} {
		inv := kubeadmShaped()
		inv.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
			crbFixture("kubeadm:cluster-admins", "ClusterRole", "cluster-admin", subs...),
		}
		if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 1 {
			t.Errorf("%s: kubeadm's binding name with %v produced %d findings, want 1 — the name alone is not the platform's", name, subs, len(fs))
		}
	}
	// And the platform's subject under another name is another grant.
	other := kubeadmShaped()
	other.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		crbFixture("acme-admins", "ClusterRole", "cluster-admin", groupSubject("kubeadm:cluster-admins")),
	}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(other, Options{}); len(fs) != 1 {
		t.Errorf("a second binding of kubeadm's group under another name produced %d findings, want 1", len(fs))
	}
}

// NOT KUBEADM, NOT EXCLUDED (security review of 8b430348). On a managed cluster whose groups come from an identity
// provider, anybody who names a group can name it kubeadm:cluster-admins, and a binding of that shape dropped out of
// the reading. It is excluded only where the reading itself shows kubeadm's control plane; elsewhere it is reported
// at the rule's severity, and its evidence says it matches kubeadm's binding.
func TestClusterAdminUserOrGroup_KubeadmsBindingIsReportedWhereTheReadingShowsNoKubeadm(t *testing.T) {
	kubeadmBinding := crbFixture("kubeadm:cluster-admins", "ClusterRole", "cluster-admin", groupSubject("kubeadm:cluster-admins"))
	notKubeadm := map[string]*collect.Inventory{
		"eks":       providerShaped("aws:///eu-central-1a/i-0abc"),
		"aks":       providerShaped("azure:///subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/pool/virtualMachines/0"),
		"no pods":   {},
		"lookalike": kubeadmShaped(),
	}
	// Every object kubeadm's mark is made of, and no mark: objects a pull request supplies, laid over a reading, or a
	// replay whose live collection never set it. The rule reads the live collection's mark and nothing else.
	notKubeadm["lookalike"].KubeadmControlPlane = false
	for name, inv := range notKubeadm {
		inv.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{kubeadmBinding}
		fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
		if len(fs) != 1 {
			t.Errorf("%s: kubeadm's binding on a reading that shows no kubeadm control plane produced %d findings, want 1", name, len(fs))
			continue
		}
		if fs[0].Severity != types.SeverityHigh {
			t.Errorf("%s: severity %q, want the rule's own high", name, fs[0].Severity)
		}
		if !strings.Contains(strings.Join(fs[0].Evidence, " | "), "matches the binding kubeadm writes") {
			t.Errorf("%s: the evidence does not say the binding matches kubeadm's own: %v", name, fs[0].Evidence)
		}
	}
}

// kubeadmShaped is a live reading of a kubeadm control plane as the bench's kind capture holds it — the API server's
// mirror pod in kube-system, owned by its control-plane Node, carrying the annotation kubeadm writes into the static
// pod manifest — with the mark the collector sets from them (internal/collect/kubeadm.go).
func kubeadmShaped() *collect.Inventory {
	return &collect.Inventory{
		KubeadmControlPlane: true,
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "cp-0", UID: "u-1",
			Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}}},
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kube-apiserver-cp-0",
			Annotations:     map[string]string{"kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint": "172.18.0.5:6443"},
			Labels:          map[string]string{"component": "kube-apiserver", "tier": "control-plane"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: "cp-0", UID: "u-1"}},
		}}},
	}
}

// providerShaped is a managed cluster's reading: worker nodes with the provider's id, and no control-plane pod.
func providerShaped(providerID string) *collect.Inventory {
	return &collect.Inventory{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-0"}, Spec: corev1.NodeSpec{ProviderID: providerID}}},
		Pods:  []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns-5d78c9869d-abcde"}}},
	}
}

// A ROLEBINDING IN A SYSTEM NAMESPACE IS REPORTED BY DEFAULT. cluster-admin inside kube-system reads every
// controller's ServiceAccount token there, which is most of the way to the whole cluster; the namespace exclusion the
// workload rules use is about noise from a distribution's own pods, and a grant to a person is not that.
func TestClusterAdminUserOrGroup_ARoleBindingInASystemNamespaceIsReported(t *testing.T) {
	inv := &collect.Inventory{RoleBindings: []rbacv1.RoleBinding{
		rbFixture("kube-system", "alice-kube-system", "ClusterRole", "cluster-admin", userSubject("alice")),
	}}
	fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
	if len(fs) != 1 || !hasRef(fs[0].AffectedResources, "RoleBinding", "kube-system", "alice-kube-system") {
		t.Fatalf("a User granted cluster-admin inside kube-system was not reported without --include-system: %+v", fs)
	}
}

// EVERY SERVICEACCOUNT IS A GROUP, and it is the ServiceAccount rule's reason for critical many times over: each
// pod's token holds the grant.
func TestClusterAdminUserOrGroup_TheServiceAccountGroupsAreCritical(t *testing.T) {
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("every-sa-admin", "ClusterRole", "cluster-admin", groupSubject("system:serviceaccounts")),
		crbFixture("shop-sa-admin", "ClusterRole", "cluster-admin", groupSubject("system:serviceaccounts:shop")),
	}}
	fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Severity != types.SeverityCritical {
			t.Errorf("%s: severity %q; a group of ServiceAccounts holding cluster-admin is every such pod's token", f.Title, f.Severity)
		}
	}
}

// THE BINDING KUBERNETES WRITES FOR ITSELF IS NOT A FINDING — the label AND the exact upstream tuple.
func TestClusterAdminUserOrGroup_TheBootstrapBindingIsNotReported(t *testing.T) {
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		bootstrapCRB("cluster-admin", "cluster-admin", groupSubject("system:masters")),
	}}
	inv.Meta.Collected = []string{"clusterrolebindings", "rolebindings"}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("the API server's own cluster-admin binding was reported: %+v", fs)
	}
	if fs := (RBACBuiltinSubject{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("binding-to-builtin-subject reported the bootstrap binding: %+v", fs)
	}
}

// ONE OBJECT, ONE STORY. A binding to system:masters, system:anonymous, system:unauthenticated or
// system:authenticated is binding-to-builtin-subject's to report, and it says something this rule cannot — who
// holds the subject is decided outside RBAC. A second finding on the same binding would argue a different thing.
// The persona's acme-break-glass is the first case.
func TestClusterAdminUserOrGroup_ABuiltInSubjectIsTheOtherRulesToReport(t *testing.T) {
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("acme-break-glass", "ClusterRole", "cluster-admin", groupSubject("system:masters")),
		crbFixture("everyone-admin", "ClusterRole", "cluster-admin", groupSubject("system:authenticated")),
		crbFixture("anon-admin", "ClusterRole", "cluster-admin", userSubject("system:anonymous")),
		crbFixture("unauth-admin", "ClusterRole", "cluster-admin", groupSubject("system:unauthenticated")),
	}}
	inv.Meta.Collected = []string{"clusterrolebindings", "rolebindings"}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 0 {
		var titles []string
		for _, f := range fs {
			titles = append(titles, f.Title)
		}
		t.Errorf("a built-in subject was reported by this rule as well: %v", titles)
	}
	if fs := (RBACBuiltinSubject{}).Evaluate(inv, Options{}); len(fs) != 4 {
		t.Errorf("binding-to-builtin-subject reported %d of the 4 bindings; this rule defers to it", len(fs))
	}
}

// A SERVICEACCOUNT STAYS THE SERVICEACCOUNT RULE'S, and a binding naming both kinds is reported by each rule for
// its own subjects only.
func TestClusterAdminUserOrGroup_AServiceAccountIsReportedOnlyByTheServiceAccountRule(t *testing.T) {
	inv := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("deployer-admin", "ClusterRole", "cluster-admin", saSubject("shop", "deployer")),
	}}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a ServiceAccount was reported by the User/Group rule: %+v", fs)
	}
	if fs := (ClusterAdminServiceAccount{}).Evaluate(inv, Options{}); len(fs) != 1 || fs[0].Severity != types.SeverityCritical {
		t.Errorf("the ServiceAccount rule no longer reports its own subject: %+v", fs)
	}

	mixed := &collect.Inventory{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
		crbFixture("mixed-admin", "ClusterRole", "cluster-admin", saSubject("shop", "deployer"), userSubject("bob")),
	}}
	users := registeredRule(t, clusterAdminUserRule).Evaluate(mixed, Options{})
	sas := ClusterAdminServiceAccount{}.Evaluate(mixed, Options{})
	if len(users) != 1 || len(sas) != 1 {
		t.Fatalf("want one finding from each rule, got %d user/group and %d ServiceAccount", len(users), len(sas))
	}
	if hasRef(users[0].AffectedResources, "ServiceAccount", "shop", "deployer") || !hasRef(users[0].AffectedResources, "User", "", "bob") {
		t.Errorf("the User/Group finding names the wrong subjects: %+v", users[0].AffectedResources)
	}
	if hasRef(sas[0].AffectedResources, "User", "", "bob") {
		t.Errorf("the ServiceAccount finding names the User: %+v", sas[0].AffectedResources)
	}
}

func TestClusterAdminUserOrGroup_OnlyTheBuiltInClusterRole(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crbFixture("alice-view", "ClusterRole", "view", userSubject("alice")),
		},
		RoleBindings: []rbacv1.RoleBinding{
			// A namespaced Role that happens to be called cluster-admin is not the built-in ClusterRole.
			rbFixture("shop", "local-admin", "Role", "cluster-admin", userSubject("alice")),
		},
	}
	if fs := registeredRule(t, clusterAdminUserRule).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a binding to another role was reported: %+v", fs)
	}
}
