package collect

import (
	"fmt"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// crb builds a ClusterRoleBinding to a single ServiceAccount subject.
func crb(name, roleRef, saNS, saName string) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleRef},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: saNS, Name: saName}},
	}
}

// rb builds a namespaced RoleBinding to a single ServiceAccount subject.
func rb(name, ns, roleRefKind, roleRef, saName string) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef:    rbacv1.RoleRef{Kind: roleRefKind, Name: roleRef},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: saName}},
	}
}

func TestBuildRBACGraph_ClusterAdminCRB_Critical(t *testing.T) {
	inv := &Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("argocd-application-controller", "cluster-admin", "argocd", "argocd-application-controller"),
		},
	}
	got := buildRBACGraph(inv, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d: %+v", len(got), got)
	}
	e := got[0]
	if e.Risk != "critical" {
		t.Errorf("Risk = %q, want critical", e.Risk)
	}
	if e.Subject != "argocd/argocd-application-controller" {
		t.Errorf("Subject = %q, want argocd/argocd-application-controller", e.Subject)
	}
	if e.Role != "cluster-admin" {
		t.Errorf("Role = %q, want cluster-admin", e.Role)
	}
	if e.Binding != "argocd-application-controller" {
		t.Errorf("Binding = %q, want argocd-application-controller", e.Binding)
	}
	want := "ServiceAccount argocd/argocd-application-controller bound to cluster-admin"
	if e.Description != want {
		t.Errorf("Description = %q, want %q", e.Description, want)
	}
}

func TestBuildRBACGraph_LinksClusterAdminFinding(t *testing.T) {
	inv := &Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("argocd-binding", "cluster-admin", "argocd", "argocd-application-controller"),
		},
	}
	// A finding whose AffectedResources reference the binding + subject, as the
	// real cluster-admin-serviceaccount rule emits.
	findings := []types.Finding{{
		ID:     "F-CA-1",
		RuleID: "k8s.rbac.cluster-admin-serviceaccount",
		AffectedResources: []types.ResourceRef{
			{Kind: "ClusterRoleBinding", Name: "argocd-binding"},
			{Kind: "ServiceAccount", Namespace: "argocd", Name: "argocd-application-controller"},
		},
	}}
	got := buildRBACGraph(inv, findings)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0].FindingIDs, []string{"F-CA-1"}) {
		t.Errorf("FindingIDs = %v, want [F-CA-1]", got[0].FindingIDs)
	}
}

func TestBuildRBACGraph_NoFindingMeansNoFindingIDs(t *testing.T) {
	inv := &Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("view-binding", "view", "team-a", "reader"),
		},
	}
	got := buildRBACGraph(inv, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].FindingIDs != nil {
		t.Errorf("FindingIDs = %v, want nil", got[0].FindingIDs)
	}
}

// The FALLBACK's table. It runs only where there is no body to read, and its asymmetry is deliberate:
// rounding up costs a reader a second, rounding down hides the binding they came for.
func TestBandFromName_Table(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{"cluster-admin", "critical"},
		{"admin", "high"},
		{"edit", "high"},
		{"namespace-admin", "high"},
		{"custom-editor", "high"},
		{"writer", "high"},
		{"view", "low"}, // the built-in, whose rules Kubernetes defines

		// A CUSTOM name containing "view"/"read" may NOT be downgraded to low. The name is chosen by whoever
		// authored the role and says nothing about its rules: a ClusterRole called "prod-readonly-viewer" can
		// grant `secrets: list`. Where the body is unreadable the honest answer for an unrecognised name is
		// "unknown", never "low". TestBandFromRules_Table below shows what the same role reads as once the
		// body IS in the snapshot — which is the whole reason the join exists.
		{"read-only-viewer", "medium"},
		{"readonly", "medium"},
		{"some-reader", "medium"},
		{"prod-readonly-viewer", "medium"},

		{"prometheus-operator", "medium"},
		{"my-custom-role", "medium"},
		{"CLUSTER-ADMIN", "critical"}, // case-insensitive
	}
	for _, c := range cases {
		if got := bandFromName(rbacv1.RoleRef{Kind: "ClusterRole", Name: c.role}); got != c.want {
			t.Errorf("bandFromName(%q) = %q, want %q", c.role, got, c.want)
		}
	}
}

// The band a role's own rules justify. Every case here is arithmetic over a declaration.
func TestBandFromRules_Table(t *testing.T) {
	rule := func(groups, resources, verbs []string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: groups, Resources: resources, Verbs: verbs}
	}
	all := []string{"*"}
	core := []string{""}
	cases := []struct {
		name  string
		rules []rbacv1.PolicyRule
		want  string
	}{
		{"cluster-admin's own shape", []rbacv1.PolicyRule{rule(all, all, all)}, "critical"},
		{"escalate", []rbacv1.PolicyRule{rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"})}, "critical"},
		{"bind", []rbacv1.PolicyRule{rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"})}, "critical"},
		{"impersonate", []rbacv1.PolicyRule{rule(core, []string{"users"}, []string{"impersonate"})}, "critical"},

		// The case the name could never answer, and the reason for the join.
		{"reads Secrets", []rbacv1.PolicyRule{rule(core, []string{"secrets"}, []string{"get", "list"})}, "high"},
		{"reads every core resource", []rbacv1.PolicyRule{rule(core, all, []string{"get", "list", "watch"})}, "high"},
		{"writes ConfigMaps", []rbacv1.PolicyRule{rule(core, []string{"configmaps"}, []string{"create", "update"})}, "high"},
		{"every verb on one resource", []rbacv1.PolicyRule{rule([]string{"apps"}, []string{"deployments"}, all)}, "high"},

		{"reads Pods only", []rbacv1.PolicyRule{rule(core, []string{"pods"}, []string{"get", "list", "watch"})}, "low"},
		{"grants nothing", nil, "low"},
		// A rule with only nonResourceURLs names no resource; its verbs must not be read as object access.
		{"health endpoints only", []rbacv1.PolicyRule{{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}}}, "low"},

		// Three rules that between them name everything are an operator's generated role, not cluster-admin.
		// The unrestricted branch reads ONE rule, so this is high (it writes), never critical.
		{"a union nobody wrote", []rbacv1.PolicyRule{
			rule(all, []string{"pods"}, []string{"get"}),
			rule([]string{"apps"}, all, []string{"get"}),
			rule([]string{"batch"}, []string{"jobs"}, []string{"create"}),
		}, "high"},
	}
	for _, c := range cases {
		if got := bandFromRules(c.rules); got != c.want {
			t.Errorf("bandFromRules(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

// A band read from a role and a band guessed from its name are different claims, and the entry says which.
func TestClassifyRBACRisk_BasisSaysWhereTheBandCameFrom(t *testing.T) {
	ref := rbacv1.RoleRef{Kind: "ClusterRole", Name: "prod-readonly-viewer"}
	body := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}}

	// The body is in the reading: arithmetic, and the name's "medium" is overruled by what it grants.
	if band, basis := classifyRBACRisk(ref, body, true, true); band != "high" || basis != riskBasisRules {
		t.Errorf("with the body: got %q/%q, want high/%s", band, basis, riskBasisRules)
	}
	// The kind was refused: there is nothing to read, so the band is the name's guess and says so.
	if band, basis := classifyRBACRisk(ref, nil, false, false); band != "medium" || basis != riskBasisName {
		t.Errorf("kind refused: got %q/%q, want medium/%s", band, basis, riskBasisName)
	}
	// The kind was read and this roleRef was not in it: a different fact from a refusal, and a different word.
	if band, basis := classifyRBACRisk(ref, nil, false, true); band != "medium" || basis != riskBasisUnresolved {
		t.Errorf("roleRef not found: got %q/%q, want medium/%s", band, basis, riskBasisUnresolved)
	}
}

// End to end: the graph joins each binding to the role it names, and a refused role kind degrades to the
// name-based guess rather than to an empty body read as "grants nothing".
func TestBuildRBACGraph_JoinsBindingsToRoleBodies(t *testing.T) {
	quiet := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-readonly-viewer"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}},
	}
	inv := &Inventory{
		ClusterRoles:        []rbacv1.ClusterRole{quiet},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{crb("viewer-binding", "prod-readonly-viewer", "apps", "reader")},
		Meta:                Meta{Collected: []string{"clusterroles", "roles"}},
	}
	got := buildRBACGraph(inv, nil)
	if len(got) != 1 {
		t.Fatalf("want one entry, got %d", len(got))
	}
	if got[0].Risk != "high" || got[0].RiskBasis != riskBasisRules {
		t.Errorf("a role that lists Secrets read as %q (%s); its name alone would have said medium",
			got[0].Risk, got[0].RiskBasis)
	}

	// THE SAME CLUSTER, WITH THE ROLE KIND REFUSED. An empty ClusterRoles slice must not be read as "the role
	// grants nothing" — that is the failure mode this whole codebase exists to avoid.
	denied := &Inventory{
		ClusterRoleBindings: inv.ClusterRoleBindings,
		Meta:                Meta{Denied: []string{"clusterroles: forbidden"}},
	}
	got = buildRBACGraph(denied, nil)
	if len(got) != 1 {
		t.Fatalf("want one entry, got %d", len(got))
	}
	if got[0].Risk != "medium" || got[0].RiskBasis != riskBasisName {
		t.Errorf("a refused role kind produced %q (%s), want medium/%s — a denial is not an empty role",
			got[0].Risk, got[0].RiskBasis, riskBasisName)
	}
}

func TestBuildRBACGraph_DeterministicOrder_RiskThenSystemLast(t *testing.T) {
	inv := &Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			crb("z-low", "view", "team-a", "reader"),                         // low, non-system
			crb("kube-system-admin", "cluster-admin", "kube-system", "boot"), // critical, system → after non-system critical
			crb("a-critical", "cluster-admin", "argocd", "ctrl"),             // critical, non-system
			crb("m-high", "admin", "team-b", "ops"),                          // high, non-system
		},
	}
	got := buildRBACGraph(inv, nil)
	gotOrder := make([]string, len(got))
	for i, e := range got {
		gotOrder[i] = e.Binding
	}
	want := []string{"a-critical", "kube-system-admin", "m-high", "z-low"}
	if !reflect.DeepEqual(gotOrder, want) {
		t.Errorf("order = %v, want %v", gotOrder, want)
	}

	// Determinism: a second run on the same input yields the same order.
	again := buildRBACGraph(inv, nil)
	if !reflect.DeepEqual(got, again) {
		t.Errorf("non-deterministic: %v vs %v", got, again)
	}
}

func TestBuildRBACGraph_Cap12_DropsLowestRisk(t *testing.T) {
	inv := &Inventory{}
	// 12 critical CRBs + 5 low ones; only the 12 criticals should survive.
	for i := 0; i < 12; i++ {
		inv.ClusterRoleBindings = append(inv.ClusterRoleBindings,
			crb(fmt.Sprintf("crit-%02d", i), "cluster-admin", "ns", fmt.Sprintf("sa-%02d", i)))
	}
	for i := 0; i < 5; i++ {
		inv.ClusterRoleBindings = append(inv.ClusterRoleBindings,
			crb(fmt.Sprintf("low-%02d", i), "view", "ns", fmt.Sprintf("v-%02d", i)))
	}
	got := buildRBACGraph(inv, nil)
	if len(got) != 12 {
		t.Fatalf("want cap of 12, got %d", len(got))
	}
	for _, e := range got {
		if e.Risk != "critical" {
			t.Errorf("cap dropped a critical and kept %q (%s)", e.Risk, e.Binding)
		}
	}
}

func TestBuildRBACGraph_SubjectFormats(t *testing.T) {
	inv := &Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "user-binding"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice@example.com"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "sa-no-ns"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "buildbot"}}, // no namespace
			},
		},
	}
	got := buildRBACGraph(inv, nil)
	bySubj := map[string]types.RBACEntry{}
	for _, e := range got {
		bySubj[e.Binding] = e
	}
	if s := bySubj["user-binding"].Subject; s != "User/alice@example.com" {
		t.Errorf("user subject = %q, want User/alice@example.com", s)
	}
	if s := bySubj["sa-no-ns"].Subject; s != "default/buildbot" {
		t.Errorf("SA-without-ns subject = %q, want default/buildbot", s)
	}
}

func TestBuildRBACGraph_RoleBindingScopedClusterAdmin(t *testing.T) {
	inv := &Inventory{
		RoleBindings: []rbacv1.RoleBinding{
			rb("ns-admin", "payments", "ClusterRole", "cluster-admin", "deployer"),
		},
	}
	got := buildRBACGraph(inv, nil)
	if len(got) != 1 || got[0].Risk != "critical" {
		t.Fatalf("want one critical entry, got %+v", got)
	}
	if got[0].Subject != "payments/deployer" {
		t.Errorf("Subject = %q, want payments/deployer", got[0].Subject)
	}
}

func TestDeriveHighlights_Counts_AndZeroOmitted(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "k8s.rbac.cluster-admin-serviceaccount", Severity: types.SeverityCritical},
		{RuleID: "k8s.rbac.cluster-admin-serviceaccount", Severity: types.SeverityCritical},
		{RuleID: "k8s.workload.privileged-host-access", Severity: types.SeverityHigh},
		{RuleID: "k8s.workload.single-replica-no-pdb", Severity: types.SeverityMedium},
		{RuleID: "k8s.workload.no-probes", Severity: types.SeverityLow},
		// pdb-blocks-drains intentionally absent → its tile must be omitted.
	}
	hs := deriveHighlights(findings)

	byKey := map[string]types.Highlight{}
	for _, h := range hs {
		byKey[h.Section+"|"+h.Label] = h
	}

	// security: Critical findings = 2 (the two critical-severity findings).
	if h, ok := byKey["security|Critical findings"]; !ok || h.Value != "2" || h.Tone != "critical" {
		t.Errorf("Critical findings tile = %+v (ok=%v), want value 2 tone critical", h, ok)
	}
	if h, ok := byKey["security|Cluster-admin ServiceAccounts"]; !ok || h.Value != "2" || h.Tone != "critical" {
		t.Errorf("Cluster-admin SA tile = %+v (ok=%v), want value 2 tone critical", h, ok)
	}
	if h, ok := byKey["security|Privileged workloads"]; !ok || h.Value != "1" {
		t.Errorf("Privileged workloads tile = %+v (ok=%v), want value 1", h, ok)
	}
	if h, ok := byKey["reliability|Single points of failure"]; !ok || h.Value != "1" {
		t.Errorf("SPOF tile = %+v (ok=%v), want value 1", h, ok)
	}
	if h, ok := byKey["reliability|Workloads without probes"]; !ok || h.Value != "1" {
		t.Errorf("no-probes tile = %+v (ok=%v), want value 1", h, ok)
	}
	// Zero-value tile omitted entirely.
	if _, ok := byKey["reliability|Drain-blocking PDBs"]; ok {
		t.Errorf("Drain-blocking PDBs tile should be omitted when count is 0")
	}
}

func TestDeriveHighlights_NoFindings_NoTiles(t *testing.T) {
	if hs := deriveHighlights(nil); len(hs) != 0 {
		t.Errorf("want no tiles for no findings, got %v", hs)
	}
}

func TestDeriveHighlights_CapThreePerSection(t *testing.T) {
	// All three security rules and all three reliability rules fire → exactly
	// 3 per section, 6 total. (No section has more than 3 candidate tiles, so
	// the cap is also a "no extra tiles" assertion.)
	findings := []types.Finding{
		{RuleID: "k8s.rbac.cluster-admin-serviceaccount", Severity: types.SeverityCritical},
		{RuleID: "k8s.workload.privileged-host-access", Severity: types.SeverityHigh},
		{RuleID: "k8s.workload.single-replica-no-pdb", Severity: types.SeverityMedium},
		{RuleID: "k8s.workload.no-probes", Severity: types.SeverityLow},
		{RuleID: "k8s.reliability.pdb-blocks-drains", Severity: types.SeverityMedium},
	}
	hs := deriveHighlights(findings)
	counts := map[string]int{}
	for _, h := range hs {
		counts[h.Section]++
	}
	if counts["security"] > 3 {
		t.Errorf("security tiles = %d, want <= 3", counts["security"])
	}
	if counts["reliability"] > 3 {
		t.Errorf("reliability tiles = %d, want <= 3", counts["reliability"])
	}
}

func TestBuildReport_WiresRBACAndHighlights(t *testing.T) {
	inv := twoM6iLargeEKS()
	inv.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		crb("argocd-binding", "cluster-admin", "argocd", "argocd-application-controller"),
	}
	findings := []types.Finding{{
		ID:       "F-CA-1",
		RuleID:   "k8s.rbac.cluster-admin-serviceaccount",
		Severity: types.SeverityCritical,
		AffectedResources: []types.ResourceRef{
			{Kind: "ClusterRoleBinding", Name: "argocd-binding"},
			{Kind: "ServiceAccount", Namespace: "argocd", Name: "argocd-application-controller"},
		},
	}}
	ar := BuildReport(inv, findings, "c", 0, pricing.Embedded())
	if len(ar.Architecture.RBAC) != 1 {
		t.Fatalf("Architecture.RBAC not populated: %+v", ar.Architecture.RBAC)
	}
	if len(ar.Highlights) == 0 {
		t.Fatalf("Highlights not populated")
	}
}
