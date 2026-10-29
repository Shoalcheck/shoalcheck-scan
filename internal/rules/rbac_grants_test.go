package rules

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// bannedGrantPhrases — EVERY ONE OF THESE ASSERTS THE UNION THIS SNAPSHOT CANNOT COMPUTE.
//
// What a subject can actually do is the union over every binding that names it, INCLUDING bindings that
// name a Group it belongs to (system:authenticated, system:serviceaccounts, system:serviceaccounts:<ns>) —
// and group membership of a real user is decided by the authenticator: an OIDC token's claims, an AWS IAM
// mapping, a client certificate's O=. None of that is in the snapshot.
//
// SubjectAccessReview would answer it properly and is a `create`. internal/collect issues zero object
// writes and that is a product claim, not a preference.
//
// So a union over collected bindings is a LOWER BOUND and never the permission set, and every phrase below
// would present it as the total.
var bannedGrantPhrases = []string{
	"can do",
	"has access to",
	"effective permissions",
	"full access",
	"is able to",
	"privilege escalation",
	"complete access",
	"unrestricted access",
	"all permissions",
	"total access",
	// Scope decides severity; the wildcard alone decides nothing (spec §3.4). A finding that called a
	// namespaced wildcard "cluster-wide" would be false in the direction that matters.
	"cluster admin",
	"cluster-admin equivalent",
	// Aggregation is a controller we do not watch. The materialised rules are read; nothing is said about
	// why they are there (spec §3.5).
	"aggregated from",
	"because of aggregation",
}

func TestRBACGrantRules_NeverOverclaimWhatASubjectCanDo(t *testing.T) {
	inv := grantFixture()
	out := RBACDangerousGrant{}.Evaluate(inv, Options{IncludeSystem: true})
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, phrase := range bannedGrantPhrases {
			if strings.Contains(blob, phrase) {
				t.Errorf("finding %s says %q — that asserts a permission union this snapshot cannot compute:\n%s",
					f.ID, phrase, blob)
			}
		}
	}
}

// A finding carrying dollars must carry evidence (validate.go), and these carry no dollars at all: there is
// no traffic, revenue or SLA data in a snapshot, and a permission is not a cost.
func TestRBACGrantRules_NeverCarryDollars(t *testing.T) {
	for _, f := range (RBACDangerousGrant{}).Evaluate(grantFixture(), Options{IncludeSystem: true}) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f — an RBAC grant has no price in this snapshot",
				f.ID, f.DollarImpactMonthly)
		}
	}
}

// SCOPE DECIDES SEVERITY, NOT SYNTAX. A `*` on a namespaced Role in one namespace and a `*` on a
// ClusterRole bound cluster-wide are not the same statement, and the most likely thing to get wrong in a
// hurry is treating them as one.
//
// The third case is the one nobody expects: a ClusterRole bound by a ROLEBINDING grants only inside that
// binding's namespace. Reading the role's kind alone would call it cluster-wide.
func TestRBACGrantRules_SeverityFollowsTheEffectiveScope(t *testing.T) {
	out := RBACDangerousGrant{}.Evaluate(grantFixture(), Options{IncludeSystem: true})

	// Selected by BINDING AND PATTERN. A `*` on `*` rule matches every pattern in the table, so keying on
	// the binding alone picked whichever finding came last — which is how the first version of this test
	// reported a severity defect that was its own ambiguity.
	bySubject := map[string]types.Finding{}
	for _, f := range out {
		if !strings.Contains(f.Title, "every verb on every resource") {
			continue
		}
		for _, e := range f.Evidence {
			switch {
			case strings.Contains(e, "wide-crb"):
				bySubject["cluster"] = f
			case strings.Contains(e, "narrow-rb"):
				bySubject["clusterrole-via-rolebinding"] = f
			case strings.Contains(e, "ns-rb"):
				bySubject["role"] = f
			}
		}
	}
	for _, tc := range []struct {
		key  string
		want types.Severity
		why  string
	}{
		{"cluster", types.SeverityHigh, "a wildcard ClusterRole bound cluster-wide"},
		{"clusterrole-via-rolebinding", types.SeverityMedium,
			"a ClusterRole bound by a RoleBinding reaches only that namespace, whatever its kind says"},
		{"role", types.SeverityMedium, "a namespaced wildcard Role"},
	} {
		f, ok := bySubject[tc.key]
		if !ok {
			t.Errorf("no finding for %s (%s) — the fixture or the matcher is not the shape this test needs",
				tc.key, tc.why)
			continue
		}
		if f.Severity != tc.want {
			t.Errorf("%s: severity %s, want %s — %s", tc.key, f.Severity, tc.want, tc.why)
		}
	}
}

// THE WIDEST STATEMENT SUBSUMES THE NARROWER ONES. `*` on `*` matches every pattern in the table, and
// every cluster has cluster-admin bound to something — so without this a single role would produce eleven
// cards saying eleven weaker versions of one fact.
func TestRBACGrantRules_AWildcardRoleProducesOneFindingNotEleven(t *testing.T) {
	out := RBACDangerousGrant{}.Evaluate(grantFixture(), Options{IncludeSystem: true})
	n := 0
	for _, f := range out {
		if strings.Contains(f.Title, "wide-superuser") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the wildcard ClusterRole produced %d findings, want 1", n)
	}
	// NON-VACUITY: a role that matches ONE pattern must still produce that one, or "subsume" would be
	// indistinguishable from "report almost nothing".
	narrow := 0
	for _, f := range out {
		if strings.Contains(f.Title, "named-secret-reader") {
			narrow++
			if !strings.Contains(f.Title, "reading Secrets") {
				t.Errorf("the secrets-only role was reported as %q", f.Title)
			}
		}
	}
	if narrow != 1 {
		t.Errorf("the secrets-only ClusterRole produced %d findings, want 1", narrow)
	}
}

// AN UNBOUND ROLE GRANTS NOTHING TO ANYBODY. A ClusterRole with `*` on `*` that no binding references is a
// definition, not an exposure, and reporting it would fill a real cluster's report with the operators'
// unbound templates.
func TestRBACGrantRules_AnUnboundRoleIsNotAFinding(t *testing.T) {
	inv := &collect.Inventory{
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan-superuser"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
	}
	inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}

	if out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}); len(out) != 0 {
		t.Errorf("an unbound ClusterRole produced %d finding(s): %+v", len(out), out[0].Title)
	}
}

// THE DENIAL GUARD. A run that could not list roles must not report that nothing dangerous was granted, and
// must not report a grant it could not attribute to a subject either.
func TestRBACGrantRules_DeniedReadsProduceNoClaim(t *testing.T) {
	for _, denied := range []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"} {
		inv := grantFixture()
		var kept []string
		for _, c := range inv.Meta.Collected {
			if c != denied {
				kept = append(kept, c)
			}
		}
		inv.Meta.Collected = kept
		inv.Meta.Denied = []string{denied + ": forbidden"}

		if out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}); len(out) != 0 {
			t.Errorf("with %q denied the rule still produced %d finding(s) — an absence from a denied read "+
				"is not an absence", denied, len(out))
		}
	}
	// NON-VACUITY: with everything collected the same fixture must produce findings, or "denied means
	// silent" is true because the rule never speaks.
	if out := (RBACDangerousGrant{}).Evaluate(grantFixture(), Options{IncludeSystem: true}); len(out) == 0 {
		t.Error("the rule produces nothing even when every kind was collected")
	}
}

// resourceNames REACH THE FINDING AS A STRUCTURED FIELD, not only as prose. A customer-chosen object name in
// free text has no token and survives --redact; ScopedTo is what internal/redact harvests. This is the half
// of Option C that makes printing the names safe rather than merely useful.
func TestRBACGrantRules_NamedObjectsAreStructuredForRedaction(t *testing.T) {
	out := RBACDangerousGrant{}.Evaluate(grantFixture(), Options{IncludeSystem: true})
	var found types.Finding
	for _, f := range out {
		if len(f.ScopedTo) > 0 {
			found = f
		}
	}
	if found.ID == "" {
		t.Fatal("no finding carried ScopedTo, and the fixture has a rule with resourceNames")
	}
	if len(found.ScopedTo) != 2 {
		t.Errorf("ScopedTo = %v, want the two named objects", found.ScopedTo)
	}
	// And every name in ScopedTo must appear in the evidence, or the structured field and the prose the
	// reader actually reads have drifted apart.
	blob := strings.Join(found.Evidence, "\n")
	for _, n := range found.ScopedTo {
		if !strings.Contains(blob, n) {
			t.Errorf("ScopedTo names %q and no evidence line mentions it", n)
		}
	}
}

// AGGREGATION IS NAMED AND NOT REASONED ABOUT. A ClusterRole with an aggregationRule has its rules filled in
// by a controller from labelled ClusterRoles. A rule that appears because a third-party operator labelled
// its own ClusterRole is still a real grant — so it is reported — but saying anything about WHY it is there
// means modelling a controller nobody watches.
func TestRBACGrantRules_AggregationIsDisclosedNotExplained(t *testing.T) {
	inv := grantFixture()
	inv.ClusterRoles = append(inv.ClusterRoles, rbacv1.ClusterRole{
		ObjectMeta:      metav1.ObjectMeta{Name: "aggregated-edit"},
		AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{}}},
		Rules:           []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
	})
	inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "aggregated-edit-crb"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "aggregated-edit"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agg", Namespace: "tools"}},
	})

	var agg *types.Finding
	for i, f := range (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}) {
		if strings.Contains(strings.Join(f.Evidence, "\n"), "aggregated-edit") {
			agg = &(RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true})[i]
		}
	}
	if agg == nil {
		t.Fatal("an aggregated ClusterRole's materialised grant was not reported at all")
	}
	blob := strings.Join(agg.Evidence, "\n")
	if !strings.Contains(blob, "aggregationRule") {
		t.Errorf("the finding does not disclose that this role's rules are controller-filled:\n%s", blob)
	}
}

// grantFixture is one cluster with the three scope cases and one resourceNames-scoped grant.
func grantFixture() *collect.Inventory {
	inv := &collect.Inventory{
		ClusterRoles: []rbacv1.ClusterRole{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "wide-superuser"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "narrow-superuser"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "named-secret-reader"},
				Rules: []rbacv1.PolicyRule{{
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					Verbs:         []string{"get", "list"},
					ResourceNames: []string{"acme-prod-db-credentials", "payments-oauth-client"},
				}},
			},
		},
		Roles: []rbacv1.Role{{
			ObjectMeta: metav1.ObjectMeta{Name: "ns-superuser", Namespace: "payments"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "wide-crb"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "wide-superuser"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "runner", Namespace: "ci"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-crb"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "named-secret-reader"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sync", Namespace: "platform"}},
			},
		},
		RoleBindings: []rbacv1.RoleBinding{
			{
				// A CLUSTERROLE BOUND BY A ROLEBINDING: reaches only this namespace.
				ObjectMeta: metav1.ObjectMeta{Name: "narrow-rb", Namespace: "sandbox"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "narrow-superuser"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev", Namespace: "sandbox"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "ns-rb", Namespace: "payments"},
				RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "ns-superuser"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "app", Namespace: "payments"}},
			},
		},
	}
	inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}
	return inv
}

// A BINDING NAMED IN EVIDENCE AND ABSENT FROM THE AFFECTED SET SURVIVES --redact.
//
// Found by redacting a real AKS reading and grepping it for every identifier the unredacted one carries:
//
//	ClusterRole res-8f7921: a rule permits reading Secrets.
//	ClusterRoleBinding kube-prometheus-stack-grafana-clusterrolebinding names no subject this reading can resolve…
//
// The ROLE is tokenized and the BINDING is not, in the same sentence. redact.gatherIdentifiers harvests
// every AffectedResources name and every RBAC chain in Architecture; this binding is in neither, because
// this rule's affected set names only the role. On a cluster whose bindings are named for the company —
// "acmebank-payments-admin" — that name leaves the building in a document the operator redacted on purpose.
//
// THE FIX IS NOT A REDACTION FIX. The bindings ARE affected objects: they are what activates the grant, and
// an operator acting on this finding edits a binding, not only the role. Naming them makes the finding
// complete AND makes the existing harvest reach them, which is the order this project prefers — a leak
// closed by the reading being right rather than by the redactor guessing at free text.
func TestRBACDangerousGrant_NamesTheBindingsItCites(t *testing.T) {
	fs := RBACDangerousGrant{}.Evaluate(grantFixture(), Options{IncludeSystem: true})
	if len(fs) == 0 {
		t.Fatal("the rule produced no finding, so this test measures nothing")
	}

	checked := 0
	for _, f := range fs {
		evidence := strings.Join(f.Evidence, "\n")
		named := map[string]bool{}
		for _, r := range f.AffectedResources {
			named[r.Name] = true
		}
		// Every binding the evidence cites by name must be an affected object of this finding.
		for _, b := range []string{"wide-crb", "secret-crb", "narrow-crb", "ns-rb"} {
			if !strings.Contains(evidence, b) {
				continue
			}
			checked++
			if !named[b] {
				t.Errorf("%s cites binding %q in its evidence and does not name it in AffectedResources.\n"+
					"  redact.gatherIdentifiers harvests the affected set, so that name survives --redact\n"+
					"  verbatim — and an operator acting on this finding edits the binding, not only the role.\n"+
					"  affected: %v", f.RuleID, b, f.AffectedResources)
			}
		}
		// And the role itself must still be there.
		if len(f.AffectedResources) == 0 {
			t.Errorf("%s names no affected resource at all", f.RuleID)
		}
	}
	if checked == 0 {
		t.Fatal("no finding cited a binding by name, so this test passed over an empty set — the fixture " +
			"no longer produces the state")
	}
	t.Logf("%d finding/binding citation(s) checked across %d finding(s)", checked, len(fs))
}

// A SUBJECT THIS READING EXCLUDED IS NOT A SUBJECT IT COULD NOT RESOLVE.
//
// Measured by running `shoalcheck explain` on the top finding of a live kind reading:
//
//	ClusterRole system:controller:job-controller contains a rule permitting creating Pods, and 1 binding(s)
//	name subjects that activate it.
//	· ClusterRoleBinding system:controller:job-controller names no subject this reading can resolve…
//
// The binding names exactly one subject and the cluster hands it over on request:
// `{"kind":"ServiceAccount","name":"job-controller","namespace":"kube-system"}`. It was resolved and then
// DROPPED, by this rule's own `!IncludeSystem && kube-` filter. The sentence reports a resolution failure
// for a deliberate exclusion — an operator reads it as "our RBAC data is incomplete" and goes looking for a
// collector problem that does not exist.
//
// The same sentence also covers a binding with no subjects at all, which is a third state. Three causes, one
// wrong word: the shape M-94 named when six causes for an unread kind were flattened into "denied".
func TestRBACDangerousGrant_AnExcludedSubjectIsNotAnUnresolvableOne(t *testing.T) {
	inv := grantFixture()
	// One binding whose only subject is a system ServiceAccount — the kind every cluster ships.
	inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "system-crb"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "wide-superuser"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "job-controller", Namespace: "kube-system"}},
	})
	// And one that names nobody at all.
	inv.ClusterRoleBindings = append(inv.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-crb"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "wide-superuser"},
	})

	fs := RBACDangerousGrant{}.Evaluate(inv, Options{IncludeSystem: false})
	if len(fs) == 0 {
		t.Fatal("the rule produced no finding, so this test measures nothing")
	}
	evidence := ""
	for _, f := range fs {
		evidence += strings.Join(f.Evidence, "\n") + "\n"
	}
	if !strings.Contains(evidence, "system-crb") || !strings.Contains(evidence, "empty-crb") {
		t.Fatalf("the fixture's two bindings are not in the evidence, so neither state is being measured:\n%s",
			evidence)
	}
	for _, ln := range strings.Split(evidence, "\n") {
		switch {
		case strings.Contains(ln, "system-crb"):
			if strings.Contains(ln, "can resolve") {
				t.Errorf("a system subject that was resolved and excluded is reported as unresolvable:\n  %s", ln)
			}
			if !strings.Contains(ln, "include-system") {
				t.Errorf("the exclusion does not name the flag that would show the subject:\n  %s", ln)
			}
		case strings.Contains(ln, "empty-crb"):
			if strings.Contains(ln, "can resolve") {
				t.Errorf("a binding that names nobody is reported as unresolvable:\n  %s", ln)
			}
		}
	}

	// THE OVER-REACH: with --include-system the same binding names its subject, and a genuinely
	// unresolvable one keeps the old sentence.
	incl := RBACDangerousGrant{}.Evaluate(inv, Options{IncludeSystem: true})
	inclEvidence := ""
	for _, f := range incl {
		inclEvidence += strings.Join(f.Evidence, "\n") + "\n"
	}
	for _, ln := range strings.Split(inclEvidence, "\n") {
		if strings.Contains(ln, "system-crb") && !strings.Contains(ln, "kube-system/job-controller") {
			t.Errorf("--include-system did not name the subject it includes:\n  %s", ln)
		}
	}
}

// A GRANT KUBERNETES WRITES FOR ITSELF IS NOT A FINDING ABOUT ANYBODY'S CLUSTER. The sibling rule
// binding-to-builtin-subject has excluded the API server's own bindings — by their label,
// kubernetes.io/bootstrapping: rbac-defaults, and by nothing else — since it was first run on a live cluster.
// This rule did not, and on the 839-finding AKS production reading 40 of its 110 findings were roles like
// system:controller:job-controller "permits creating Pods": true, unremovable, and reconciled back by the API
// server on its next start. On the e2e cluster the terminal's findings list showed thirty of them in a row.
//
// The exclusion is per BINDING, never per role: cluster-admin is a bootstrap role too, and binding it to your
// own ServiceAccount is exactly the grant this rule exists for.
func TestRBACDangerousGrant_ABootstrapBindingIsKubernetesOwnAndYoursIsNot(t *testing.T) {
	boot := map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	inv := &collect.Inventory{
		ClusterRoles: []rbacv1.ClusterRole{
			{ObjectMeta: metav1.ObjectMeta{Name: "system:controller:job-controller", Labels: boot},
				Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: boot},
				Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Name: "system:controller:job-controller", Labels: boot},
				RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:controller:job-controller"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "job-controller"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: boot},
				RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ci-deployer-admin"},
				RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "ci", Name: "deployer"}}},
		},
	}
	inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}

	out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(out) != 1 {
		var titles []string
		for _, f := range out {
			titles = append(titles, f.Title)
		}
		t.Fatalf("%d finding(s), want exactly the customer's cluster-admin binding: %v", len(out), titles)
	}
	f := out[0]
	var cited []string
	for _, r := range f.AffectedResources {
		cited = append(cited, r.Kind+" "+r.Name)
	}
	joined := strings.Join(cited, ", ") + " " + strings.Join(f.Evidence, " ")
	if !strings.Contains(joined, "ci-deployer-admin") {
		t.Errorf("the customer's binding is not cited: %s", joined)
	}
	if strings.Contains(joined, "system:masters") || strings.Contains(joined, "ClusterRoleBinding cluster-admin") {
		t.Errorf("the API server's own binding is still cited beside the customer's: %s", joined)
	}
}

// THE SAME EXCLUSION, ONE RULE ALONG. Kubernetes writes system:controller:service-controller and its siblings
// for cloud controllers a kind or managed cluster may never run, so the ServiceAccounts they name are absent
// by design. Reported as "grants to a ServiceAccount that is not there" on every such cluster: 3 of 45 on the
// AKS production reading, 4 on the e2e cluster.
func TestDanglingBindingSubject_ABootstrapBindingIsKubernetesOwn(t *testing.T) {
	boot := map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	inv := &collect.Inventory{
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{ObjectMeta: metav1.ObjectMeta{Name: "system:controller:service-controller", Labels: boot},
				RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:controller:service-controller"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "service-controller"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "app-reader"},
				RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "app", Name: "gone"}}},
		},
	}
	inv.Meta.Collected = []string{"serviceaccounts", "rolebindings", "clusterrolebindings"}
	out := (DanglingBindingSubject{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(out) != 1 || !strings.Contains(out[0].Title, "app-reader") {
		var titles []string
		for _, f := range out {
			titles = append(titles, f.Title)
		}
		t.Errorf("want only the customer's dangling binding, got %v", titles)
	}
}

// THE LABEL IS NOT A CREDENTIAL. kubernetes.io/bootstrapping: rbac-defaults is an ordinary label: anybody who can
// create a binding can put it on one. Trusted alone, it let a binding granting cluster-admin to an attacker's
// ServiceAccount vanish from every RBAC rule — persistence that an audit is exactly the tool to find. A binding
// is Kubernetes' own only when it also has the shape Kubernetes writes: a system: name (or cluster-admin), the
// role of the same name, and nothing but system identities as subjects. Raised by the automated security review
// of the push on 2026-10-16.
func TestRBAC_ALabelledBindingWithoutTheBootstrapShapeIsStillReported(t *testing.T) {
	boot := map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	admin := rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: boot},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	spoofs := map[string]rbacv1.ClusterRoleBinding{
		"an ordinary name": {ObjectMeta: metav1.ObjectMeta{Name: "ci-admin", Labels: boot},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "ci", Name: "deployer"}}},
		"an invented system: role to every authenticated user": {ObjectMeta: metav1.ObjectMeta{Name: "system:evil", Labels: boot},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}}},
		"a system: name over another role": {ObjectMeta: metav1.ObjectMeta{Name: "system:metrics-reader", Labels: boot},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}}},
		"a bootstrap shape with a customer subject": {ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: boot},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}, {Kind: "ServiceAccount", Namespace: "ci", Name: "deployer"}}},
	}
	for name, b := range spoofs {
		inv := &collect.Inventory{ClusterRoles: []rbacv1.ClusterRole{admin}, ClusterRoleBindings: []rbacv1.ClusterRoleBinding{b}}
		inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings", "serviceaccounts"}
		if out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}); len(out) == 0 {
			t.Errorf("%s: a binding labelled rbac-defaults without the bootstrap shape hid a cluster-admin grant", name)
		}
	}
	// And the real one, in its real shape, is still Kubernetes' own.
	real := rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: boot},
		RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}}}
	inv := &collect.Inventory{ClusterRoles: []rbacv1.ClusterRole{admin}, ClusterRoleBindings: []rbacv1.ClusterRoleBinding{real}}
	inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}
	if out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}); len(out) != 0 {
		t.Errorf("the upstream cluster-admin binding to system:masters was reported: %s", out[0].Title)
	}
}

func TestKubernetesOwnBinding_OnlyTheExactUpstreamTuple(t *testing.T) {
	boot := map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	sa := func(ns, n string) rbacv1.Subject {
		return rbacv1.Subject{Kind: "ServiceAccount", Namespace: ns, Name: n}
	}
	grp := func(n string) rbacv1.Subject { return rbacv1.Subject{Kind: "Group", Name: n} }
	usr := func(n string) rbacv1.Subject { return rbacv1.Subject{Kind: "User", Name: n} }
	cases := []struct {
		why                  string
		kind, ns, name, role string
		subjects             []rbacv1.Subject
		want                 bool
	}{
		{"upstream controller", "ClusterRoleBinding", "", "system:controller:job-controller", "system:controller:job-controller", []rbacv1.Subject{sa("kube-system", "job-controller")}, true},
		{"upstream broad group", "ClusterRoleBinding", "", "system:public-info-viewer", "system:public-info-viewer", []rbacv1.Subject{grp("system:unauthenticated"), grp("system:authenticated")}, true},
		{"upstream masters", "ClusterRoleBinding", "", "cluster-admin", "cluster-admin", []rbacv1.Subject{grp("system:masters")}, true},
		{"upstream no subjects", "ClusterRoleBinding", "", "system:node", "system:node", nil, true},
		{"upstream system:: role binding", "RoleBinding", "kube-system", "system::extension-apiserver-authentication-reader", "extension-apiserver-authentication-reader", []rbacv1.Subject{usr("system:kube-controller-manager"), usr("system:kube-scheduler")}, true},
		{"invented system: name to every authenticated user", "ClusterRoleBinding", "", "system:evil", "system:evil", []rbacv1.Subject{grp("system:authenticated")}, false},
		{"controller bound to another SA", "ClusterRoleBinding", "", "system:controller:job-controller", "system:controller:job-controller", []rbacv1.Subject{sa("kube-system", "attacker")}, false},
		{"invented controller", "ClusterRoleBinding", "", "system:controller:evil", "system:controller:evil", []rbacv1.Subject{sa("kube-system", "evil")}, false},
		{"upstream binding with a subject added", "ClusterRoleBinding", "", "cluster-admin", "cluster-admin", []rbacv1.Subject{grp("system:masters"), sa("ci", "deployer")}, false},
		{"upstream name pointing at another role", "ClusterRoleBinding", "", "system:basic-user", "cluster-admin", []rbacv1.Subject{grp("system:authenticated")}, false},
		{"upstream role binding in the wrong namespace", "RoleBinding", "default", "system::extension-apiserver-authentication-reader", "extension-apiserver-authentication-reader", []rbacv1.Subject{usr("system:kube-controller-manager"), usr("system:kube-scheduler")}, false},
		{"an upstream ClusterRoleBinding name used as a RoleBinding", "RoleBinding", "kube-system", "cluster-admin", "cluster-admin", []rbacv1.Subject{grp("system:masters")}, false},
	}
	for _, c := range cases {
		refKind := "ClusterRole"
		if c.kind == "RoleBinding" {
			refKind = "Role"
		}
		ref := rbacv1.RoleRef{Kind: refKind, Name: c.role}
		if got := kubernetesOwnBinding(c.kind, c.ns, c.name, boot, ref, c.subjects); got != c.want {
			t.Errorf("%s: own=%v, want %v", c.why, got, c.want)
		}
		if kubernetesOwnBinding(c.kind, c.ns, c.name, nil, ref, c.subjects) {
			t.Errorf("%s: counted as Kubernetes' own without the label", c.why)
		}
	}
}

// AN UPSTREAM BINDING WHOSE ROLE WAS EDITED IS STILL A GRANT. The API server's reconciliation adds missing
// permissions to a bootstrap role and removes none, so `*` written into system:basic-user stays — and its
// binding to system:authenticated is the upstream tuple exactly. The dangerous-grant rule therefore never
// excludes a binding whose subjects are a broad group, and never excludes an unrestricted role other than
// cluster-admin: their upstream roles grant nothing this rule reports, so the guard costs no noise.
func TestRBACDangerousGrant_AnEditedBootstrapRoleIsStillReported(t *testing.T) {
	boot := map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}
	star := []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}
	cases := map[string]rbacv1.ClusterRoleBinding{
		"system:basic-user to every authenticated user": {ObjectMeta: metav1.ObjectMeta{Name: "system:basic-user", Labels: boot},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:basic-user"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}}},
		"a controller's role widened to everything": {ObjectMeta: metav1.ObjectMeta{Name: "system:controller:ttl-controller", Labels: boot},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:controller:ttl-controller"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "ttl-controller"}}},
	}
	for why, b := range cases {
		inv := &collect.Inventory{
			ClusterRoles:        []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: b.RoleRef.Name, Labels: boot}, Rules: star}},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{b},
		}
		inv.Meta.Collected = []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"}
		if out := (RBACDangerousGrant{}).Evaluate(inv, Options{IncludeSystem: true}); len(out) == 0 {
			t.Errorf("%s: an edited bootstrap role was hidden behind its upstream binding", why)
		}
	}
}
