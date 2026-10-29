package rules

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// rbac_grants.go — WHAT A BINDING ACTUALLY GRANTS.
//
// Until 2026-08-28 this product read RBAC bindings and not the Role/ClusterRole bodies they point at, so it
// could say "ServiceAccount X is bound to ClusterRole Y" and nothing about what Y permits. Nine CIS controls
// sat at MANUAL for that reason, and the one that motivated the change — 5.1.2, "minimize access to secrets"
// — is not a control anybody can act on when it cannot say WHICH secrets.
//
// A PolicyRule is a declaration. Reading it is arithmetic, not inference, so the claim here is as strong as
// the PDB-arithmetic claims: both halves are read verbatim from the snapshot.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
//	No "this ServiceAccount can do X". EFFECTIVE PERMISSIONS ARE NOT READABLE. What a subject can
//	actually do is the union over every binding that names it, INCLUDING bindings that name a Group it
//	belongs to — system:authenticated, system:serviceaccounts, system:serviceaccounts:<ns> — and group
//	membership of a real user is decided by the authenticator: an OIDC token's claims, an AWS IAM
//	mapping, a client certificate's O=. None of that is in the snapshot. A union over collected bindings
//	is a LOWER BOUND and never the permission set, so every finding here is a statement about ONE
//	binding and ONE rule, named, and never a total.
//
//	SubjectAccessReview would answer it properly and is a `create`. internal/collect issues zero object
//	writes and that is a product claim, not a preference. Do not propose it.
//
//	No severity from syntax. A `*` on a namespaced Role in a sandbox namespace and a `*` on a ClusterRole
//	bound cluster-wide are not the same statement. SCOPE decides severity; the wildcard alone decides
//	nothing. The case that catches people: a ClusterRole bound by a ROLEBINDING grants only inside that
//	binding's namespace, whatever the role's kind suggests.
//
//	Nothing about aggregation. A ClusterRole with an aggregationRule has its `rules` filled in by a
//	controller from labelled ClusterRoles. The MATERIALISED rules are read and reported — a grant that
//	exists because a third-party operator labelled its own ClusterRole is still a real grant — and the
//	finding says the rules are controller-filled without reasoning about why any of them is there.
//
//	No unbound roles. A ClusterRole with `*` on `*` that no binding references is a definition, not an
//	exposure. Reporting it would fill a real cluster's report with its operators' unbound templates.
//
//	No dollars. There is no traffic, revenue or SLA data in the snapshot, and a permission has no price.
//
//	No remediation command. Removing a grant is a decision about who needs what, and a generated
//	`kubectl` line would be a change to a live authorisation policy proposed by a tool that cannot see
//	who depends on it. The finding names what to look at.
//
// rbac_grants_test.go enforces the phrase list mechanically, the way node_drain_test.go does for drains.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE PATTERN TABLE IS A CLAIM TABLE, NOT A COVERAGE TABLE
//
// dangerousGrants below is curated, and drift means "a newly dangerous pair is not flagged" — never "we
// under-report something we claimed to cover". The report never says this list is exhaustive. That is the
// opposite posture from RequiredKinds or the collector's step table, where a missing entry silently weakens
// a claim that is still being made.

// RBACDangerousGrant reports, per (Role|ClusterRole, matched rule), a grant a reviewer should look at,
// scoped by what the binding that activates it actually reaches.
type RBACDangerousGrant struct{}

func (RBACDangerousGrant) ID() string { return "k8s.rbac.dangerous-grant" }

// 1.1.0 (2026-10-21): a pattern names the requests its danger lives on and a rule matches it as the RBAC
// authorizer would allow one (rbacAllows) — read-only grants stopped matching the write patterns, `*/proxy` and its
// kind started matching, admission policies joined the webhook pattern, and pods/exec and pods/attach got a
// pattern of their own.
func (RBACDangerousGrant) Version() string { return "1.1.0" }

// RequiredKinds gates the COMPARISON, not the run (see deps.go).
//
// All four are load-bearing and for two different reasons. The bodies ARE the claim: without `clusterroles`
// and `roles` there is no rule to quote. The bindings are what make the claim about anybody: an unbound role
// grants nothing, so a reading without bindings would report every definition as an exposure.
//
// `serviceaccounts` is deliberately absent: a binding names its subject inline, and a subject that is a
// Group or a User is not a ServiceAccount at all.
func (RBACDangerousGrant) RequiredKinds() []string {
	return []string{"clusterrolebindings", "clusterroles", "rolebindings", "roles"}
}

// grantPattern is one (resource, verb) shape worth a reviewer's attention, with a severity per effective
// scope. Both severities are stated rather than derived, because deriving one from the other is exactly the
// syntax-to-severity move the claim boundary refuses.
type grantPattern struct {
	key   string // stable, for the finding ID
	label string // the operator's words for what the grant permits
	// targets are the requests the danger lives on, named as the API server's authorizer sees them: group,
	// resource, subresource. A rule matches the pattern when the RBAC authorizer would allow one of these requests
	// with one of the verbs — see rbacAllows.
	//
	// WHY REQUESTS AND NOT A PATTERN LANGUAGE. The table used to say resource "*" for "this pattern does not care
	// which", and verbs "*" for "a rule with `*` counts". Read by a matcher, both meant "anything", so `verbs: ["*"]`
	// on ConfigMaps was impersonation and a role that only READ webhook configurations was writing them (measured
	// on the engine bench, including kubeadm's own system:kubelet-api-admin on every kubeadm cluster). And a
	// pattern language that was not the authorizer's missed what the authorizer grants: `*/proxy` is nodes/proxy.
	// Naming the request and asking the authorizer's question removes both.
	targets []grantTarget
	verbs   []string
	why     string
	cluster types.Severity
	scoped  types.Severity
}

// grantTarget is one request a dangerous pattern names. anySub marks a resource whose every subresource is the
// target — impersonating a user extra is a request for userextras/<key>, whatever the key.
type grantTarget struct {
	group, resource, sub string
	anySub               bool
}

func targets(group string, resources ...string) []grantTarget {
	out := make([]grantTarget, 0, len(resources))
	for _, r := range resources {
		res, sub, _ := strings.Cut(r, "/")
		out = append(out, grantTarget{group: group, resource: res, sub: sub})
	}
	return out
}

// A `*` IN A PATTERN AND A `*` IN A RULE ARE DIFFERENT THINGS, and conflating them is the bug this comment
// exists to prevent. It was made once already: `any-any` started life as a table entry with `group: "*",
// resource: "*", verbs: ["*"]`, and since a `*` in a PATTERN means "any", it matched EVERY rule — a
// ClusterRole granting `get` on two named Secrets was reported as permitting every verb on every resource.
//
// In a pattern, `*` means "this pattern does not care which". In a rule, `*` means the rule itself is
// unrestricted. The second is a claim about the role's own text, so it is checked explicitly rather than
// expressed as a pattern that accepts anything.
var unrestrictedGrant = grantPattern{
	key: "any-any", label: "every verb on every resource",
	why:     "A rule written with `*` for verbs, groups and resources permits anything the API server offers, including resources added later by a CRD nobody has reviewed.",
	cluster: types.SeverityHigh, scoped: types.SeverityMedium,
}

// unrestrictedRule reports whether any SINGLE PolicyRule is literally `*` on `*` on `*`.
//
// One rule, not the union across rules: three separate rules that between them name every group, verb and
// resource are a different and much more common shape — an operator's generated role — and calling that
// "every verb on every resource" would be a claim about a union nobody wrote.
func unrestrictedRule(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		if hasStar(r.APIGroups) && hasStar(r.Resources) && hasStar(r.Verbs) {
			return true
		}
	}
	return false
}

func hasStar(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

// dangerousGrants — the high-value verb/resource pairs, each behind a CIS control in §5.1.
var dangerousGrants = []grantPattern{
	{
		key: "secrets-read", label: "reading Secrets", targets: targets("", "secrets"),
		verbs:   []string{"get", "list", "watch"},
		why:     "A Secret's value is the credential itself. Anything that may read one holds whatever it protects, for as long as it is valid.",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium,
	},
	{
		key: "pods-create", label: "creating Pods", targets: targets("", "pods"), verbs: []string{"create"},
		why:     "Creating a Pod chooses its image, its ServiceAccount and its mounts, so it is a way to run code with another identity's token.",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium,
	},
	{
		// Added after the engine bench's differential (docs/engine/benchmark.md): Polaris and kubescape both report
		// exec/attach grants and this table had no row for them. CREATE only — since 1.31 a websocket exec needs
		// create as well (AuthorizePodWebsocketUpgradeCreatePermission), so GET is not reported; on an older API
		// server GET also reaches exec, and this pattern under-reports there rather than over-reporting here.
		key: "pods-exec", label: "running commands in existing Pods (exec or attach)",
		targets: targets("", "pods/exec", "pods/attach"), verbs: []string{"create"},
		why:     "exec and attach run a process inside somebody else's container, with its ServiceAccount token, its mounted Secrets and its network identity.",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium,
	},
	{
		key: "escalate", label: "the escalate verb on RBAC objects",
		targets: targets("rbac.authorization.k8s.io", "roles", "clusterroles"), verbs: []string{"escalate"},
		why:     "`escalate` removes the API server's own check that you may only grant permissions you already hold.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		key: "bind", label: "the bind verb on RBAC objects",
		targets: targets("rbac.authorization.k8s.io", "roles", "clusterroles"), verbs: []string{"bind"},
		why:     "`bind` permits creating a binding to a role whose permissions the binder does not hold.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		key: "impersonate", label: "the impersonate verb",
		// What the impersonation filter asks the authorizer for: users, groups and ServiceAccounts in core, uids and
		// userextras/<key> in authentication.k8s.io.
		targets: append(append(targets("", "users", "groups", "serviceaccounts"), targets("authentication.k8s.io", "uids")...),
			grantTarget{group: "authentication.k8s.io", resource: "userextras", anySub: true}),
		verbs:   []string{"impersonate"},
		why:     "Impersonation acts as another user, group or ServiceAccount, so the request is authorised as them.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		key: "sa-token", label: "minting ServiceAccount tokens", targets: targets("", "serviceaccounts/token"),
		verbs:   []string{"create"},
		why:     "The TokenRequest subresource issues a usable token for a ServiceAccount without touching the account itself.",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium,
	},
	{
		key: "nodes-proxy", label: "the nodes/proxy subresource", targets: targets("", "nodes/proxy"),
		// Every HTTP method the proxy forwards to the kubelet maps to one of these; GET alone is enough to reach
		// a container's exec endpoint over a websocket upgrade.
		verbs:   []string{"get", "create", "update", "patch", "delete"},
		why:     "nodes/proxy reaches the kubelet API directly, which is a path to running commands in containers on that node.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		key: "csr-approve", label: "approving certificate signing requests",
		targets: targets("certificates.k8s.io", "certificatesigningrequests/approval"),
		verbs:   []string{"update", "patch"},
		why:     "Approving a CSR mints a client certificate, and a certificate's subject decides who the API server thinks you are.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		// The key stays "webhooks" because finding IDs carry it; the label says what it now covers. Admission
		// policies joined it after an automated review: a mutating policy rewrites what it matches and a validating
		// one refuses it, cluster-wide, with no webhook server to notice.
		key: "webhooks", label: "writing admission webhook or admission policy configurations",
		targets: targets("admissionregistration.k8s.io",
			"validatingwebhookconfigurations", "mutatingwebhookconfigurations",
			"validatingadmissionpolicies", "validatingadmissionpolicybindings",
			"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"),
		verbs:   []string{"create", "update", "patch", "delete", "deletecollection"},
		why:     "An admission webhook sees and can rewrite every object admitted to the cluster, and an admission policy can rewrite or refuse every object it matches.",
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
	},
	{
		key: "pv-create", label: "creating PersistentVolumes", targets: targets("", "persistentvolumes"),
		verbs:   []string{"create"},
		why:     "A PersistentVolume names a host path or a cloud disk directly, so creating one can mount storage the namespace was never given.",
		cluster: types.SeverityMedium, scoped: types.SeverityMedium,
	},
}

// binding is one activation of a role: who it names and how far it reaches.
type binding struct {
	kind     string // ClusterRoleBinding | RoleBinding
	name     string
	ns       string // the binding's namespace; "" for a ClusterRoleBinding
	subjects []rbacv1.Subject
	// clusterWide is FALSE for a ClusterRole bound by a RoleBinding. That is the case worth naming: the
	// role's kind says cluster and the binding says otherwise, and the binding wins.
	clusterWide bool
}

func (r RBACDangerousGrant) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// THE DENIAL GUARD, on all four. The rule reasons about what a role grants AND about who holds it; a
	// read that was refused is not an absence, and a grant we cannot attribute to a subject is not an
	// exposure we can report. Same posture as HPAPinnedAtMax (silent_failures.go).
	for _, kind := range r.RequiredKinds() {
		if !metaCollected(inv, kind) {
			return nil
		}
	}

	// Bindings indexed by what they point at. A ClusterRoleBinding whose roleRef is not a ClusterRole is not
	// valid Kubernetes, so it is skipped rather than guessed at.
	//
	// A BINDING THE API SERVER WROTE FOR ITSELF IS SKIPPED — its label AND the exact upstream tuple, never the
	// label alone, which anybody can set (see bootstrap_policy.go). Per BINDING, never
	// per role: cluster-admin is a bootstrap role, and binding it to your own ServiceAccount is exactly the grant
	// this rule exists for. Measured on the AKS production reading: 40 of 110 findings were roles like
	// system:controller:job-controller "permits creating Pods", activated only by their bootstrap bindings —
	// true, unremovable, and reconciled back on the API server's next start.
	//
	// AND AN UPSTREAM BINDING IS STILL READ WHEN ITS ROLE COULD HAVE BEEN EDITED INTO A GRANT. Reconciliation adds
	// missing permissions to a bootstrap role and removes none, so `*` written into system:basic-user survives
	// behind a binding that is the upstream tuple exactly. Two cases are never skipped, and neither costs noise
	// because the upstream roles they name grant nothing this rule reports: a binding to a broad subject
	// (system:authenticated and its kin), and an unrestricted role that is not cluster-admin.
	clusterRoleRules := map[string][]rbacv1.PolicyRule{}
	for _, cr := range inv.ClusterRoles {
		clusterRoleRules[cr.Name] = cr.Rules
	}
	roleRules := map[string][]rbacv1.PolicyRule{}
	for _, ro := range inv.Roles {
		roleRules[ro.Namespace+"/"+ro.Name] = ro.Rules
	}
	kubernetesOwnAndUnedited := func(kind, ns, name string, labels map[string]string, ref rbacv1.RoleRef,
		subjects []rbacv1.Subject) bool {
		if !kubernetesOwnBinding(kind, ns, name, labels, ref, subjects) {
			return false
		}
		for _, s := range subjects {
			if broadSubject(s) {
				return false
			}
		}
		rules := clusterRoleRules[ref.Name]
		if ref.Kind == "Role" {
			rules = roleRules[ns+"/"+ref.Name]
		}
		return !(unrestrictedRule(rules) && ref.Name != "cluster-admin")
	}

	byClusterRole := map[string][]binding{}
	byRole := map[string][]binding{} // key: namespace + "/" + name
	for _, b := range inv.ClusterRoleBindings {
		if b.RoleRef.Kind != "ClusterRole" ||
			kubernetesOwnAndUnedited("ClusterRoleBinding", "", b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		byClusterRole[b.RoleRef.Name] = append(byClusterRole[b.RoleRef.Name], binding{
			kind: "ClusterRoleBinding", name: b.Name, subjects: b.Subjects, clusterWide: true,
		})
	}
	for _, b := range inv.RoleBindings {
		if kubernetesOwnAndUnedited("RoleBinding", b.Namespace, b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		switch b.RoleRef.Kind {
		case "ClusterRole":
			byClusterRole[b.RoleRef.Name] = append(byClusterRole[b.RoleRef.Name], binding{
				kind: "RoleBinding", name: b.Name, ns: b.Namespace, subjects: b.Subjects,
			})
		case "Role":
			key := b.Namespace + "/" + b.RoleRef.Name
			byRole[key] = append(byRole[key], binding{
				kind: "RoleBinding", name: b.Name, ns: b.Namespace, subjects: b.Subjects,
			})
		}
	}

	var out []types.Finding
	for _, cr := range inv.ClusterRoles {
		bs := byClusterRole[cr.Name]
		if len(bs) == 0 {
			continue // a definition, not an exposure
		}
		out = append(out, r.findingsFor("ClusterRole", "", cr.Name, cr.Rules,
			cr.AggregationRule != nil, bs, opts)...)
	}
	for _, ro := range inv.Roles {
		bs := byRole[ro.Namespace+"/"+ro.Name]
		if len(bs) == 0 {
			continue
		}
		out = append(out, r.findingsFor("Role", ro.Namespace, ro.Name, ro.Rules, false, bs, opts)...)
	}
	return out
}

func (r RBACDangerousGrant) findingsFor(kind, ns, name string, rules []rbacv1.PolicyRule,
	aggregated bool, bindings []binding, opts Options) []types.Finding {

	// Widest reach across every binding decides the severity, and every binding is named in the evidence.
	// Taking the widest is the conservative direction: a role bound cluster-wide once and namespaced twice
	// is reachable cluster-wide.
	clusterWide := false
	for _, b := range bindings {
		if b.clusterWide {
			clusterWide = true
		}
	}

	// THE WIDEST STATEMENT SUBSUMES THE NARROWER ONES. A role written `*` on `*` on `*` permits every
	// pattern in the table, so a cluster-admin-shaped role would otherwise produce ten cards saying ten
	// weaker versions of one fact — and every cluster has cluster-admin bound to something.
	//
	// A rendering decision about the same evidence, not a withheld claim: nothing narrower is true that the
	// widest line does not already cover.
	if unrestrictedRule(rules) {
		return []types.Finding{r.finding(kind, ns, name, unrestrictedGrant, nil, aggregated, bindings, clusterWide, opts)}
	}

	var out []types.Finding
	for _, p := range dangerousGrants {
		matched, names := matchRules(rules, p)
		if !matched {
			continue
		}
		out = append(out, r.finding(kind, ns, name, p, names, aggregated, bindings, clusterWide, opts))
	}
	return out
}

func (r RBACDangerousGrant) finding(kind, ns, name string, p grantPattern, names []string,
	aggregated bool, bindings []binding, clusterWide bool, opts Options) types.Finding {

	sev := p.scoped
	reach := "within one namespace"
	if clusterWide {
		sev = p.cluster
		reach = "cluster-wide"
	}
	f := types.Finding{
		ID:      findingID(r.ID(), kind+"/"+p.key, ns, name),
		IDBasis: &types.ResourceRef{Kind: kind + "/" + p.key, Namespace: ns, Name: name},
		RuleID:  r.ID(), RuleVersion: r.Version(),
		Title:    fmt.Sprintf("%s %s permits %s", kind, name, p.label),
		Severity: sev, Category: types.CategorySecurity,
		// 1.0: the rule and the binding are both read verbatim. What is uncertain is whether the grant is
		// intended, which is a question for the reviewer and not a detection confidence.
		Confidence:      1.0,
		EstimatedEffort: types.EffortMedium,
		Description: fmt.Sprintf("%s %s contains a rule permitting %s, and %s name subjects "+
			"that activate it. The grant reaches %s.", kind, name, p.label, nWord(len(bindings), "binding", "bindings"), reach),
		WhyItMatters:      p.why,
		AffectedResources: affectedForGrant(kind, ns, name, bindings),
		Provenance:        types.Provenance{Collector: "kubernetes", Version: engineVersion},
	}
	f.Evidence = grantEvidence(kind, ns, name, p, names, aggregated, bindings, opts)
	f.ScopedTo = names
	return f
}

// matchRules reports whether any PolicyRule in the role matches the pattern, and returns the object names
// such a rule is restricted to.
//
// A rule with no resourceNames applies to EVERY object of that resource, and returns no names — the caller
// must not read an empty slice as "scoped to nothing". Names are unioned across matching rules and sorted,
// so the field is stable between two readings of the same cluster.
func matchRules(rules []rbacv1.PolicyRule, p grantPattern) (bool, []string) {
	matched := false
	seen := map[string]bool{}
	var names []string
	unrestricted := false

	for _, rule := range rules {
		if !grantsPattern(rule, p) {
			continue
		}
		matched = true
		if len(rule.ResourceNames) == 0 {
			unrestricted = true
			continue
		}
		for _, n := range rule.ResourceNames {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	if !matched || unrestricted {
		// One unrestricted matching rule makes the named ones irrelevant: the grant already covers every
		// object. Returning the names anyway would read as a narrower grant than the role actually has.
		return matched, nil
	}
	sort.Strings(names)
	return true, names
}

// grantsPattern reports whether the authorizer would allow the rule one of the pattern's requests.
func grantsPattern(rule rbacv1.PolicyRule, p grantPattern) bool {
	for _, t := range p.targets {
		for _, v := range p.verbs {
			if t.anySub {
				if rbacAllowsAnySub(rule, t.group, t.resource, v) {
					return true
				}
				continue
			}
			if rbacAllows(rule, t.group, t.resource, t.sub, v) {
				return true
			}
		}
	}
	return false
}

// rbacAllows answers the RBAC authorizer's question for one rule and one request, with its semantics exactly
// (APIGroupMatches, ResourceMatches, VerbMatches in Kubernetes' rbac package):
//
//   - `*` in apiGroups, resources or verbs matches anything;
//   - a resource entry otherwise matches "resource" or "resource/subresource" exactly, so "pods" does not grant
//     "pods/log";
//   - `*/sub` grants that subresource of every resource — the spelling of nodes/proxy a reviewer skimming for
//     "nodes/proxy" does not see;
//   - nothing else is a wildcard: "pods/*" and "*/*" are literal strings no request is named;
//   - groups and verbs compare exactly.
//
// rbac_match_test.go holds it to those cases, and the bench checked the two non-obvious ones (`*/proxy` grants,
// `*/*` does not) with `kubectl auth can-i` against a real API server.
func rbacAllows(rule rbacv1.PolicyRule, group, resource, sub, verb string) bool {
	if !hasEntry(rule.APIGroups, group) || !hasEntry(rule.Verbs, verb) {
		return false
	}
	combined := resource
	if sub != "" {
		combined = resource + "/" + sub
	}
	for _, r := range rule.Resources {
		if r == "*" || r == combined {
			return true
		}
		if sub != "" && r == "*/"+sub {
			return true
		}
	}
	return false
}

// rbacAllowsAnySub is rbacAllows for a request on SOME subresource of resource, whichever: a rule naming
// "resource/<key>", "*/<key>" or "*" allows one. A key spelled "*" is the authorizer's literal string, not a
// wildcard, and names no extra anybody sets — so "*/*" and "userextras/*" allow nothing here, as they allow
// nothing there.
func rbacAllowsAnySub(rule rbacv1.PolicyRule, group, resource, verb string) bool {
	if !hasEntry(rule.APIGroups, group) || !hasEntry(rule.Verbs, verb) {
		return false
	}
	for _, r := range rule.Resources {
		if r == "*" {
			return true
		}
		for _, prefix := range []string{resource + "/", "*/"} {
			if key, ok := strings.CutPrefix(r, prefix); ok && key != "" && key != "*" {
				return true
			}
		}
	}
	return false
}

// hasEntry is the authorizer's group and verb match: `*` or the exact string.
func hasEntry(have []string, want string) bool {
	for _, h := range have {
		if h == "*" || h == want {
			return true
		}
	}
	return false
}

func grantEvidence(kind, ns, name string, p grantPattern, names []string,
	aggregated bool, bindings []binding, opts Options) []string {

	where := kind + " " + name
	if ns != "" {
		where = fmt.Sprintf("%s %s/%s", kind, ns, name)
	}
	ev := []string{fmt.Sprintf("%s: a rule permits %s.", where, p.label)}

	if len(names) > 0 {
		// The names, not a count. A grant on `secrets` is not assessable without knowing which — that is the
		// whole argument for Option C. They are also in Finding.ScopedTo, which is the structured field
		// internal/redact harvests, so --redact tokenizes them here too.
		ev = append(ev, fmt.Sprintf("Restricted to %s: %s.", nWord(len(names), "named object", "named objects"), strings.Join(names, ", ")))
	}
	if aggregated {
		ev = append(ev, "This ClusterRole carries an aggregationRule, so its rules are filled in by a "+
			"controller from labelled ClusterRoles. The rules read here are the materialised ones.")
	}

	for _, b := range bindings {
		reach := "cluster-wide"
		if !b.clusterWide {
			reach = "within namespace " + b.ns
			if b.kind == "RoleBinding" && kind == "ClusterRole" {
				reach = "within namespace " + b.ns + " only, because a RoleBinding scopes a ClusterRole to " +
					"its own namespace"
			}
		}
		bname := b.kind + " " + b.name
		if b.ns != "" {
			bname = fmt.Sprintf("%s %s/%s", b.kind, b.ns, b.name)
		}
		ev = append(ev, fmt.Sprintf("%s names %s, and reaches %s.", bname, subjectList(b.subjects, b.ns, opts), reach))
	}

	// THE SCOPE OF THE CLAIM USED TO BE APPENDED HERE, and it is not any more.
	//
	// The sentence — "this names one rule and the bindings that activate it; it is not a total, because a
	// subject's permissions are the union over every binding naming it or any group it belongs to, and group
	// membership comes from the authenticator" — is still said, verbatim and better, by the boundary family
	// "rbac — what a role permits, never what a subject can do". It was written here because
	// Finding.ClaimBoundaries did not exist yet: this was the only place a rule could state its own limit.
	//
	// Now it exists and travels to every surface, so keeping the evidence copy printed one thought twice
	// under two headings whose whole purpose is to differ — evidence is what the reading READ, a boundary is
	// what the finding does NOT establish. Measured on a live 188-finding reading before removal: fifty pairs
	// at 0.96 similarity, all from this rule. TestGolden_NoEvidenceRepeatsABoundary holds the class.
	return ev
}

// affectedForGrant is the role and EVERY BINDING THE EVIDENCE CITES.
//
// It was the role alone, and the bindings were named in evidence text and nowhere structured. Two
// consequences, and the second is why this is a rules change rather than a redaction one:
//
//   - an operator acting on this finding edits a BINDING — the role is what permits, the binding is what
//     activates — and the finding did not say which one;
//   - redact.gatherIdentifiers harvests the affected set, so a binding named only in free text survived
//     --redact verbatim. Measured on a live AKS reading: "ClusterRole res-8f7921: a rule permits reading
//     Secrets. ClusterRoleBinding kube-prometheus-stack-grafana-clusterrolebinding names no subject…" —
//     the role tokenized and the binding intact, in one sentence.
//
// A leak closed by the reading being right rather than by the redactor guessing at free text.
func affectedForGrant(kind, ns, name string, bindings []binding) []types.ResourceRef {
	out := []types.ResourceRef{{Kind: kind, Namespace: ns, Name: name}}
	for _, b := range bindings {
		out = append(out, types.ResourceRef{Kind: b.kind, Namespace: b.ns, Name: b.name})
	}
	return out
}

// subjectList names who a binding activates, and — when it names nobody this reading will print — says
// WHICH of the three reasons applies.
//
// ONE SENTENCE COVERED THREE STATES. "names no subject this reading can resolve" was returned when the
// binding had no subjects at all, when every subject was a system ServiceAccount this run excluded, and (in
// principle) when a subject could not be resolved. Measured on a live kind cluster: ClusterRoleBinding
// system:controller:job-controller names kube-system/job-controller, the cluster returns it on request, and
// the document reported a resolution failure — so an operator reads "our RBAC data is incomplete" and goes
// looking for a collector problem that does not exist. The exclusion is a CHOICE this run made and the
// sentence now says so, with the flag that reverses it.
func subjectList(subjects []rbacv1.Subject, fallbackNS string, opts Options) string {
	var parts []string
	excludedSystem := 0
	for _, s := range subjects {
		switch s.Kind {
		case rbacv1.ServiceAccountKind:
			sns := s.Namespace
			if sns == "" {
				sns = fallbackNS
			}
			if sns == "" {
				parts = append(parts, "a ServiceAccount whose namespace the binding does not resolve")
				continue
			}
			if !opts.IncludeSystem && strings.HasPrefix(sns, "kube-") {
				excludedSystem++
				continue
			}
			parts = append(parts, fmt.Sprintf("ServiceAccount %s/%s", sns, s.Name))
		case "Group":
			// Named as a Group, never resolved into members: who is in it is the authenticator's answer.
			parts = append(parts, fmt.Sprintf("Group %s", s.Name))
		case "User":
			parts = append(parts, fmt.Sprintf("User %s", s.Name))
		default:
			parts = append(parts, fmt.Sprintf("%s %s", s.Kind, s.Name))
		}
	}
	if len(parts) == 0 {
		switch {
		case len(subjects) == 0:
			return "no subject at all"
		case excludedSystem == len(subjects):
			return fmt.Sprintf("only %s in system namespaces, which this run excludes (--include-system shows %s)",
				nWord(excludedSystem, "subject", "subjects"), pick(excludedSystem, "it", "them"))
		default:
			return "no subject this reading can resolve"
		}
	}
	return strings.Join(parts, ", ")
}
