package rules

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type ClusterAdminServiceAccount struct{}

func (ClusterAdminServiceAccount) ID() string      { return "k8s.rbac.cluster-admin-serviceaccount" }
func (ClusterAdminServiceAccount) Version() string { return "1.0.0" }

// Evaluate flags every binding that hands the cluster-admin ClusterRole to a
// ServiceAccount: ClusterRoleBindings (cluster-wide power) and the rarer but
// real RoleBindings referencing cluster-admin (full power inside one
// namespace). One finding per binding; a binding with several SA subjects
// gets one evidence line and one affected-resource entry per subject.
//
// SCOPE CAVEAT (carried into every finding's wording): this check matches the
// built-in ClusterRole named exactly "cluster-admin" by name only. A custom
// ClusterRole that grants apiGroups/resources/verbs ["*"], or one that
// aggregates into cluster-admin via an aggregationRule, is functionally
// cluster-admin but is named something else — and is NOT detected here,
// because the collector deliberately does not read Role/ClusterRole bodies
// (collect.go: bindings only). Absence of findings from this rule therefore
// does NOT mean "no ServiceAccount has god-level access."
func (r ClusterAdminServiceAccount) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, b := range inv.ClusterRoleBindings {
		if !refsClusterAdmin(b.RoleRef) {
			continue
		}
		// CRB subjects must carry their own namespace; no fallback exists.
		sas := serviceAccountSubjects(b.Subjects, "", opts)
		if len(sas) == 0 {
			continue
		}
		out = append(out, r.finding("ClusterRoleBinding", "", b.Name, "cluster-wide", sas))
	}
	for _, b := range inv.RoleBindings {
		if !refsClusterAdmin(b.RoleRef) {
			continue
		}
		sas := serviceAccountSubjects(b.Subjects, b.Namespace, opts)
		if len(sas) == 0 {
			continue
		}
		out = append(out, r.finding("RoleBinding", b.Namespace, b.Name,
			fmt.Sprintf("scoped to namespace %s", b.Namespace), sas))
	}
	return out
}

func refsClusterAdmin(ref rbacv1.RoleRef) bool {
	return ref.Kind == "ClusterRole" && ref.Name == "cluster-admin"
}

// serviceAccountSubjects keeps only the ServiceAccount subjects a finding
// should report: namespace resolved (falling back to the binding's namespace
// for RoleBindings), system namespaces skipped unless IncludeSystem.
func serviceAccountSubjects(subjects []rbacv1.Subject, fallbackNS string, opts Options) []rbacv1.Subject {
	var out []rbacv1.Subject
	for _, s := range subjects {
		if s.Kind != rbacv1.ServiceAccountKind {
			continue
		}
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNS
		}
		if ns == "" {
			continue // CRB subject without a namespace is unresolvable — nothing to point at
		}
		if !opts.IncludeSystem && isSystemNamespace(ns) {
			continue
		}
		s.Namespace = ns
		out = append(out, s)
	}
	return out
}

// knownOperatorSA reports whether the (namespace, name) pair looks like a
// well-known platform controller that ships its own cluster-admin grant. Such
// SAs are a true observation but usually a false PROBLEM: GitOps/operator
// stacks legitimately require cluster-wide reach, so presenting them at
// Critical/1.0 — identically to a hand-rolled app SA — is the #1 false-positive
// complaint about cluster scanners. This list mirrors the platform-component
// detection table the collector already uses (collect.detectStack: Argo CD,
// Flux, Calico/Tigera, cert-manager, …) plus the other controllers that are
// near-universally cluster-admin by design. It does NOT suppress the finding —
// it only down-ranks severity and confidence and adds a "verify, don't
// auto-remediate" caveat. system-namespace SAs are already filtered upstream;
// this covers the third-party operator namespaces isSystemNamespace does not.
func knownOperatorSA(ns, name string) bool {
	// EXACT NAMESPACES, NOT PREFIXES. This used to match a namespace that BEGAN with "argocd" or "vault", and an
	// SA name that began with "cert-manager" in any namespace — so a cluster-admin SA called cert-manager-sync in
	// `default`, or any SA in a namespace called argocd-tools, was presented as expected by design. A namespace
	// is matched whole, and only the namespaces these controllers install into by default; putting an SA in one
	// already takes rights there.
	if operatorNamespaces[strings.ToLower(ns)] {
		return true
	}
	// Controllers that live in a SHARED namespace are recognised by namespace AND name together.
	for _, c := range sharedNamespaceControllers {
		if strings.EqualFold(ns, c.ns) && strings.HasPrefix(strings.ToLower(name), c.name) {
			return true
		}
	}
	return false
}

// operatorNamespaces are the namespaces platform controllers install into by default, matched whole.
var operatorNamespaces = map[string]bool{
	"argocd": true, "flux-system": true, "crossplane-system": true, "cattle-system": true,
	"gatekeeper-system": true, "capi-system": true, "capi-kubeadm-bootstrap-system": true,
	"capi-kubeadm-control-plane-system": true, "tigera-operator": true, "calico-system": true,
	"cert-manager": true, "kyverno": true, "vault": true, "external-secrets": true,
}

// sharedNamespaceControllers are controllers that run in a namespace other workloads share.
var sharedNamespaceControllers = []struct{ ns, name string }{
	{"kube-system", "cluster-autoscaler"},
	{"karpenter", "karpenter"},
	{"kube-system", "karpenter"},
}

func (r ClusterAdminServiceAccount) finding(bindingKind, bindingNS, bindingName, scope string, sas []rbacv1.Subject) types.Finding {
	bindingRef := bindingName
	if bindingNS != "" {
		bindingRef = bindingNS + "/" + bindingName
	}
	affected := []types.ResourceRef{{Kind: bindingKind, Namespace: bindingNS, Name: bindingName}}
	evidence := make([]string, 0, len(sas)+1)
	// EVERY subject must be a recognised controller for the binding to be down-ranked: one controller on a
	// binding does not vouch for the app ServiceAccount beside it.
	operatorLike := len(sas) > 0
	for _, s := range sas {
		if !knownOperatorSA(s.Namespace, s.Name) {
			operatorLike = false
		}
		evidence = append(evidence, fmt.Sprintf(
			"%s %s: ServiceAccount %s/%s -> cluster-admin", bindingKind, bindingRef, s.Namespace, s.Name))
		affected = append(affected, types.ResourceRef{Kind: "ServiceAccount", Namespace: s.Namespace, Name: s.Name})
	}
	// Scope-honesty caveat: this rule cannot see wildcard/aggregated custom
	// god-roles. State it in the evidence so a reader never infers that the
	// absence of findings means no SA has god-level access.
	evidence = append(evidence,
		"scope note: matches the built-in ClusterRole \"cluster-admin\" by name only — custom wildcard (*,*,*) or aggregated ClusterRoles are functionally equivalent but out of scope (role bodies not collected)")

	first := sas[0] // remediation skeleton is interpolated for the first SA; others follow the same pattern

	// Severity/confidence policy (resolves the prior TODO(founder) marker):
	//  - The GRANT is a hard fact (roleRef + subjects) — detection certainty 1.0.
	//  - But Confidence on a Finding reads to the customer as "this is a problem
	//    worth acting on." For a legitimately-privileged operator SA the finding
	//    is a true observation but a false problem. So we calibrate to the
	//    PROBLEM, not the detection: a generic app SA holding cluster-admin is a
	//    near-certain over-privilege (Critical, 0.9); a recognized platform
	//    controller is expected-by-design (High, 0.55 — verify, don't auto-fix).
	severity := types.SeverityCritical
	confidence := 0.9
	operatorCaveat := ""
	if operatorLike {
		severity = types.SeverityHigh
		confidence = 0.55
		operatorCaveat = " Every one of these ServiceAccounts is a well-known platform controller in its own namespace (GitOps/operator/policy/CNI), which commonly requires cluster-admin by design — treat as expected and VERIFY against the workload before remediating, do not auto-remove."
	}

	return types.Finding{
		ID:          findingID(r.ID(), bindingKind, bindingNS, bindingName),
		IDBasis:     &types.ResourceRef{Kind: bindingKind, Namespace: bindingNS, Name: bindingName},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("Review cluster-admin grant on ServiceAccount %s/%s", first.Namespace, first.Name),
		Description: fmt.Sprintf(
			"%s %s binds the cluster-admin ClusterRole (%s) to %s. Every pod running under such an account carries a token with unrestricted API access. The grant itself is a fact; whether it is justified depends on what the workload actually does.%s",
			bindingKind, bindingRef, scope, nWord(len(sas), "ServiceAccount", "ServiceAccounts"), operatorCaveat),
		WhyItMatters:      "If a pod holding this token is compromised, the blast radius is the whole cluster: read every Secret, run privileged workloads, erase the evidence. Confirm the workload genuinely needs cluster-wide write before keeping the grant.",
		Evidence:          evidence,
		Severity:          severity,
		Category:          types.CategorySecurity,
		AffectedResources: affected,
		EstimatedEffort:   types.EffortHigh, // requires mapping what the SA actually does before scoping it down
		RemediationYAML:   scopedGrantReplacement(bindingKind, first.Namespace, first.Name),
		Confidence:        confidence,
		Provenance:        provenance(),
	}
}

// scopedGrantReplacement emits a least-privilege skeleton replacing the
// cluster-admin grant. The binding TOPOLOGY is preserved so the remediation
// never silently shrinks a controller's reach:
//
//   - ClusterRoleBinding origin → scoped ClusterRole + ClusterRoleBinding
//     (cluster-wide). A CRB subject is almost always a controller that watches
//     ALL namespaces; downgrading it to a single-namespace RoleBinding would
//     break reconciliation everywhere else.
//   - RoleBinding origin → scoped ClusterRole + RoleBinding (namespace-local),
//     matching the original single-namespace scope.
//
// The rules are placeholders the operator fills from observed behavior; an
// explicit comment warns NOT to delete the original binding until the scoped
// role is verified to cover real usage (else the workload loses access it used).
func scopedGrantReplacement(bindingKind, ns, sa string) string {
	header := fmt.Sprintf(`# Least-privilege replacement for a cluster-admin grant.
# DO NOT delete the original %s until this scoped role is confirmed to cover
# the ServiceAccount's OBSERVED usage — removing it first will break the
# workload. Fill the rules below from what %s actually does (audit logs / what
# it watches), then cut over and remove the cluster-admin binding.
`, bindingKind, sa)

	role := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %[1]s-scoped
rules:
  # fill with the verbs this SA actually uses (placeholder below)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
`, sa)

	var binding string
	if bindingKind == "ClusterRoleBinding" {
		// Preserve cluster-wide reach.
		binding = fmt.Sprintf(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[2]s-scoped
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[2]s-scoped
subjects:
  - kind: ServiceAccount
    name: %[2]s
    namespace: %[1]s
`, ns, sa)
	} else {
		// RoleBinding origin: keep it namespace-local.
		binding = fmt.Sprintf(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: %[2]s-scoped
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[2]s-scoped
subjects:
  - kind: ServiceAccount
    name: %[2]s
    namespace: %[1]s
`, ns, sa)
	}

	return header + role + binding
}

// RequiredKinds — Both binding lists, because a subject bound at only one level would look unbound if the other was denied.
// See deps.go for what belongs in this list.
func (r ClusterAdminServiceAccount) RequiredKinds() []string {
	return []string{"clusterrolebindings", "rolebindings"}
}
