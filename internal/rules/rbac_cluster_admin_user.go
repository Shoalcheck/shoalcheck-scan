package rules

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// rbac_cluster_admin_user.go — CLUSTER-ADMIN HELD BY A USER OR A GROUP.
//
// The other half of ClusterAdminServiceAccount, and a separate rule because rule ids are a contract: that one says
// "ServiceAccount" in its id and its findings, and widening it would change what every reading it ever produced
// meant. Until v0.1.1 nothing named this grant. QA bound cluster-admin to `User alice` on a kubeadm cluster and the
// gate passed: cluster-admin's unrestricted rule was already a finding there (kubeadm binds the role to its own admin
// group), so the new binding added a name to an old finding and nothing new — while CIS 5.1.1, which is about every
// subject, was mapped to the ServiceAccount rule alone.
//
// WHAT THIS RULE LEAVES TO ITS NEIGHBOURS, so one binding never carries two findings arguing different things:
//
//	ServiceAccounts are k8s.rbac.cluster-admin-serviceaccount's. A binding naming a ServiceAccount and a User is
//	reported by each rule for its own subjects.
//
//	system:masters, system:anonymous, system:unauthenticated and system:authenticated are
//	k8s.rbac.binding-to-builtin-subject's, because what matters about them is not the role: who holds them is decided
//	outside RBAC, and that rule says so. The persona's acme-break-glass is the case.
//
//	The binding the API server writes for itself — cluster-admin to Group system:masters, labelled
//	kubernetes.io/bootstrapping: rbac-defaults — is excluded by the label AND the exact upstream tuple
//	(bootstrap_policy.go). It names a built-in subject in any case; the check is here so the exclusion is stated
//	where the rule is, not inferred from a table.
//
// AND THE PLATFORM'S OWN, MATCHED WHOLE, WHERE THE READING SHOWS THE PLATFORM: a binding an installer writes on every
// cluster it creates is not news about anybody's cluster, and a high finding on each of them is noise. Only what a
// reading in this repository shows is listed — kubeadm's kubeadm:cluster-admins — in platformClusterRoleBindings,
// and it is skipped only when the reading shows kubeadm's control plane; elsewhere it is reported, its evidence
// saying it matches kubeadm's. A provider's admin binding nobody has captured is reported, and the boundary says so.
//
// RequiredKinds does not gain pods for that check, deliberately. The check can only REMOVE a finding, on positive
// evidence; a reading without pods reports the binding, which is the safe side. Declaring pods would make every
// comparison withhold this rule's findings whenever the pod list was refused — including a gate's, where the
// grant is the thing being judged.
type ClusterAdminUserOrGroup struct{}

func (ClusterAdminUserOrGroup) ID() string      { return "k8s.rbac.cluster-admin-user-or-group" }
func (ClusterAdminUserOrGroup) Version() string { return "1.0.0" }

// RequiredKinds — both binding lists, as the ServiceAccount rule's: a subject bound at only one level would look
// unbound if the other was denied. See deps.go.
func (ClusterAdminUserOrGroup) RequiredKinds() []string {
	return []string{"clusterrolebindings", "rolebindings"}
}

// Evaluate reports every binding that hands the cluster-admin ClusterRole to a User or a Group: ClusterRoleBindings
// (cluster-wide) and RoleBindings (full power inside one namespace). One finding per binding, as the ServiceAccount
// rule does; a binding with several such subjects names each in the evidence and in the affected resources.
func (r ClusterAdminUserOrGroup) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, b := range inv.ClusterRoleBindings {
		if !refsClusterAdmin(b.RoleRef) ||
			kubernetesOwnBinding("ClusterRoleBinding", "", b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		installer, built := platformBinding(inv, b.Name, b.Labels, b.RoleRef, b.Subjects)
		if built {
			continue
		}
		subs := userOrGroupSubjects(b.Subjects)
		if len(subs) == 0 {
			continue
		}
		f := r.finding("ClusterRoleBinding", "", b.Name, "cluster-wide", subs)
		if installer != "" {
			// Reported at the rule's own severity, and said: the reader who knows the cluster is the installer's
			// can tell, and this reading could not.
			f.Evidence = append(f.Evidence, fmt.Sprintf("ClusterRoleBinding %s matches the binding %s writes on "+
				"the clusters it installs, but this reading shows no %s control plane (no kube-apiserver pod in "+
				"kube-system carrying %s's annotation), so it is reported as any binding is", b.Name, installer,
				installer, installer))
		}
		out = append(out, f)
	}
	for _, b := range inv.RoleBindings {
		// NO SYSTEM-NAMESPACE EXCLUSION, whatever --include-system says. That exclusion is for a distribution's own
		// pods; a person or a group granted cluster-admin inside kube-system can read every controller's
		// ServiceAccount token there, which is most of the way to the cluster (security review of e8af2dd4). What is
		// left out is the exact upstream binding, and no upstream RoleBinding points at cluster-admin.
		if !refsClusterAdmin(b.RoleRef) ||
			kubernetesOwnBinding("RoleBinding", b.Namespace, b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		if subs := userOrGroupSubjects(b.Subjects); len(subs) > 0 {
			out = append(out, r.finding("RoleBinding", b.Namespace, b.Name,
				fmt.Sprintf("scoped to namespace %s", b.Namespace), subs))
		}
	}
	return out
}

// userOrGroupSubjects keeps the User and Group subjects this rule reports: every one except the built-in subjects
// binding-to-builtin-subject reports.
func userOrGroupSubjects(subjects []rbacv1.Subject) []rbacv1.Subject {
	var out []rbacv1.Subject
	for _, s := range subjects {
		if (s.Kind != rbacv1.UserKind && s.Kind != rbacv1.GroupKind) || isBuiltinSubject(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func isBuiltinSubject(s rbacv1.Subject) bool {
	for _, bs := range builtinSubjects {
		if s.Kind == bs.kind && s.Name == bs.name {
			return true
		}
	}
	return false
}

// serviceAccountGroup is a Group the API server puts ServiceAccounts in: system:serviceaccounts holds every one,
// system:serviceaccounts:<ns> every one in a namespace.
func serviceAccountGroup(s rbacv1.Subject) bool {
	return s.Kind == rbacv1.GroupKind &&
		(s.Name == "system:serviceaccounts" || strings.HasPrefix(s.Name, "system:serviceaccounts:"))
}

func (r ClusterAdminUserOrGroup) finding(bindingKind, bindingNS, bindingName, scope string, subs []rbacv1.Subject) types.Finding {
	bindingRef := bindingName
	if bindingNS != "" {
		bindingRef = bindingNS + "/" + bindingName
	}
	affected := []types.ResourceRef{{Kind: bindingKind, Namespace: bindingNS, Name: bindingName}}
	evidence := make([]string, 0, len(subs))
	podTokens, credentials := false, 0
	for _, s := range subs {
		evidence = append(evidence, fmt.Sprintf("%s %s: %s %s -> cluster-admin", bindingKind, bindingRef, s.Kind, s.Name))
		// The subject as a structured reference, as the ServiceAccount rule names its ServiceAccounts. A User is
		// often a person's address; named only in free text it would survive --redact, which tokenizes what the
		// affected set carries.
		affected = append(affected, types.ResourceRef{Kind: s.Kind, Name: s.Name})
		if serviceAccountGroup(s) {
			podTokens = true
		} else {
			credentials++
		}
	}
	first := subs[0]

	// Severity/confidence, calibrated to the PROBLEM the way the ServiceAccount rule's are:
	//  - The grant is read verbatim from the binding; the detection is certain.
	//  - A ServiceAccount holding cluster-admin is critical because every pod running as it carries the token. A User
	//    or a Group is a credential held outside the cluster — a certificate, an identity provider's token, a cloud
	//    IAM mapping — so a compromised pod does not hand it over: high. And a human administrator or a platform
	//    team's group is more often intended than an application's account is, so confidence sits between the
	//    ServiceAccount rule's 0.9 for an application and its 0.55 for a platform controller.
	//  - A Group of ServiceAccounts is pod tokens again, every one of them: critical, at the application's 0.9.
	severity, confidence := types.SeverityHigh, 0.7
	var holders []string
	if credentials > 0 {
		holders = append(holders, "Whoever the authenticator maps to "+pick(credentials, "this identity", "these identities")+
			" — a client certificate, an identity provider's token, a cloud IAM mapping — holds unrestricted API "+
			"access, and who that is is decided outside the cluster.")
	}
	if podTokens {
		severity, confidence = types.SeverityCritical, 0.9
		holders = append(holders, "A system:serviceaccounts group holds ServiceAccounts, so every pod running "+
			"under one of them carries a token with unrestricted API access.")
	}

	// A RoleBinding scopes the role to its namespace, so the blast radius the reader is told is that namespace.
	why := "cluster-admin permits every action on every resource. A credential that carries it — leaked, phished or " +
		"left on a laptop — is the whole cluster: every Secret, every workload, the audit trail. Confirm each holder " +
		"needs cluster-wide write, and prefer a narrower role or a break-glass path that is used rarely and watched."
	if bindingKind == "RoleBinding" {
		why = "cluster-admin bound inside a namespace permits every action on every resource in it. A credential " +
			"that carries it — leaked, phished or left on a laptop — is the whole namespace: every Secret in it and " +
			"every workload. Confirm each holder needs it, and prefer a narrower role."
	}

	return types.Finding{
		ID:          findingID(r.ID(), bindingKind, bindingNS, bindingName),
		IDBasis:     &types.ResourceRef{Kind: bindingKind, Namespace: bindingNS, Name: bindingName},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("Review cluster-admin grant on %s %s", first.Kind, first.Name),
		Description: fmt.Sprintf(
			"%s %s binds the cluster-admin ClusterRole (%s) to %s. %s The grant itself is a fact; whether it is "+
				"justified depends on who holds the identity and what they need it for.",
			bindingKind, bindingRef, scope, subjectCount(subs), strings.Join(holders, " ")),
		WhyItMatters:      why,
		Evidence:          evidence,
		Severity:          severity,
		Category:          types.CategorySecurity,
		AffectedResources: affected,
		EstimatedEffort:   types.EffortHigh, // requires finding out what each holder actually does before scoping it down
		Confidence:        confidence,
		Provenance:        provenance(),
	}
}

// subjectCount is "1 User", "2 Groups" or "1 User and 1 Group".
func subjectCount(subs []rbacv1.Subject) string {
	users, groups := 0, 0
	for _, s := range subs {
		if s.Kind == rbacv1.UserKind {
			users++
		} else {
			groups++
		}
	}
	switch {
	case groups == 0:
		return nWord(users, "User", "Users")
	case users == 0:
		return nWord(groups, "Group", "Groups")
	}
	return nWord(users, "User", "Users") + " and " + nWord(groups, "Group", "Groups")
}
