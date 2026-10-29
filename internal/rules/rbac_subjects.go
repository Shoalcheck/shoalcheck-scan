package rules

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// rbac_subjects.go — A BINDING THAT NAMES A SUBJECT NOBODY SHOULD BE BINDING.
//
// This is the other half of internal/rules/rbac_grants.go and deliberately a separate rule. That one reads
// what a ROLE permits and reports the bindings that activate it; this one reads the SUBJECT and says nothing
// about the role's contents. A binding of a harmless role to `system:anonymous` is invisible to the first
// and is the whole point of the second.
//
// FOUR SUBJECTS, FOUR DIFFERENT SENTENCES.
//
//	system:masters is not authorized by RBAC — the API server hard-codes it ABOVE the authorizer, so a
//	member does everything regardless of what any Role says. A binding to it therefore grants nothing it
//	does not already have: it is a signal that somebody wired a break-glass path, and the path is the
//	finding, not the binding's permissions.
//
//	system:anonymous and system:unauthenticated reach a caller who presented no credential. Whether the
//	API server accepts anonymous requests at all is a flag on the control plane (`--anonymous-auth`) that
//	a managed cluster does not expose, so this reading cannot say whether the grant is reachable — only
//	that it was written.
//
//	system:authenticated is every identity the authenticator accepts, which on any cluster includes every
//	ServiceAccount in every namespace. It is the broadest subject that is not a bypass.
//
// WHAT THIS RULE DOES NOT SAY, and it is the same list rbac_grants.go states at length: no effective
// permissions, no severity from syntax alone, no remediation command, no dollars. Removing a grant is a
// decision about who depends on it, and this tool cannot see that.
//
// AND THE ABSENCE OF A BINDING IS NOT THE ABSENCE OF THE GROUP. A client certificate with O=system:masters
// makes its holder a member with no RBAC object anywhere — internal/rules/compliance.go says exactly this
// where CIS 5.1.7 is forced to MANUAL, and the boundary on every finding here repeats it.
type RBACBuiltinSubject struct{}

func (RBACBuiltinSubject) ID() string { return "k8s.rbac.binding-to-builtin-subject" }

// 1.1.0 (2026-10-27, v0.1.1): cluster-admin bound to system:authenticated, system:unauthenticated or system:anonymous
// is critical at any scope. It was medium cluster-wide for system:authenticated and low inside a namespace, so on a
// cluster where cluster-admin was already bound, `gate` passed a change handing full control to every identity.
func (RBACBuiltinSubject) Version() string { return "1.1.0" }

// RequiredKinds — the two binding lists and nothing else. The claim is about a binding's SUBJECT, so the
// roles are not needed and are deliberately not declared: a run that could not read them makes exactly the
// same claim. See deps.go.
func (RBACBuiltinSubject) RequiredKinds() []string {
	return []string{"clusterrolebindings", "rolebindings"}
}

// builtinSubject is one subject that should not appear in a binding, with the two severities the house
// pattern uses: what it means bound cluster-wide, and what it means bound inside one namespace.
type builtinSubject struct {
	kind    string // rbacv1 Subject.Kind
	name    string
	cluster types.Severity
	scoped  types.Severity
	// admin is the severity when the binding points at the built-in ClusterRole cluster-admin, at either scope; ""
	// keeps the two above. THE ONE PLACE THIS RULE LOOKS AT THE ROLE, and only at its name: cluster-admin handed to
	// everybody is full control handed to everybody, and a RoleBinding of it inside kube-system reads every
	// controller's token. system:masters has none — its members already do everything, whatever the role.
	admin types.Severity
	what  string // what the subject IS — the sentence a reader needs before the severity means anything
	// held is how somebody comes to BE this subject, which is what makes an absence of bindings unable to
	// prove an absence of holders. It is per-subject because the answer differs: a group can be asserted by
	// a certificate or a token claim, and system:anonymous is what the API server itself falls back to.
	held string
}

// THE TABLE IS A CLAIM TABLE. Every row is a subject whose membership is decided outside RBAC, which is why
// each one's sentence is about who holds it rather than about what the binding grants.
var builtinSubjects = []builtinSubject{
	{
		kind: "Group", name: "system:masters",
		// NOT SCOPED BY THE BINDING. A RoleBinding naming system:masters grants that role in that namespace,
		// and its members already do everything everywhere — so the namespace does not bound the subject and
		// the severity does not fall with it.
		cluster: types.SeverityHigh, scoped: types.SeverityHigh,
		what: "system:masters is authorized above RBAC: the API server grants its members every action on " +
			"every resource without consulting any Role, so this binding is a signal that a break-glass path " +
			"exists rather than the thing that grants the power",
		held: "a client certificate carrying O=system:masters, an OIDC claim or a provider IAM mapping makes its holder a member with no RBAC object anywhere",
	},
	{
		kind: "User", name: "system:anonymous",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium, admin: types.SeverityCritical,
		what: "system:anonymous is the identity the API server uses for a request that carried no credential",
		held: "every request that reaches the API server without a credential is this identity, whether or not any binding names it",
	},
	{
		kind: "Group", name: "system:unauthenticated",
		cluster: types.SeverityHigh, scoped: types.SeverityMedium, admin: types.SeverityCritical,
		what: "system:unauthenticated is the group every credential-less request belongs to",
		held: "every credential-less request belongs to this group, whether or not any binding names it",
	},
	{
		kind: "Group", name: "system:authenticated",
		cluster: types.SeverityMedium, scoped: types.SeverityLow, admin: types.SeverityCritical,
		what: "system:authenticated is every identity the authenticator accepts, which includes every " +
			"ServiceAccount in every namespace",
		held: "every identity the authenticator accepts belongs to this group, and which identities those are is decided outside the cluster",
	},
}

func (r RBACBuiltinSubject) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// THE DENIAL GUARD. A binding list that was refused is not a cluster without such bindings.
	for _, kind := range r.RequiredKinds() {
		if !metaCollected(inv, kind) {
			return nil
		}
	}

	var out []types.Finding
	for _, b := range inv.ClusterRoleBindings {
		if kubernetesOwnBinding("ClusterRoleBinding", "", b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		out = append(out, r.findingsFor("ClusterRoleBinding", "", b.Name,
			b.RoleRef, b.Subjects, true)...)
	}
	for _, b := range inv.RoleBindings {
		if kubernetesOwnBinding("RoleBinding", b.Namespace, b.Name, b.Labels, b.RoleRef, b.Subjects) {
			continue
		}
		out = append(out, r.findingsFor("RoleBinding", b.Namespace, b.Name,
			b.RoleRef, b.Subjects, false)...)
	}
	return out
}

// bootstrapDefault reports whether the API server wrote this binding itself.
//
// WITHOUT THIS THE RULE IS NOISE ON EVERY CLUSTER IN THE WORLD, measured on a live one before it was added:
// six findings, and all six were the distribution's own — `cluster-admin` to system:masters,
// `system:discovery` and `system:basic-user` to system:authenticated, `system:public-info-viewer` to
// system:unauthenticated. Reporting the objects Kubernetes creates at startup is not a finding about
// anybody's cluster.
//
// THE MARKER IS THE OBJECT'S OWN. `kubernetes.io/bootstrapping: rbac-defaults` is written by the API
// server's bootstrap policy and reconciled on every start, so it is a fact the binding states about itself
// rather than a list of names this rule would have to keep. A name list would also be a guess: it would go
// stale with each Kubernetes release and would silently start excluding somebody's own binding that happened
// to be named the same.
//
// WHAT THAT DELIBERATELY LEAVES IN. A binding created by an installer rather than by the bootstrap policy
// carries no such label — kubeadm's `kube-public/kubeadm:bootstrap-signer-clusterinfo`, which binds
// system:anonymous so that `kubeadm join` can read cluster-info, is exactly that. It is reported, and that is
// the right side to err on: it IS a grant to unauthenticated callers, it is not the API server's, and one
// look at it costs less than a rule that decides for the reader which installers are trustworthy. The
// boundary on every finding says the exclusion is by that label alone.
func bootstrapDefault(labels map[string]string) bool {
	return labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}

// kubernetesOwnBinding lives in bootstrap_policy.go: the label AND the exact upstream tuple.

func (r RBACBuiltinSubject) findingsFor(kind, ns, name string, ref rbacv1.RoleRef,
	subjects []rbacv1.Subject, clusterWide bool) []types.Finding {

	var out []types.Finding
	for _, s := range subjects {
		for _, bs := range builtinSubjects {
			if s.Kind != bs.kind || s.Name != bs.name {
				continue
			}
			sev := bs.scoped
			if clusterWide {
				sev = bs.cluster
			}
			if bs.admin != "" && refsClusterAdmin(ref) {
				sev = bs.admin
			}
			out = append(out, r.finding(kind, ns, name, ref, bs, sev, clusterWide))
		}
	}
	return out
}

func (r RBACBuiltinSubject) finding(kind, ns, name string, ref rbacv1.RoleRef,
	bs builtinSubject, sev types.Severity, clusterWide bool) types.Finding {

	scope := fmt.Sprintf("inside namespace %s", ns)
	if clusterWide {
		scope = "cluster-wide"
	}
	where := name
	if ns != "" {
		where = ns + "/" + name
	}

	return types.Finding{
		ID:          findingID(r.ID(), kind, ns, name+"|"+bs.name),
		IDBasis:     &types.ResourceRef{Kind: kind, Namespace: ns, Name: name + "|" + bs.name},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s %s binds %s %s",
			kind, where, bs.kind, bs.name),
		// THE EXAMPLE FOLLOWS THE SUBJECT. The first version named a client certificate carrying
		// O=system:masters on every finding, including ones about system:anonymous, where it describes a
		// group the binding has nothing to do with. Read on a live finding, which is the only way it showed.
		Description: fmt.Sprintf("%s %s names %s %s as a subject and points at %s %s, %s. %s. This is what "+
			"the binding says; what any holder of that subject can actually do is the union over every "+
			"binding that names it, and the absence of a binding is not the absence of the subject: %s.",
			kind, where, bs.kind, bs.name, ref.Kind, ref.Name, scope, bs.what, bs.held),
		WhyItMatters: bs.what + ", so a binding that names it hands the referenced role to everyone it " +
			"covers at once, without any of them appearing in this or any other object.",
		Evidence: []string{
			fmt.Sprintf("%s %s: subjects include %s %s", kind, where, bs.kind, bs.name),
			fmt.Sprintf("%s %s: roleRef is %s %s, %s", kind, where, ref.Kind, ref.Name, scope),
		},
		Severity:          sev,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: kind, Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}
