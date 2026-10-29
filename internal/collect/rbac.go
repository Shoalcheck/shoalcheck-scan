package collect

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// rbacGraphCap bounds the RBAC graph so the rendered view is a readable risk
// summary, not a wall of every binding in the cluster. We sort by risk first
// (critical → low), so the cap drops the least interesting low-risk entries.
const rbacGraphCap = 12

// buildRBACGraph turns the collected bindings into a risk-classified RBACEntry
// list for the Architecture → RBAC sub-tab.
//
// THE BAND IS READ FROM THE ROLE, NOT GUESSED FROM ITS NAME. Until 2026-08-28 this product collected the
// bindings and not the Role/ClusterRole bodies, so the band was a function of the roleRef name — and the
// comment on classifyRBACRisk spent fifteen lines explaining why a name-based guess had to round up. The
// bodies have been collected since; this function now joins each binding to the role it names and classifies
// from the rules that role actually carries. What survives from the old code is the fallback, for the two
// cases where there is no body to read, and every entry says which of the two it is (RiskBasis).
//
// Ordering is deterministic: by risk (critical first), then non-system before
// system bindings (RBAC risk in kube-system is real, so it's kept — just sorted
// last), then by binding name. Capped at rbacGraphCap entries.
func buildRBACGraph(inv *Inventory, findings []types.Finding) []types.RBACEntry {
	// Index cluster-admin findings by the binding and subject refs they touch,
	// so an entry can deep-link to the finding card that flagged it — the
	// ServiceAccount rule's and, since v0.1.1, the User/Group rule's.
	findingsByRef := map[resourceKey][]string{}
	for _, f := range findings {
		if f.RuleID != "k8s.rbac.cluster-admin-serviceaccount" && f.RuleID != "k8s.rbac.cluster-admin-user-or-group" {
			continue
		}
		for _, r := range f.AffectedResources {
			k := resourceKey{r.Kind, r.Namespace, r.Name}
			findingsByRef[k] = append(findingsByRef[k], f.ID)
		}
	}

	// The role bodies, indexed the way a roleRef addresses them. A RoleBinding may name a ClusterRole, so the
	// kind is part of the key; a Role is addressed within the binding's own namespace.
	clusterRoles := make(map[string][]rbacv1.PolicyRule, len(inv.ClusterRoles))
	for _, cr := range inv.ClusterRoles {
		clusterRoles[cr.Name] = cr.Rules
	}
	roles := make(map[string][]rbacv1.PolicyRule, len(inv.Roles))
	for _, r := range inv.Roles {
		roles[r.Namespace+"/"+r.Name] = r.Rules
	}
	// A REFUSED READ IS NOT AN EMPTY ONE. When the kind was denied there is no body to look up and the band
	// falls back to the name; when the kind was read, a miss means the roleRef names nothing in this reading.
	haveClusterRoles := inv.Meta.HasCollected("clusterroles")
	haveRoles := inv.Meta.HasCollected("roles")

	var entries []types.RBACEntry

	add := func(bindingKind, bindingNS, bindingName string, roleRef rbacv1.RoleRef, subjects []rbacv1.Subject) {
		subj := firstSubject(subjects)
		if subj == "" {
			return // a binding with no subjects grants nothing — nothing to show
		}
		var (
			body     []rbacv1.PolicyRule
			found    bool
			kindRead bool
		)
		if roleRef.Kind == "Role" {
			body, found = roles[bindingNS+"/"+roleRef.Name]
			kindRead = haveRoles
		} else {
			body, found = clusterRoles[roleRef.Name]
			kindRead = haveClusterRoles
		}
		risk, basis := classifyRBACRisk(roleRef, body, found, kindRead)
		ids := findingIDsFor(findingsByRef, bindingKind, bindingNS, bindingName, subjects)
		entries = append(entries, types.RBACEntry{
			Subject:     subj,
			Binding:     bindingName,
			Role:        roleRef.Name,
			Risk:        risk,
			RiskBasis:   basis,
			FindingIDs:  ids,
			Description: rbacDescription(subj, roleRef.Name),
		})
	}

	for _, b := range inv.ClusterRoleBindings {
		add("ClusterRoleBinding", "", b.Name, b.RoleRef, b.Subjects)
	}
	for _, b := range inv.RoleBindings {
		add("RoleBinding", b.Namespace, b.Name, b.RoleRef, b.Subjects)
	}

	sortRBACEntries(entries)
	if len(entries) > rbacGraphCap {
		entries = entries[:rbacGraphCap]
	}
	return entries
}

// resourceKey is the (kind, namespace, name) tuple used to match a finding's
// AffectedResources against an RBAC binding and its subjects.
type resourceKey struct{ kind, ns, name string }

// findingIDsFor collects the IDs of any cluster-admin findings whose affected
// resources reference this binding or one of its subjects.
func findingIDsFor(idx map[resourceKey][]string, bindingKind, bindingNS, bindingName string, subjects []rbacv1.Subject) []string {
	seen := map[string]bool{}
	var out []string
	gather := func(k resourceKey) {
		for _, id := range idx[k] {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	gather(resourceKey{bindingKind, bindingNS, bindingName})
	for _, s := range subjects {
		if s.Kind == rbacv1.ServiceAccountKind {
			ns := s.Namespace
			if ns == "" {
				ns = bindingNS
			}
			gather(resourceKey{"ServiceAccount", ns, s.Name})
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// firstSubject renders the first subject as "ns/name" for ServiceAccounts (a
// SA's namespace is load-bearing) or "Kind/name" for Users/Groups.
func firstSubject(subjects []rbacv1.Subject) string {
	if len(subjects) == 0 {
		return ""
	}
	s := subjects[0]
	if s.Kind == rbacv1.ServiceAccountKind {
		ns := s.Namespace
		if ns == "" {
			ns = "default" // a SA subject without a namespace defaults to "default"
		}
		return ns + "/" + s.Name
	}
	return s.Kind + "/" + s.Name
}

// The three bases a band can rest on. They are values on the wire, so they are named here rather than spelled
// as literals at the call site.
const (
	riskBasisRules      = "rules"      // the role's own PolicyRules were in this reading
	riskBasisName       = "name"       // the role kind was refused; the band is a guess from the name
	riskBasisUnresolved = "unresolved" // the kind was read and this roleRef was not among it
)

// classifyRBACRisk returns the band for one binding and the basis that band rests on.
//
// WITH THE BODY, THIS IS ARITHMETIC. A PolicyRule is a declaration; reading it is not inference, so a band
// derived from one is as strong a claim as the PDB arithmetic elsewhere in this build.
//
// WITHOUT IT, IT IS A GUESS, AND IT SAYS SO. The name-based fallback is kept for exactly two cases — the role
// kind was refused, or the roleRef names nothing this reading saw — and both are reported through the basis
// so no surface can render a guess as a reading. The fallback's asymmetry is the one the old code had and it
// is still right: erring LOUD costs a reader a second of attention, erring QUIET hides the binding they came
// to find. A custom ClusterRole named "prod-readonly-viewer" can grant `secrets: list`, and an earlier version
// of this function classified it low purely because its name contained "read" and "view" — a string its author
// chose freely. So only Kubernetes' own four user-facing ClusterRoles may produce a definitive low or high
// band from a name; anything else that merely sounds powerful rounds UP, and anything that merely sounds
// harmless rounds to medium ("unknown"), never to low.
func classifyRBACRisk(ref rbacv1.RoleRef, body []rbacv1.PolicyRule, found, kindRead bool) (band, basis string) {
	if found {
		return bandFromRules(body), riskBasisRules
	}
	if kindRead {
		return bandFromName(ref), riskBasisUnresolved
	}
	return bandFromName(ref), riskBasisName
}

// bandFromRules is the band a role's own rules justify.
//
// The bands mirror what internal/rules already says about the same shapes, so the graph's summary and the
// findings cannot disagree: an unrestricted rule and the three escalation primitives are critical, the
// high-value grants and any write verb are high, and a role that can only read is low.
//
// A ROLE WITH NO RULES IS LOW BECAUSE IT GRANTS NOTHING. That is a reading, not an absence: the body was in
// this snapshot and it was empty.
func bandFromRules(rules []rbacv1.PolicyRule) string {
	band := "low"
	raise := func(b string) {
		if riskRank(b) < riskRank(band) {
			band = b
		}
	}
	for _, r := range rules {
		// Escalation primitives: each one lets its holder grant more than it holds, so scope does not soften
		// them. `bind` and `escalate` are RBAC-only verbs; `impersonate` acts as another identity outright.
		for _, v := range r.Verbs {
			switch strings.ToLower(v) {
			case "escalate", "bind", "impersonate":
				raise("critical")
			}
		}
		// `*` on `*` on `*` in ONE rule is what cluster-admin is. Read as one rule, never as the union across
		// several: three rules that between them name every group, verb and resource are an operator's
		// generated role, and calling that "everything" would be a claim about a union nobody wrote.
		if hasStarIn(r.APIGroups) && hasStarIn(r.Resources) && hasStarIn(r.Verbs) {
			raise("critical")
		}
		// A rule carrying only nonResourceURLs (/healthz and friends) names no resource and grants no object
		// access, so it must not be read as an unqualified verb list.
		if len(r.Resources) == 0 {
			continue
		}
		if grantsSecretRead(r) {
			raise("high")
		}
		for _, v := range r.Verbs {
			switch strings.ToLower(v) {
			case "create", "update", "patch", "delete", "deletecollection", "*":
				raise("high")
			}
		}
	}
	return band
}

// grantsSecretRead reports whether one rule permits reading Secrets — the grant behind CIS 5.1.2, and the one
// a name can never be trusted about. A Secret's value is the credential itself.
func grantsSecretRead(r rbacv1.PolicyRule) bool {
	inCore := false
	for _, g := range r.APIGroups {
		if g == "" || g == "*" {
			inCore = true
			break
		}
	}
	if !inCore {
		return false
	}
	named := false
	for _, res := range r.Resources {
		if res == "secrets" || res == "*" {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	for _, v := range r.Verbs {
		switch strings.ToLower(v) {
		case "get", "list", "watch", "*":
			return true
		}
	}
	return false
}

// hasStarIn reports whether a rule's list is the unrestricted `*`. In a rule, `*` is a claim about the role's
// own text — not a wildcard we are matching against.
func hasStarIn(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

// bandFromName is the fallback, used only where there is no body to read.
func bandFromName(ref rbacv1.RoleRef) string {
	name := strings.ToLower(ref.Name)
	switch {
	// The built-ins, matched exactly: Kubernetes defines these rules, so the name IS evidence.
	case name == "cluster-admin":
		return "critical"
	case name == "admin" || name == "edit":
		return "high"
	case name == "view":
		return "low"

	// Custom names. Rounding up is a safe guess; rounding down is not, so there is no
	// corresponding "sounds read-only" branch.
	case strings.Contains(name, "admin") || strings.Contains(name, "edit") || strings.Contains(name, "write"):
		return "high"

	default:
		// Unknown custom role, including anything named "*-viewer" or "readonly-*": the rules
		// are unread, so the honest band is unknown.
		return "medium"
	}
}

// rbacDescription is the one-line plain-English summary shown under the entry.
// subject is "ns/name" for ServiceAccounts (from firstSubject) or "Kind/name"
// for Users/Groups.
func rbacDescription(subject, role string) string {
	switch {
	case strings.HasPrefix(subject, "User/"):
		return fmt.Sprintf("User %s bound to %s", strings.TrimPrefix(subject, "User/"), role)
	case strings.HasPrefix(subject, "Group/"):
		return fmt.Sprintf("Group %s bound to %s", strings.TrimPrefix(subject, "Group/"), role)
	default:
		// "ns/name" — a ServiceAccount.
		return fmt.Sprintf("ServiceAccount %s bound to %s", subject, role)
	}
}

// riskRank orders risk bands most- to least-severe for sorting.
func riskRank(risk string) int {
	switch risk {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// entryInSystemNS reports whether an entry's subject lives in a system
// namespace — used only to sort system bindings last (never to drop them).
func entryInSystemNS(e types.RBACEntry) bool {
	if i := strings.IndexByte(e.Subject, '/'); i >= 0 {
		return isSystemNamespace(e.Subject[:i])
	}
	return false
}

// sortRBACEntries imposes the deterministic order: risk (critical first), then
// non-system before system, then binding name, then subject (final tiebreak).
func sortRBACEntries(entries []types.RBACEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if ra, rb := riskRank(a.Risk), riskRank(b.Risk); ra != rb {
			return ra < rb
		}
		if sa, sb := entryInSystemNS(a), entryInSystemNS(b); sa != sb {
			return !sa // non-system (false) sorts before system (true)
		}
		if a.Binding != b.Binding {
			return a.Binding < b.Binding
		}
		return a.Subject < b.Subject
	})
}

// deriveHighlights turns the finding set into the security + reliability stat
// tiles shown in each section's bento row. Counts are by ruleID; a tile is
// emitted only when its value is > 0 (no "0 critical" noise); at most 3 tiles
// per section, in the order listed below.
func deriveHighlights(findings []types.Finding) []types.Highlight {
	byRule := map[string]int{}
	critical := 0
	for _, f := range findings {
		byRule[f.RuleID]++
		if f.Severity == types.SeverityCritical {
			critical++
		}
	}

	var out []types.Highlight

	// security — at most 3, in priority order.
	sec := []types.Highlight{
		highlight("security", "Critical findings", critical,
			"Severity-critical findings across all categories", toneIfPositive(critical, "critical")),
		highlight("security", "Privileged workloads", byRule["k8s.workload.privileged-host-access"],
			"Workloads with privileged or host-level access", toneIfPositive(byRule["k8s.workload.privileged-host-access"], "warn")),
		highlight("security", "Cluster-admin ServiceAccounts", byRule["k8s.rbac.cluster-admin-serviceaccount"],
			"Bindings granting cluster-admin to a ServiceAccount", toneIfPositive(byRule["k8s.rbac.cluster-admin-serviceaccount"], "critical")),
		highlight("security", "Cluster-admin users and groups", byRule["k8s.rbac.cluster-admin-user-or-group"],
			"Bindings granting cluster-admin to a User or a Group", toneIfPositive(byRule["k8s.rbac.cluster-admin-user-or-group"], "warn")),
	}
	out = append(out, emitUpTo(sec, 3)...)

	// reliability — at most 3, in priority order.
	rel := []types.Highlight{
		highlight("reliability", "Single points of failure", byRule["k8s.workload.single-replica-no-pdb"],
			"Single-replica workloads with no PodDisruptionBudget", toneIfPositive(byRule["k8s.workload.single-replica-no-pdb"], "critical")),
		highlight("reliability", "Workloads without probes", byRule["k8s.workload.no-probes"],
			"Workloads missing liveness/readiness probes", toneIfPositive(byRule["k8s.workload.no-probes"], "warn")),
		highlight("reliability", "Drain-blocking PDBs", byRule["k8s.reliability.pdb-blocks-drains"],
			"PodDisruptionBudgets that can block node drains", toneIfPositive(byRule["k8s.reliability.pdb-blocks-drains"], "warn")),
	}
	out = append(out, emitUpTo(rel, 3)...)

	return out
}

// highlight builds a tile; Value is empty when count == 0 so emitUpTo can skip it.
func highlight(section, label string, count int, detail, tone string) types.Highlight {
	if count == 0 {
		return types.Highlight{} // sentinel zero-value; dropped by emitUpTo
	}
	return types.Highlight{
		Section: section,
		Label:   label,
		Value:   fmt.Sprintf("%d", count),
		Detail:  detail,
		Tone:    tone,
	}
}

// toneIfPositive returns critTone when count > 0, else "info" (unused once the
// tile is dropped, but keeps the data honest).
func toneIfPositive(count int, critTone string) string {
	if count > 0 {
		return critTone
	}
	return "info"
}

// emitUpTo drops zero-value (skipped) tiles and caps the rest at max.
func emitUpTo(tiles []types.Highlight, max int) []types.Highlight {
	var out []types.Highlight
	for _, t := range tiles {
		if t.Value == "" { // zero-value sentinel from highlight()
			continue
		}
		out = append(out, t)
		if len(out) == max {
			break
		}
	}
	return out
}
