package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type DefaultSATokenAutomount struct{}

func (DefaultSATokenAutomount) ID() string { return "k8s.workload.default-sa-token-automount" }

// 1.1.0 (2026-10-21): judges every pod spec the cluster runs — bare Pods, Jobs and CronJobs too (podTemplates) —
// and no longer reads the token volume the API server injects into every Pod as a sign of a cloud IAM integration.
func (DefaultSATokenAutomount) Version() string { return "1.1.0" }

// Evaluate flags workloads that run under the namespace's default
// ServiceAccount with its API token automounted. Automount precedence
// mirrors Kubernetes: an explicit pod-template setting wins; when the pod is
// silent, the ServiceAccount object's automountServiceAccountToken decides;
// when both are silent, the token is mounted.
//
// Scope: this rule evaluates only the workload kinds that workloads()
// flattens — Deployments, StatefulSets, and DaemonSets. Controller-less bare
// Pods and Jobs/CronJobs that run on the default SA are NOT assessed here, so
// a clean result for a namespace does not prove full default-SA hygiene; it
// means none of its Deployments/StatefulSets/DaemonSets mount the default
// token. (Extending coverage to bare Pods/Jobs lives in the shared workloads
// flattener, out of this rule's scope.)
//
// Severity/impact is graded by what the default SA can actually do: the rule
// cross-references the collected RoleBindings/ClusterRoleBindings to see
// whether anything grants the namespace's default SA real privileges. An
// automounted token bound to nothing is baseline-authenticated only; a token
// bound to a powerful (Cluster)Role is a genuine breakout amplifier. When RBAC
// was not collected (RBAC-denied run), the rule does not assert absence of
// bindings — it states the cross-reference could not be performed.
func (r DefaultSATokenAutomount) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Namespaces whose default SA object opts out of automount — that covers
	// every pod in the namespace that doesn't explicitly opt back in.
	defaultSAOptOut := map[string]bool{}
	for _, sa := range inv.ServiceAccounts {
		if sa.Name == "default" && sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			defaultSAOptOut[sa.Namespace] = true
		}
	}

	// DENIAL GUARD: we can only reason about what the default SA can do if the
	// binding lists were actually collected. If either binding kind was denied
	// / not collected, treat the RBAC picture as unknown and never assert "no
	// bindings reference the default SA".
	rbacCollected := metaCollected(inv, "rolebindings") && metaCollected(inv, "clusterrolebindings")
	// boundRoles["ns"] = sorted, de-duped list of role descriptions bound to
	// that namespace's default SA. Only meaningful when rbacCollected.
	boundRoles := map[string][]string{}
	if rbacCollected {
		boundRoles = defaultSABoundRoles(inv, opts)
	}

	var out []types.Finding
	for _, w := range podTemplates(inv, opts) {
		saName := w.PodSpec.ServiceAccountName
		if saName != "" && saName != "default" {
			continue // dedicated SA — out of this rule's scope
		}
		if pod := w.PodSpec.AutomountServiceAccountToken; pod != nil {
			if !*pod {
				continue // explicit pod-level opt-out
			}
			// explicit true: mounted regardless of the SA object
		} else if defaultSAOptOut[w.Namespace] {
			continue // pod silent, SA-level opt-out applies
		}

		roles := boundRoles[w.Namespace]
		hasBindings := len(roles) > 0
		usesProjectedToken := podLikelyUsesProjectedToken(w.PodSpec)

		out = append(out, types.Finding{
			ID:                findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:           &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:            r.ID(),
			RuleVersion:       r.Version(),
			Title:             fmt.Sprintf("Disable default SA token automount on %s/%s", w.Namespace, w.Name),
			Description:       r.description(w.Kind, w.Namespace, w.Name, rbacCollected, hasBindings, roles),
			WhyItMatters:      whyItMatters(rbacCollected, hasBindings),
			Evidence:          r.evidence(w.Kind, w.Namespace, w.Name, rbacCollected, roles, usesProjectedToken),
			Severity:          severityFor(rbacCollected, hasBindings),
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			RemediationYAML:   automountPatch(w),
			Confidence:        confidenceFor(rbacCollected, hasBindings),
			Provenance:        provenance(),
		})
	}
	return out
}

// description tailors the impact wording to what the default SA can actually
// do. Strong breakout framing only when a binding grants it real power.
func (r DefaultSATokenAutomount) description(kind, ns, name string, rbacCollected, hasBindings bool, roles []string) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"%s %s/%s sets no dedicated ServiceAccount and mounts the default SA's API token into every container. ",
		kind, ns, name)

	switch {
	case rbacCollected && hasBindings:
		fmt.Fprintf(&b,
			"The default SA in %s is granted real privileges (%s), so any code execution inside the pod yields a usable cluster credential rather than a baseline one. ",
			ns, strings.Join(roles, ", "))
	case rbacCollected && !hasBindings:
		// Common inert case: no RoleBinding/ClusterRoleBinding references the
		// default SA, so the token grants only baseline authenticated/discovery
		// access today. Drop the worst-case breakout framing.
		b.WriteString(
			"No RoleBinding or ClusterRoleBinding observed in this cluster references this namespace's default SA, so the token grants only baseline authenticated/discovery access today — but any future RoleBinding silently widens this exposure to every pod already on the default SA. ")
	default:
		// RBAC not collected — do not assert what the token can or cannot do.
		b.WriteString(
			"RBAC bindings were not collected on this run, so what this token can actually do could not be determined; if a RoleBinding or ClusterRoleBinding grants the default SA real privileges, any code execution in the pod yields a usable cluster credential. ")
	}

	b.WriteString(
		"If this workload does need API access, give it a dedicated ServiceAccount with a scoped Role instead. ")
	b.WriteString(
		"Exception: if this pod uses the projected token for cloud IAM (EKS IRSA / Pod Identity, GKE Workload Identity), disabling automount will break that — give it a dedicated SA configured for the integration instead of turning the token off.")
	return b.String()
}

// whyItMatters keeps the breakout-amplifier framing only where the credential
// is actually privileged.
func whyItMatters(rbacCollected, hasBindings bool) string {
	if rbacCollected && !hasBindings {
		return "A mounted token is an unnecessary credential surface: it costs nothing to remove and prevents a future RBAC grant from silently turning every default-SA pod into an authenticated API client."
	}
	return "A mounted token can turn a container compromise into authenticated Kubernetes API access — a common amplifier in cluster breakout chains when the bound SA carries real permissions."
}

// evidence cites the RBAC fact (or its absence of collection) so the line
// corroborates severity instead of paraphrasing the title.
func (r DefaultSATokenAutomount) evidence(kind, ns, name string, rbacCollected bool, roles []string, usesProjectedToken bool) []string {
	ev := []string{fmt.Sprintf(
		"%s %s/%s runs as default SA with token automounted", kind, ns, name)}

	switch {
	case rbacCollected && len(roles) > 0:
		ev = append(ev, fmt.Sprintf(
			"default SA in %s is bound to: %s", ns, strings.Join(roles, ", ")))
	case rbacCollected:
		ev = append(ev, fmt.Sprintf(
			"no Role/ClusterRole binding observed references the default SA in %s (baseline authenticated access only)", ns))
	default:
		ev = append(ev,
			"RBAC bindings not collected this run — privilege of the default SA was not assessed")
	}

	if usesProjectedToken {
		ev = append(ev,
			"pod declares a projected serviceAccountToken volume and/or a cloud-IAM annotation — disabling automount may break a token-projection / IRSA integration; verify before applying")
	}
	return ev
}

// severityFor grades real-world impact: a privileged default SA is a genuine
// breakout amplifier (medium); an inert default SA with no bindings is hygiene
// (low). When RBAC wasn't collected we cannot rule out privilege, but we also
// can't confirm it, so we stay low to avoid overclaiming on an unknown — the
// aggregate rollup still surfaces volume.
func severityFor(rbacCollected, hasBindings bool) types.Severity {
	if rbacCollected && hasBindings {
		return types.SeverityMedium
	}
	// Calibrated 2026-06-13/-16: low for the common inert case. This rule fires
	// on nearly every workload on the default SA; on a real AKS cluster it was
	// the single largest contributor to an unreadable medium pile. A token
	// bound to nothing is an amplifier with nothing to amplify.
	return types.SeverityLow
}

// confidenceFor expresses certainty that THIS IS A PROBLEM, not that a field
// was read. The automount fact is always certain; whether it matters depends
// on the bound privileges.
func confidenceFor(rbacCollected, hasBindings bool) float64 {
	switch {
	case rbacCollected && hasBindings:
		// Real privilege confirmed by an observed binding, and removing an
		// unneeded mounted token is near-universally good hygiene.
		return 0.8
	case rbacCollected && !hasBindings:
		// Certain the token is mounted and certain (from RBAC) it grants
		// nothing today — so it's a real but low-stakes hygiene gap; could be
		// intentional / harmless.
		return 0.5
	default:
		// Could not assess privilege; this is candidate hardening pending the
		// RBAC picture.
		return 0.4
	}
}

// defaultSABoundRoles maps namespace -> sorted role descriptions bound to that
// namespace's default ServiceAccount, across RoleBindings and
// ClusterRoleBindings. Only namespaces in scope (respecting IncludeSystem) get
// entries. Caller must have confirmed both binding kinds were collected.
func defaultSABoundRoles(inv *collect.Inventory, opts Options) map[string][]string {
	set := map[string]map[string]struct{}{}
	add := func(ns, desc string) {
		if !opts.IncludeSystem && isSystemNamespace(ns) {
			return
		}
		if set[ns] == nil {
			set[ns] = map[string]struct{}{}
		}
		set[ns][desc] = struct{}{}
	}

	// RoleBindings: a subject's namespace falls back to the binding's namespace.
	for _, b := range inv.RoleBindings {
		for _, s := range b.Subjects {
			ns, ok := defaultSASubjectNamespace(s, b.Namespace)
			if !ok {
				continue
			}
			add(ns, roleRefDesc(b.RoleRef, "RoleBinding "+b.Name))
		}
	}
	// ClusterRoleBindings: subject must carry its own namespace (no fallback).
	for _, b := range inv.ClusterRoleBindings {
		for _, s := range b.Subjects {
			ns, ok := defaultSASubjectNamespace(s, "")
			if !ok {
				continue
			}
			add(ns, roleRefDesc(b.RoleRef, "ClusterRoleBinding "+b.Name))
		}
	}

	out := make(map[string][]string, len(set))
	for ns, descs := range set {
		list := make([]string, 0, len(descs))
		for d := range descs {
			list = append(list, d)
		}
		sort.Strings(list)
		out[ns] = list
	}
	return out
}

// defaultSASubjectNamespace returns the resolved namespace of a subject that is
// the "default" ServiceAccount, or ok=false if the subject is not a default-SA
// subject we can attribute to a namespace.
func defaultSASubjectNamespace(s rbacv1.Subject, fallbackNS string) (string, bool) {
	if s.Kind != rbacv1.ServiceAccountKind || s.Name != "default" {
		return "", false
	}
	ns := s.Namespace
	if ns == "" {
		ns = fallbackNS
	}
	if ns == "" {
		return "", false // unresolvable subject — nothing to attribute
	}
	return ns, true
}

// roleRefDesc renders a binding's roleRef as a short, reader-facing label and
// notes which binding carried it.
func roleRefDesc(ref rbacv1.RoleRef, via string) string {
	kind := ref.Kind
	if kind == "" {
		kind = "Role"
	}
	return fmt.Sprintf("%s %s (via %s)", kind, ref.Name, via)
}

// podLikelyUsesProjectedToken reports whether the pod spec carries observable
// signals that it deliberately relies on a projected SA token — a projected
// serviceAccountToken volume, or a cloud-IAM annotation/label on the pod
// template. These are exactly the cases where disabling automount would break
// a working integration, so we surface a verify-first caveat rather than
// suppressing the finding outright (read-only specs can't confirm usage).
func podLikelyUsesProjectedToken(spec corev1.PodSpec) bool {
	for _, v := range spec.Volumes {
		// The API server's ServiceAccount admission injects kube-api-access-<suffix> into EVERY pod it mounts a
		// token into; it is the automount itself, not a sign of a cloud IAM integration. A template never carries
		// it, a live Pod always does — so without this every bare Pod read as "likely uses a projected token".
		if v.Projected == nil || strings.HasPrefix(v.Name, "kube-api-access-") {
			continue
		}
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken != nil {
				return true
			}
		}
	}
	return false
}

// metaCollected reports whether a collection step name appears in
// inv.Meta.Collected (and is not denied). Used for the denial guard so the
// rule never asserts observed-absence of bindings that were never listed.
func metaCollected(inv *collect.Inventory, kind string) bool {
	for _, d := range inv.Meta.Denied {
		// Denied entries are formatted "<kind>: <err>" — match the prefix.
		if d == kind || strings.HasPrefix(d, kind+":") {
			return false
		}
	}
	for _, c := range inv.Meta.Collected {
		if c == kind {
			return true
		}
	}
	return false
}

// RequiredKinds — The bindings are how this rule knows what the mounted token can DO — without them the finding is about
// a token of unknown power, which is a different claim.
// See deps.go for what belongs in this list.
func (r DefaultSATokenAutomount) RequiredKinds() []string {
	return podTemplateKinds("clusterrolebindings", "rolebindings", "serviceaccounts")
}

// automountPatch is the change, written where the object keeps its pod spec. A Pod's spec cannot be changed in
// place, so for a Pod it is the line to set where the pod is created.
func automountPatch(w workload) string {
	const caveat = "# Validate before applying: if this pod relies on a projected token for\n" +
		"# cloud IAM (EKS IRSA / Pod Identity, GKE Workload Identity) or actually\n" +
		"# calls the Kubernetes API, do NOT disable automount — give it a dedicated\n" +
		"# ServiceAccount configured for that integration instead.\n"
	head := fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\n", w.objectAPIVersion(), w.Kind, w.Name, w.Namespace)
	switch w.templatePath() {
	case ".spec":
		return caveat + "# A Pod's spec is immutable: set this where the pod is created, then recreate it.\n" + head +
			"spec:\n  automountServiceAccountToken: false\n"
	case ".spec.jobTemplate.spec.template.spec":
		return caveat + head + "spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          automountServiceAccountToken: false\n"
	}
	return caveat + head + "spec:\n  template:\n    spec:\n      automountServiceAccountToken: false\n"
}
