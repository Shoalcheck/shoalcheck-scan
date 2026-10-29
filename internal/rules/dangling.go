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

// dangling.go — ONE OBJECT NAMES ANOTHER, AND THE OTHER IS NOT THERE.
//
// From Sweep 2 of the exhaustive-coverage epic (docs/qa/2026-08-29-sweep2-reference-integrity.md), which
// called this family *"the highest-yield of the four, and the one whose findings are unarguable"* — a
// reference that resolves to nothing is a contradiction inside the operator's own configuration, not an
// opinion about best practice.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
//	NOT WHAT IT WILL DO. The reference resolving to nothing is the finding. "The pod will not start" is
//	true for a pod created after the ServiceAccount went away and false for the pod that has been running
//	for a month on a token it already holds — and the snapshot cannot tell which one it is looking at. Same
//	for a binding: whether anything was ever denied is in an audit log we do not read.
//
//	NOT FROM A LIST WE DID NOT READ. Every claim here is an ABSENCE claim over the TARGET list, which
//	makes the denial guard load-bearing in a way it is not for most rules: a denied `serviceaccounts` list
//	would make every workload in the cluster look broken. Both the source and the target kind are checked,
//	per reference, before anything is said.
//
//	NOT ABOUT KINDS WE DO NOT COLLECT. An HPA can scale an Argo Rollout, a KEDA ScaledObject or a bare
//	ReplicaSet — all scalable, none collected. Reporting those as missing would fire on every cluster
//	running a progressive-delivery controller. They are excluded AND COUNTED, because excluding silently
//	would let a reader conclude every autoscaler was checked.
//
//	NOT THE VOLUME PAIR, YET. `PV.spec.claimRef` → PVC and `PVC.spec.volumeName` → PV are both in Sweep
//	2's candidate list and both are deferred here: each is a race between two List calls, and a PV carrying
//	a `claimRef` while `Available` is the ordinary pre-binding state rather than a defect. The states that
//	survive the race are already reported by `UnattachedVolume` reading the phase. Recorded rather than
//	half-built.
//
//	NO DOLLARS. A name that resolves to nothing has no price.
//
// dangling_test.go enforces the phrase list mechanically, and carries the §8.1 adversarial cases: an empty
// `serviceAccountName` means `default`, a RoleBinding may legitimately reference a ClusterRole, and an HPA
// target of an uncollected kind is not a dangle.

// danglingRefs is the shared denial guard: the rule speaks only about a pair of lists it actually read.
func danglingObserved(inv *collect.Inventory, kinds ...string) bool {
	for _, k := range kinds {
		if !observed(inv, k) {
			return false
		}
	}
	return true
}

// ── Rule: a workload names a ServiceAccount that is not there ────────────────────────────────────

// DanglingServiceAccount reports workloads whose pod spec names a ServiceAccount absent from this reading.
type DanglingServiceAccount struct{}

func (DanglingServiceAccount) ID() string      { return "k8s.config.serviceaccount-unresolved" }
func (DanglingServiceAccount) Version() string { return "1.0.0" }

// RequiredKinds — the workload kinds are what is iterated and `serviceaccounts` is what the absence claim
// rests on. All four are load-bearing: a reading without the account list cannot say a name resolves to
// nothing, and a reading without a workload kind is missing the sources entirely.
func (DanglingServiceAccount) RequiredKinds() []string {
	return sortedKinds([]string{"daemonsets", "deployments", "serviceaccounts", "statefulsets"})
}

func (r DanglingServiceAccount) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "serviceaccounts", "deployments", "statefulsets", "daemonsets") {
		return nil
	}
	have := map[string]bool{}
	for _, sa := range inv.ServiceAccounts {
		have[sa.Namespace+"/"+sa.Name] = true
	}

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		name := w.PodSpec.ServiceAccountName
		if name == "" {
			// AN EMPTY FIELD MEANS `default`, NOT MISSING. This is the overwhelmingly common case, and a rule
			// that read "" as a name would report every ordinary workload in the cluster.
			continue
		}
		if have[w.Namespace+"/"+name] {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s %s/%s names a ServiceAccount this reading did not find", w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf("The pod template of %s %s/%s sets serviceAccountName to %q, and no "+
				"ServiceAccount by that name exists in namespace %s in this reading. What happens next depends "+
				"on when each pod was created: a pod already running holds a token it was issued earlier, and "+
				"this reading cannot tell those apart from a pod that has yet to be admitted.",
				w.Kind, w.Namespace, w.Name, name, w.Namespace),
			WhyItMatters: "A ServiceAccount name is resolved by the API server at admission. A name that " +
				"matches nothing is a contradiction between two objects the operator wrote, and it is the kind " +
				"that stays invisible until something restarts.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("%s %s/%s: spec.template.spec.serviceAccountName = %q", w.Kind, w.Namespace, w.Name, name),
				fmt.Sprintf("%s were read in namespace %s, and none is named %q", nWord(countSAsIn(inv, w.Namespace), "ServiceAccount", "ServiceAccounts"), w.Namespace, name),
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func countSAsIn(inv *collect.Inventory, ns string) int {
	n := 0
	for _, sa := range inv.ServiceAccounts {
		if sa.Namespace == ns {
			n++
		}
	}
	return n
}

// ── Rule: a binding names a role that is not there ───────────────────────────────────────────────

// DanglingRoleRef reports RoleBindings and ClusterRoleBindings whose roleRef names nothing.
//
// SWEEP 2 FOUND THIS INSIDE THE FAMILY WE SHIPPED THE DAY BEFORE. `rbac_grants.go` indexes bindings BY their
// roleRef and then iterates the ROLES, so a binding pointing at a role that does not exist never matches
// anything and is structurally invisible to the one rule that reads bindings and roles together. It took the
// census to see it.
type DanglingRoleRef struct{}

func (DanglingRoleRef) ID() string      { return "k8s.rbac.roleref-unresolved" }
func (DanglingRoleRef) Version() string { return "1.0.0" }

func (DanglingRoleRef) RequiredKinds() []string {
	return sortedKinds([]string{"clusterrolebindings", "clusterroles", "rolebindings", "roles"})
}

func (r DanglingRoleRef) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "clusterroles", "roles", "clusterrolebindings", "rolebindings") {
		return nil
	}
	clusterRoles := map[string]bool{}
	for _, cr := range inv.ClusterRoles {
		clusterRoles[cr.Name] = true
	}
	roles := map[string]bool{}
	for _, ro := range inv.Roles {
		roles[ro.Namespace+"/"+ro.Name] = true
	}

	// resolves answers for one roleRef, in the binding's namespace when the ref is namespaced.
	resolves := func(ref rbacv1.RoleRef, ns string) (bool, string) {
		switch ref.Kind {
		case "ClusterRole":
			// A RoleBinding may reference a ClusterRole — that is the normal way to reuse a cluster role in
			// one namespace, and looking it up in the Roles list would report every one of them as dangling.
			return clusterRoles[ref.Name], "ClusterRole " + ref.Name
		case "Role":
			return roles[ns+"/"+ref.Name], fmt.Sprintf("Role %s/%s", ns, ref.Name)
		}
		// An unrecognised roleRef kind is not ours to judge: the API server rejects one at write time, so
		// anything else here came from a path we do not model.
		return true, ""
	}

	var out []types.Finding
	for _, b := range inv.ClusterRoleBindings {
		if b.RoleRef.APIGroup != rbacv1.GroupName {
			continue
		}
		if ok, target := resolves(b.RoleRef, ""); !ok {
			out = append(out, r.finding(inv, "ClusterRoleBinding", "", b.Name, target, b.Subjects))
		}
	}
	for _, b := range inv.RoleBindings {
		if !opts.IncludeSystem && isSystemNamespace(b.Namespace) {
			continue
		}
		if b.RoleRef.APIGroup != rbacv1.GroupName {
			continue
		}
		if ok, target := resolves(b.RoleRef, b.Namespace); !ok {
			out = append(out, r.finding(inv, "RoleBinding", b.Namespace, b.Name, target, b.Subjects))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r DanglingRoleRef) finding(inv *collect.Inventory, kind, ns, name, target string,
	subjects []rbacv1.Subject) types.Finding {

	where := kind + " " + name
	if ns != "" {
		where = fmt.Sprintf("%s %s/%s", kind, ns, name)
	}
	return types.Finding{
		ID:          findingID(r.ID(), kind, ns, name),
		IDBasis:     &types.ResourceRef{Kind: kind, Namespace: ns, Name: name},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("%s names a role this reading did not find", where),
		Description: fmt.Sprintf("%s has roleRef %s, and no such object exists in this reading. A binding "+
			"whose role is absent is a permission grant with nothing on the other end of it — and because the "+
			"binding object itself is valid, nothing in the cluster reports the pairing.",
			where, target),
		WhyItMatters: "A binding is half of a grant. When the other half is missing the binding still exists, " +
			"still names its subjects, and still reads like access that was intended — which is what makes it " +
			"worth naming rather than leaving for somebody to discover while debugging.",
		Evidence: []string{
			snapshotNote(inv),
			// Plain words, no arrow: TestRendered_PaintsOnlyGlyphsItShips caught a U+2192 here, and the
			// report ships no face containing it — so the reader's system would supply it or draw tofu.
			fmt.Sprintf("%s: roleRef names %s", where, target),
			fmt.Sprintf("it names %s", subjectSummary(subjects, ns)),
			fmt.Sprintf("%s and %s were read in this reading", nWord(len(inv.ClusterRoles), "ClusterRole", "ClusterRoles"), nWord(len(inv.Roles), "Role", "Roles")),
		},
		Severity:          types.SeverityLow,
		Category:          types.CategoryConfig,
		AffectedResources: []types.ResourceRef{{Kind: kind, Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}

func subjectSummary(subjects []rbacv1.Subject, fallbackNS string) string {
	if len(subjects) == 0 {
		return "no subject at all"
	}
	var parts []string
	for _, s := range subjects {
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNS
		}
		if s.Kind == rbacv1.ServiceAccountKind && ns != "" {
			parts = append(parts, fmt.Sprintf("ServiceAccount %s/%s", ns, s.Name))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s", s.Kind, s.Name))
	}
	return strings.Join(parts, ", ")
}

// ── Rule: an autoscaler names a workload that is not there ───────────────────────────────────────

// DanglingScaleTarget reports HorizontalPodAutoscalers whose scaleTargetRef names nothing.
type DanglingScaleTarget struct{}

func (DanglingScaleTarget) ID() string      { return "k8s.config.hpa-target-unresolved" }
func (DanglingScaleTarget) Version() string { return "1.0.0" }

func (DanglingScaleTarget) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "horizontalpodautoscalers", "statefulsets"})
}

func (r DanglingScaleTarget) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !danglingObserved(inv, "horizontalpodautoscalers", "deployments", "statefulsets") {
		return nil
	}
	deploys := map[string]bool{}
	for _, d := range inv.Deployments {
		deploys[d.Namespace+"/"+d.Name] = true
	}
	sts := map[string]bool{}
	for _, s := range inv.StatefulSets {
		sts[s.Namespace+"/"+s.Name] = true
	}

	var out []types.Finding
	uncollected := map[string]int{}
	for _, h := range inv.HPAs {
		if !opts.IncludeSystem && isSystemNamespace(h.Namespace) {
			continue
		}
		ref := h.Spec.ScaleTargetRef
		key := h.Namespace + "/" + ref.Name
		switch ref.Kind {
		case "Deployment":
			if !deploys[key] {
				out = append(out, r.finding(inv, h.Namespace, h.Name, ref.Kind, ref.Name, len(inv.Deployments)))
			}
		case "StatefulSet":
			if !sts[key] {
				out = append(out, r.finding(inv, h.Namespace, h.Name, ref.Kind, ref.Name, len(inv.StatefulSets)))
			}
		default:
			// An Argo Rollout, a KEDA ScaledObject, a bare ReplicaSet. All scalable, none collected — and
			// reporting them as missing would fire on every cluster running a progressive-delivery
			// controller. Counted so the exclusion is visible.
			uncollected[ref.Kind]++
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	if len(uncollected) > 0 {
		out = append(out, r.exclusionNote(inv, uncollected))
	}
	return out
}

func (r DanglingScaleTarget) finding(inv *collect.Inventory, ns, name, kind, target string, pool int) types.Finding {
	return types.Finding{
		ID:          findingID(r.ID(), "HorizontalPodAutoscaler", ns, name),
		IDBasis:     &types.ResourceRef{Kind: "HorizontalPodAutoscaler", Namespace: ns, Name: name},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("HorizontalPodAutoscaler %s/%s names a %s this reading did not find", ns, name, kind),
		Description: fmt.Sprintf("HorizontalPodAutoscaler %s/%s has scaleTargetRef %s %s, and no %s by that "+
			"name exists in namespace %s in this reading. The autoscaler object is valid and will keep "+
			"reporting its own status; what is missing is the thing it points at.",
			ns, name, kind, target, kind, ns),
		WhyItMatters: "An autoscaler is a promise that a workload will grow under load. A target that " +
			"resolves to nothing leaves the promise in place and unattached, which reads to anyone auditing " +
			"the namespace as though the workload were autoscaled.",
		Evidence: []string{
			snapshotNote(inv),
			fmt.Sprintf("%s/%s: spec.scaleTargetRef = %s %s", ns, name, kind, target),
			fmt.Sprintf("%s %s read across this cluster, and none is %s/%s", nWord(pool, kind, kind+"s"),
				pick(pool, "was", "were"), ns, target),
		},
		Severity:          types.SeverityMedium,
		Category:          types.CategoryConfig,
		AffectedResources: []types.ResourceRef{{Kind: "HorizontalPodAutoscaler", Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}

// exclusionNote is a confidence-0 disclosure: which autoscalers were NOT assessed, and why. Excluding
// silently would let a reader conclude every HPA in the cluster was checked.
func (r DanglingScaleTarget) exclusionNote(inv *collect.Inventory, uncollected map[string]int) types.Finding {
	kinds := make([]string, 0, len(uncollected))
	for k := range uncollected {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var parts []string
	total := 0
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%d targeting %s", uncollected[k], k))
		total += uncollected[k]
	}
	return types.Finding{
		ID:          findingID(r.ID(), "Cluster", "", "uncollected-target-kinds"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "uncollected-target-kinds"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s %s not checked — the kind is not collected",
			nWord(total, "autoscaler target", "autoscaler targets"), pick(total, "was", "were")),
		Description: fmt.Sprintf("An HorizontalPodAutoscaler can scale anything that publishes the scale "+
			"subresource, including custom resources this audit does not read. %s were not assessed, because "+
			"this reading holds no objects of those kinds and reporting them as missing would say more about "+
			"what was collected than about the cluster.", strings.Join(parts, ", ")),
		WhyItMatters: "A check that silently skips part of its input reads as a check that found nothing " +
			"wrong. This names the part that was skipped so the coverage is legible.",
		Evidence: []string{
			snapshotNote(inv),
			"assessed kinds: Deployment, StatefulSet — the two workload kinds this audit collects",
			"not assessed: " + strings.Join(kinds, ", "),
		},
		Severity:          types.SeverityInfo,
		Category:          types.CategoryConfig,
		AffectedResources: []types.ResourceRef{{Kind: "Cluster"}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        0.0,
		Provenance:        provenance(),
	}
}

var _ = corev1.Pod{}
