package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// topology_posture.go — FACTS ABOUT THE SHAPE OF THE CLUSTER AND WHO OWNS WHAT IN IT.
//
// Phase 1, all overlap-empty rows. What binds them is that each is a claim about STRUCTURE — how many of
// something there is, or who is responsible for it — rather than about a value being wrong.
//
//	NO DOLLARS. A control-plane count has no price, and an unowned pod's cost is already in node-headroom.

// ── Rule: a control plane that is one node ───────────────────────────────────────────────────────

// SingleControlPlaneNode reports a cluster whose control-plane node count is one.
//
// ON A MANAGED CLUSTER THIS RULE IS SILENT BY CONSTRUCTION, and that is correct rather than a gap: EKS, AKS
// and GKE do not expose control-plane nodes through the node list at all, so a managed cluster shows ZERO
// control-plane nodes and zero is not one. The claim is only makeable where the nodes are visible, which is
// exactly where it is actionable.
type SingleControlPlaneNode struct{}

func (SingleControlPlaneNode) ID() string      { return "k8s.reliability.single-control-plane" }
func (SingleControlPlaneNode) Version() string { return "1.0.0" }

func (SingleControlPlaneNode) RequiredKinds() []string { return sortedKinds([]string{"nodes"}) }

// controlPlaneLabels are the two labels Kubernetes has used for a control-plane node. Both are checked
// because the older one survives on clusters upgraded in place, and reading only the current one would
// report a three-node control plane as absent.
var controlPlaneLabels = []string{
	"node-role.kubernetes.io/control-plane",
	"node-role.kubernetes.io/master",
}

func (r SingleControlPlaneNode) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "nodes") {
		return nil
	}
	var cp []string
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		for _, l := range controlPlaneLabels {
			if _, ok := n.Labels[l]; ok {
				cp = append(cp, n.Name)
				break
			}
		}
	}
	// ZERO IS NOT ONE. A managed control plane is invisible to the node list, and reporting its absence
	// as a single point of failure would fire on every EKS, AKS and GKE cluster in existence.
	if len(cp) != 1 {
		return nil
	}
	return []types.Finding{{
		ID:          findingID(r.ID(), "Node", "", cp[0]),
		IDBasis:     &types.ResourceRef{Kind: "Node", Namespace: "", Name: cp[0]},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("The control plane is one node (%s)", cp[0]),
		Description: fmt.Sprintf("Exactly one of the %s in this reading carries a control-plane "+
			"role label: %s. A single control-plane node means the API server, scheduler and controller "+
			"manager have one host between them. Whether etcd is on that host or external is not readable "+
			"from the node list.", nWord(len(inv.Nodes), "node", "nodes"), cp[0]),
		WhyItMatters: "While that node is unavailable nothing can be scheduled, no controller reconciles " +
			"and no kubectl command succeeds — the workloads already running keep running, which is what " +
			"makes it easy to leave in place after it was set up for a proof of concept.",
		Evidence: []string{
			snapshotNote(inv),
			fmt.Sprintf("1 of %s carries a control-plane role label: %s", nWord(len(inv.Nodes), "node", "nodes"), cp[0]),
			"both node-role.kubernetes.io/control-plane and the older .../master are checked, because the " +
				"older label survives on clusters upgraded in place",
			"a MANAGED control plane is not visible in the node list at all, so this rule is silent on EKS, " +
				"AKS and GKE rather than reporting them as having none",
		},
		Severity:          types.SeverityMedium,
		Category:          types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "Node", Name: cp[0]}},
		EstimatedEffort:   types.EffortHigh,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

// ── Rule: a pod no controller owns ───────────────────────────────────────────────────────────────

// UnmanagedPod reports running pods with no controller owner reference.
type UnmanagedPod struct{}

func (UnmanagedPod) ID() string      { return "k8s.reliability.unmanaged-pod" }
func (UnmanagedPod) Version() string { return "1.0.0" }

func (UnmanagedPod) RequiredKinds() []string { return sortedKinds([]string{"pods"}) }

func (r UnmanagedPod) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") {
		return nil
	}
	byNS := map[string][]string{}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		// A FINISHED POD IS NOT AN UNMANAGED ONE — every `kubectl run --rm` and every completed Job pod
		// whose owner was garbage-collected would otherwise be reported.
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if p.DeletionTimestamp != nil {
			continue
		}
		if controllerRef(*p) != nil {
			continue
		}
		// A STATIC POD IS OWNED BY A KUBELET, NOT BY NOTHING. The mirror pod carries this annotation, and
		// reporting it would say a control-plane component is unmanaged when it is managed by a file on
		// disk — which is the one place this rule's remediation would be actively wrong.
		if _, mirror := p.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
			continue
		}
		byNS[p.Namespace] = append(byNS[p.Namespace], p.Name)
	}
	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	var out []types.Finding
	for _, ns := range nss {
		names := byNS[ns]
		sort.Strings(names)
		refs := make([]types.ResourceRef, 0, len(names))
		for _, n := range names {
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: ns, Name: n})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Namespace", ns, "unmanaged-pods"),
			IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: ns, Name: "unmanaged-pods"},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s in %s %s no controller", nWord(len(names), "pod", "pods"), ns,
				pick(len(names), "has", "have")),
			Description: fmt.Sprintf("%s in namespace %s carry no controller ownerReference. "+
				"Nothing recreates a pod like this: if its node is drained, fails or is replaced, the pod "+
				"is gone and no Deployment, StatefulSet, DaemonSet or Job notices.", nWord(len(names), "pod", "pods"), ns),
			WhyItMatters: "An unowned pod is invisible to every operation that assumes a controller — a " +
				"rollout, a drain, a node upgrade. It is usually a debugging pod somebody left behind, and " +
				"occasionally it is something load-bearing that was applied by hand.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("%s in %s with no controller ownerReference: %s", nWord(len(names), "pod", "pods"), ns, strings.Join(names, ", ")),
				"static (mirror) pods are excluded: their controller is a file on the node's disk, so they " +
					"are managed by something this reading cannot see rather than by nothing",
				"pods in a terminal phase are excluded — a completed Job's pod outliving its owner is " +
					"ordinary garbage collection, not an unmanaged workload",
			},
			Severity:          types.SeverityLow,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

// ── Rule: pods covered by more than one PodDisruptionBudget ──────────────────────────────────────

// PodCoveredByTwoPDBs reports pods matched by more than one PDB.
//
// THE EVICTION API REFUSES OUTRIGHT when two budgets cover one pod — it does not intersect them, it errors.
// So this is not a preference: it is a configuration in which no voluntary eviction of those pods can
// succeed at all, which makes it a different claim from pdb-blocks-drains (a budget whose arithmetic leaves
// no room) and is why the census marked it overlap-empty.
type PodCoveredByTwoPDBs struct{}

func (PodCoveredByTwoPDBs) ID() string      { return "k8s.config.pod-covered-by-two-pdbs" }
func (PodCoveredByTwoPDBs) Version() string { return "1.0.0" }

func (PodCoveredByTwoPDBs) RequiredKinds() []string {
	return sortedKinds([]string{"poddisruptionbudgets", "pods"})
}

func (r PodCoveredByTwoPDBs) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "pods") || !observed(inv, "poddisruptionbudgets") {
		return nil
	}
	type cover struct {
		pods []string
		pdbs []string
	}
	byNS := map[string]*cover{}

	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		var covering []string
		for j := range inv.PDBs {
			pdb := &inv.PDBs[j]
			if pdb.Namespace != p.Namespace {
				continue
			}
			sel := pdbSelector(pdb)
			// A NIL SELECTOR MATCHES NOTHING here rather than everything. pdbSelector returns nil when the
			// selector is absent or unparseable, and treating that as "matches all" would report every pod
			// in the namespace as doubly covered off one malformed object.
			if sel == nil || !sel.Matches(labels.Set(p.Labels)) {
				continue
			}
			covering = append(covering, pdb.Name)
		}
		if len(covering) < 2 {
			continue
		}
		c := byNS[p.Namespace]
		if c == nil {
			c = &cover{}
			byNS[p.Namespace] = c
		}
		c.pods = append(c.pods, p.Name)
		for _, n := range covering {
			if !contains(c.pdbs, n) {
				c.pdbs = append(c.pdbs, n)
			}
		}
	}

	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	var out []types.Finding
	for _, ns := range nss {
		c := byNS[ns]
		sort.Strings(c.pods)
		sort.Strings(c.pdbs)
		refs := []types.ResourceRef{}
		for _, n := range c.pdbs {
			refs = append(refs, types.ResourceRef{Kind: "PodDisruptionBudget", Namespace: ns, Name: n})
		}
		for _, n := range c.pods {
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: ns, Name: n})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Namespace", ns, strings.Join(c.pdbs, "|")),
			IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: ns, Name: strings.Join(c.pdbs, "|")},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s in %s %s covered by %d PodDisruptionBudgets",
				nWord(len(c.pods), "pod", "pods"), ns, pick(len(c.pods), "is", "are"), len(c.pdbs)),
			Description: fmt.Sprintf("In namespace %s, %s are selected by more than one "+
				"PodDisruptionBudget (%s). The eviction API does not combine overlapping budgets — it "+
				"refuses the eviction and returns an error naming the conflict.",
				ns, nWord(len(c.pods), "pod", "pods"), strings.Join(c.pdbs, ", ")),
			WhyItMatters: "Both budgets look correct on their own, and each is usually owned by a " +
				"different chart or team. The conflict is only visible at the moment somebody drains a " +
				"node, which is the worst moment to discover it.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("PodDisruptionBudgets covering the same pods in %s: %s", ns, strings.Join(c.pdbs, ", ")),
				fmt.Sprintf("%s matched by more than one of them: %s", nWord(len(c.pods), "pod", "pods"), strings.Join(c.pods, ", ")),
				"a PDB whose selector could not be read is treated as matching nothing, so one malformed " +
					"budget cannot make every pod in the namespace look doubly covered",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
