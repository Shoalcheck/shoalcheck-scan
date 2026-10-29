package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The hostname key, kept local to this file. Zone and region live in collect.ZoneOf / collect.RegionOf,
// which own the GA-then-beta fallback — a label read here would be a second reader with a different answer.
const (
	aaLabelHostname = "kubernetes.io/hostname"
)

// NoAntiAffinity flags multi-replica Deployments/StatefulSets with neither
// podAntiAffinity nor topologySpreadConstraints. We can assert only the
// spec-field absence (certain); the availability impact is an unverified
// worst case. Real placement depends on the scheduler's default
// SelectorSpread, node count, and taints — none of which we collect — so the
// finding flags missing spread intent, not a proven co-location.
//
// Feasibility gate: spreading is only meaningful when there is more than one
// place to spread to. We read inv.Nodes to count distinct schedulable nodes
// (and distinct zones); a single-node cluster cannot spread at all, so the
// finding is suppressed there rather than recommending an unsatisfiable
// constraint. When the API never returned the node list (RBAC-denied /
// timed-out — see inv.Meta.Denied), we cannot prove the cluster is single-node,
// so we keep the finding but caveat that spread feasibility is unverified
// instead of fabricating a node count.
type NoAntiAffinity struct{}

func (NoAntiAffinity) ID() string      { return "k8s.workload.no-anti-affinity" }
func (NoAntiAffinity) Version() string { return "1.0.0" }

func (r NoAntiAffinity) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Count distinct placement domains from the collected node list. Honor the
	// denial guard: only trust a zero/low count when nodes were actually
	// collected. If "nodes" is absent from Meta.Collected, treat topology as
	// unknown (nodesObserved=false) rather than asserting a single-node cluster.
	nodesObserved := aaNodesCollected(inv, "nodes")
	nodeCount, zoneCount := schedulableTopology(inv.Nodes)

	// Single-node cluster: spreading is physically impossible and buys zero
	// availability (every pod dies with the one node regardless of spread).
	// Suppress entirely — but only when we actually observed the node list.
	if nodesObserved && nodeCount < 2 {
		return nil
	}

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		if w.Kind == "DaemonSet" || w.Replicas < 2 {
			continue // DaemonSets are node-bound; one replica has nothing to spread
		}
		// Presence-only check: a non-empty podAntiAffinity OR any
		// topologySpreadConstraints entry counts as declared spread intent.
		// We deliberately do NOT validate effectiveness here (e.g. a soft
		// preferred rule on an irrelevant topologyKey, or a huge maxSkew can
		// still leave replicas co-located). Validating term/key correctness
		// would need the scheduler's view we don't collect, so this is an
		// intentional conservative pass, not a verified "this workload is
		// spread". An EMPTY &PodAntiAffinity{} (no required and no preferred
		// terms) carries no spread intent and is treated as absent.
		if hasPodAntiAffinityTerms(&w) {
			continue
		}
		if len(w.PodSpec.TopologySpreadConstraints) > 0 {
			continue
		}

		// Does a PDB already cover this workload? If so, the voluntary-drain
		// half of the risk is bounded by the budget; we reframe around
		// involuntary node failure instead of claiming "drain takes several
		// down together".
		pdbBounded := antiAffinityPDBCovers(inv.PDBs, w.Namespace, w.PodLabels)

		// Build the failure-mode clause honestly given what we know about
		// topology and any covering PDB.
		var failureClause string
		switch {
		case pdbBounded:
			failureClause = "The scheduler may co-locate replicas on one node, so an involuntary failure of that node could take several down together. (A PodDisruptionBudget already bounds how many pods a voluntary drain can evict at once, so the drain blast radius is limited; the involuntary node-failure exposure remains.)"
		default:
			failureClause = "The scheduler may co-locate replicas on one node, so one node failure or drain could take several down together."
		}

		// Severity defaults to Medium (likely reliability gap for a real
		// multi-replica workload). It drops to Low when the only spread axis
		// available is hostname-level (single zone observed) — spread still
		// helps against single-node loss but cannot protect against an AZ
		// outage, so the upside is narrower.
		severity := types.SeverityMedium
		var topologyNote string
		if nodesObserved {
			switch {
			case zoneCount < 2:
				// Single AZ (or zone labels absent): only hostname spread is
				// possible. Narrower benefit -> Low.
				severity = types.SeverityLow
				topologyNote = fmt.Sprintf(
					" Observed %s in a single availability zone, so only host-level spread is possible (a zone outage would still take all replicas).", nWord(nodeCount, "schedulable node", "schedulable nodes"))
			case w.Replicas > int32(nodeCount):
				// More replicas than nodes: spread is bounded by node count;
				// perfect one-per-node placement is impossible.
				topologyNote = fmt.Sprintf(
					" Observed %s across %s; with %d replicas, host-level spread is bounded by node count and cannot place one replica per node.", nWord(nodeCount, "schedulable node", "schedulable nodes"), nWord(zoneCount, "zone", "zones"), w.Replicas)
			default:
				topologyNote = fmt.Sprintf(
					" Observed %s across %s.", nWord(nodeCount, "schedulable node", "schedulable nodes"),

					// Nodes not collected: do not assert a count. Caveat feasibility.
					nWord(zoneCount, "zone", "zones"))
			}
		} else {

			topologyNote = " Node topology was not collected (node list denied or not observed), so the number of distinct nodes/zones available for spread is unverified."
		}

		// StatefulSet caveat: for quorum/leader-elected stateful systems, a
		// topology spread constraint does NOT, on its own, make the workload
		// HA. A small (e.g. 2-member) set has no quorum surviving one loss, and
		// spread addresses neither split-brain nor quorum loss. The real fix is
		// adequate replica count plus application-level HA; spread only
		// complements that.
		why := "Replicas co-located on one node die together — without a spread rule the redundancy you pay for may buy less availability than the replica count implies."
		if w.Kind == "StatefulSet" {
			why += " For stateful/quorum systems, a spread constraint complements but does not replace adequate replica count and application-level HA — adding topologySpreadConstraints alone does not make a small (e.g. 2-member) datastore highly available or resolve quorum/split-brain risk."
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Spread %s/%s replicas across nodes", w.Namespace, w.Name),
			Description: fmt.Sprintf(
				"%s %s/%s runs %d replicas but declares no podAntiAffinity and no topologySpreadConstraints. %s%s",
				w.Kind, w.Namespace, w.Name, w.Replicas, failureClause, topologyNote),
			WhyItMatters: why,
			Evidence: []string{
				fmt.Sprintf("%s %s/%s: %d replicas, no podAntiAffinity/topologySpreadConstraints",
					w.Kind, w.Namespace, w.Name, w.Replicas),
			},
			Severity:          severity,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			RemediationYAML: fmt.Sprintf(
				"# Validate against your workload before applying: with whenUnsatisfiable: ScheduleAnyway this is\n# soft (won't block scheduling); spread is bounded by the number of schedulable nodes/zones.\napiVersion: apps/v1\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      topologySpreadConstraints:\n        - maxSkew: 1\n          topologyKey: kubernetes.io/hostname\n          whenUnsatisfiable: ScheduleAnyway\n          labelSelector:\n            matchLabels:\n%s",
				w.Kind, w.Name, w.Namespace, indentedLabels(w.PodLabels, "              ")),
			Confidence: 0.6, // spec-field absence is certain; availability impact is an unverified worst case (placement depends on default SelectorSpread / node count / taints) and may be bounded by a covering PDB
			Provenance: provenance(),
		})
	}
	return out
}

// hasPodAntiAffinityTerms reports whether the workload declares a
// podAntiAffinity that carries at least one term (required or preferred). An
// absent Affinity, absent PodAntiAffinity, or an empty &PodAntiAffinity{} with
// no terms all count as NO spread intent. This intentionally does not inspect
// whether a present term targets a meaningful topology key — see the caveat in
// Evaluate's loop comment.
func hasPodAntiAffinityTerms(w *workload) bool {
	if w.PodSpec.Affinity == nil || w.PodSpec.Affinity.PodAntiAffinity == nil {
		return false
	}
	pa := w.PodSpec.Affinity.PodAntiAffinity
	return len(pa.RequiredDuringSchedulingIgnoredDuringExecution) > 0 ||
		len(pa.PreferredDuringSchedulingIgnoredDuringExecution) > 0
}

// schedulableTopology counts distinct schedulable nodes and distinct zones
// from the collected node list. Nodes cordoned via spec.unschedulable are
// excluded — they are not placement targets. Returns (0, 0) when no nodes are
// present (the caller distinguishes "not collected" from "single node" via
// Meta.Collected, so it must not over-trust a zero here).
func schedulableTopology(nodes []corev1.Node) (nodeCount, zoneCount int) {
	hosts := map[string]struct{}{}
	zones := map[string]struct{}{}
	for i := range nodes {
		n := nodes[i]
		if n.Spec.Unschedulable {
			continue
		}
		// Prefer the hostname label; fall back to the node object name so a
		// node without the label still counts as one distinct host.
		host := n.Labels[aaLabelHostname]
		if host == "" {
			host = n.Name
		}
		hosts[host] = struct{}{}
		// collect.ZoneOf, not a raw label: this counted a beta-labelled cluster as having zero zones, which
		// made the spread check read a genuinely multi-zone cluster as single-zone. See collect/zonelabels.go.
		if z := collect.ZoneOf(n); z != "" {
			zones[z] = struct{}{}
		}
	}
	return len(hosts), len(zones)
}

// antiAffinityPDBCovers reports whether any PodDisruptionBudget in the same
// namespace selects the workload's pods. Local copy of the standard selector
// match (single_replica.go has an equivalent) to keep this rule self-contained.
func antiAffinityPDBCovers(pdbs []policyv1.PodDisruptionBudget, ns string, podLabels map[string]string) bool {
	for i := range pdbs {
		pdb := pdbs[i]
		if pdb.Namespace != ns || pdb.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil || sel.Empty() {
			continue
		}
		if sel.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}

// aaNodesCollected reports whether a collection step succeeded: the kind is
// present in inv.Meta.Collected and absent from inv.Meta.Denied (denied entries
// are formatted "<kind>: <err>"). File-local to avoid colliding with the
// equivalent helper in sibling rule files. Used for the denial guard so we
// never read an empty inv.Nodes as "single-node cluster" when the node list was
// simply never returned.
func aaNodesCollected(inv *collect.Inventory, kind string) bool {
	for _, d := range inv.Meta.Denied {
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

// indentedLabels renders labels as YAML map entries at the given indent,
// sorted for deterministic output.
func indentedLabels(m map[string]string, indent string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s%s: %s\n", indent, k, m[k])
	}
	return b.String()
}

// RequiredKinds — Nodes decide whether spreading was even possible; a denied PDB list would overstate the exposure.
// See deps.go for what belongs in this list.
func (r NoAntiAffinity) RequiredKinds() []string {
	return withWorkloads("nodes", "poddisruptionbudgets")
}
