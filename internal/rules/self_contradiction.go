package rules

// self_contradiction.go — THE CLUSTER THAT CONTRADICTS ITSELF: places where the operator declared
// something their own cluster does not carry.
//
// Every other rule family in this tree compares a cluster against a standard somebody chose — CIS,
// a severity ladder, a house opinion about probes. These five compare two things the operator wrote,
// or one thing they wrote against one thing their own controller published. Nothing here is measured
// against a standard of ours, which is why `Confidence` is 1.0 by construction rather than an
// authored constant: the reading is subtraction over collected fields.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
// An exact reading invites an inexact sentence. Each refusal below was decided separately:
//
//	NO SCHEDULING VERDICT, IN ANY FORM. "no node carries this label" is arithmetic. "so these pods
//	cannot be scheduled" is not: what the scheduler does with a node lacking a constraint's
//	topologyKey differs between topology spread constraints and inter-pod affinity terms, and
//	NEITHER is modelled here. Nor are taints, tolerations, preemption, extended resources, or a
//	custom schedulerName. "will schedule", "will not schedule" and "cannot be scheduled" are
//	already in bannedDrainPhrases for exactly this reason and are banned here too.
//
//	NO VERDICT ABOUT INTENT. A PodDisruptionBudget the controller matched no pods with may be
//	pre-created for a workload not deployed yet. A nodeSelector naming an absent label is how a
//	node pool held at zero is requested. A ResourceQuota may have been lowered on purpose during a
//	freeze. Nobody told us which, so the finding reports the observation and the operator supplies
//	the intent. The words for the opposite — "misconfigured", "broken", "typo", "mistake" — are
//	banned by self_contradiction_test.go.
//
//	NO CLAIM THAT ANY OF THIS IS ENFORCED. Whether the API server runs the ResourceQuota admission
//	plugin is not readable from a read-only client, and neither is whether the CNI enforces
//	NetworkPolicy at all (netpol.go's detectCNIPosture is a DaemonSet-name heuristic, not a
//	reading). Both rules name the unreadable half instead of completing the syllogism — the same
//	move rollout_preflight.go makes about the MaxUnavailableStatefulSet feature gate.
//
//	NO DRAIN OR EVICTION VOCABULARY. PDBSelectsNoPods says only that the disruption controller
//	matched no pods with a budget. Every claim about what a budget DOES belongs to the drain
//	family, where TestDrainRules_AlwaysNameTheBypass forces each one to name the voluntary-path
//	bypass in the same breath. The vocabulary is banned here so a future edit cannot make a budget
//	claim in this file without that caveat.
//
//	NO DOLLARS. A contradiction between two declarations has no price, and there is no traffic,
//	revenue or SLA data in the snapshot to invent one from. PriceBasis is PriceNotCost on all five.
//
//	A SNAPSHOT IS A SNAPSHOT, SAID OUT LOUD. An absent node label becomes present the moment a pool
//	carrying it is added, and Cluster Autoscaler and Karpenter create nodes with labels no current
//	node carries. Every label-based finding carries that sentence in its own evidence.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY THE PDB RULE READS status.expectedPods AND NEVER MATCHES A SELECTOR ITSELF
//
// pdb_blocks_drains.go:46 suppresses a budget whose selector matches nothing in `workloads(inv,
// opts)`, and that suppression is correct for the claim that rule makes. Reusing its matching for
// THIS claim would repeat the worst defect Drain Preflight shipped: rule A emitted 0 findings on a
// real AKS because it looked for covered pods in an index that knew only Deployments and
// StatefulSets, silently discarding CloudNativePG `Cluster` and Strimzi `StrimziPodSet` pods. Those
// are precisely the operator-managed databases whose budgets matter. status.expectedPods is the
// disruption controller's OWN count of what its selector matched — the answer, computed by the
// component that acts on it, already in the inventory.

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// snapshotCaveat is carried by every finding that compares a declaration to the node label set. A
// pool carrying the missing label can appear between this reading and the next, and an autoscaler
// creating one is not an error — it is the mechanism a scale-from-zero pool is requested with.
const snapshotCaveat = "this is one reading: a node pool carrying the named label may be added at any " +
	"time, and Cluster Autoscaler and Karpenter create nodes carrying labels no current node carries, " +
	"which is how a pool held at zero is requested"

// schedulerNotModelled states, in the finding, the boundary the file header states in code review.
const schedulerNotModelled = "what the scheduler does with a node that lacks a declared topology key " +
	"differs between topology spread constraints and inter-pod affinity terms, and neither is modelled " +
	"here — nor are taints, tolerations, preemption or a custom schedulerName. This finding is about the " +
	"declaration, not about placement."

// nodeLabelKeys returns every label key present on at least one collected node, sorted. It is the
// set every declaration in this file is compared against, and printing it is what makes a
// one-character difference visible to the reader.
func nodeLabelKeys(nodes []corev1.Node) map[string]bool {
	out := map[string]bool{}
	for i := range nodes {
		for k := range nodes[i].Labels {
			out[k] = true
		}
	}
	return out
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A PodDisruptionBudget its own controller matched no pods with
// ─────────────────────────────────────────────────────────────────────────────────────────────

type PDBSelectsNoPods struct{}

func (PDBSelectsNoPods) ID() string      { return "k8s.config.pdb-selects-no-pods" }
func (PDBSelectsNoPods) Version() string { return "1.0.0" }

// RequiredKinds — the budget and its published status are the whole claim. The workload and pod
// lists are deliberately NOT declared: this rule never matches a selector (see the file header), so
// a run without them makes exactly the same claim about exactly the same budgets, and declaring
// them would make a comparison report the rule unevaluated on a run it fully evaluated.
// See deps.go for what belongs in this list.
func (PDBSelectsNoPods) RequiredKinds() []string { return []string{"poddisruptionbudgets"} }

func (r PDBSelectsNoPods) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: the claim is that a controller matched nothing. An unlisted budget list would
	// make the rule silent while looking identical to a cluster with no budgets, and Meta is the
	// only thing that can tell those apart.
	if !observed(inv, "poddisruptionbudgets") {
		return nil
	}
	var out []types.Finding
	for i := range inv.PDBs {
		pdb := &inv.PDBs[i]
		if !opts.IncludeSystem && isSystemNamespace(pdb.Namespace) {
			continue
		}
		// An empty status is NOT "matched no pods" — it is "the controller has not answered for the
		// spec in front of us". pdb_blocks_drains.go added this guard for the same reason.
		if !pdbStatusIsFresh(pdb) {
			continue
		}
		if pdb.Status.ExpectedPods != 0 {
			continue
		}
		evidence := []string{
			fmt.Sprintf("PodDisruptionBudget %s/%s: status.expectedPods=0 at observedGeneration=%d "+
				"(metadata.generation=%d), so the disruption controller matched no pods with this budget's selector",
				pdb.Namespace, pdb.Name, pdb.Status.ObservedGeneration, pdb.Generation),
			fmt.Sprintf("declared budget: %s", pdbDeclaredBudget(pdb)),
			fmt.Sprintf("selector as written: %s", selectorText(pdb.Spec.Selector)),
			// The count comes from the controller, not from us, and saying so is what makes the
			// reading independent of which workload kinds this tool happens to index.
			"the count is the disruption controller's own, read from status — this rule does not match the " +
				"selector itself, so a budget over pods owned by an operator's custom resource reads the same " +
				"as one over a Deployment",
			fmt.Sprintf("reading taken %s", stamp(readingTime(inv))),
			"a budget matching no pods may be deliberate: pre-created for a workload not deployed yet, or " +
				"left in place while its workload sits at zero replicas",
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PodDisruptionBudget", pdb.Namespace, pdb.Name),
			IDBasis:     &types.ResourceRef{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Budget %s/%s matches no pods", pdb.Namespace, pdb.Name),
			Description: fmt.Sprintf(
				"PodDisruptionBudget %s/%s declares %s, and its own status reports expectedPods=0 — the "+
					"disruption controller found no pods matching its selector. The declaration and the "+
					"controller's count are both read verbatim; which of the two the operator intended to change "+
					"is not readable here.",
				pdb.Namespace, pdb.Name, pdbDeclaredBudget(pdb)),
			WhyItMatters: "A budget over zero pods is a declaration nothing is attached to, and nothing in " +
				"the cluster reports the difference between that and one the controller is acting on.",
			Evidence:          evidence,
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name}},
			EstimatedEffort:   types.EffortLow,
			PriceBasis:        types.PriceNotCost,
			Confidence:        1.0, // two published fields, compared
			Provenance:        provenance(),
		})
	}
	return out
}

// pdbDeclaredBudget renders what the operator wrote, which is what they will search for. It is
// evidence, never the arithmetic — the arithmetic is status.expectedPods.
func pdbDeclaredBudget(pdb *policyv1.PodDisruptionBudget) string {
	switch {
	case pdb.Spec.MinAvailable != nil:
		return "spec.minAvailable=" + pdb.Spec.MinAvailable.String()
	case pdb.Spec.MaxUnavailable != nil:
		return "spec.maxUnavailable=" + pdb.Spec.MaxUnavailable.String()
	default:
		return "neither spec.minAvailable nor spec.maxUnavailable is set"
	}
}

// selectorText renders a label selector for evidence. A nil selector and an empty one are different
// statements in the API and must not print alike: nil selects nothing, {} selects every pod in the
// namespace.
func selectorText(sel *metav1.LabelSelector) string {
	if sel == nil {
		return "absent (no spec.selector)"
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		return "{} (every pod in the namespace)"
	}
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return "unparseable as written"
	}
	return s.String()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A topology domain no node is labelled with
// ─────────────────────────────────────────────────────────────────────────────────────────────

type TopologyKeyNoNodeCarries struct{}

func (TopologyKeyNoNodeCarries) ID() string      { return "k8s.config.topology-key-no-node-carries" }
func (TopologyKeyNoNodeCarries) Version() string { return "1.0.0" }

// RequiredKinds — the node label set is half the arithmetic and the workload templates are the
// other half. `daemonsets` is deliberately omitted because the rule skips DaemonSets outright
// (node-bound: there is nothing to spread), matching anti_affinity.go:61. `pods` is omitted because
// the claim is about the template's declaration, not about what is bound.
// See deps.go for what belongs in this list.
func (TopologyKeyNoNodeCarries) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "nodes", "statefulsets"})
}

// topoOffender is one declared topology key no node carries, with the enforcement mode the operator
// chose for it. The mode is carried rather than collapsed because a hard constraint and an advisory
// one are two different statements and one sentence for both would be false for one of them.
type topoOffender struct {
	Field string // where it was written, verbatim enough to find
	Key   string
	Mode  string
	Hard  bool
}

func (r TopologyKeyNoNodeCarries) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: without the node list, "no node carries this key" is a claim about a list we
	// never read. Every finding in this rule is that claim.
	if !observed(inv, "nodes") {
		return nil
	}
	keys := nodeLabelKeys(inv.Nodes)
	present := sortedSetKeys(keys)

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		if w.Kind == "DaemonSet" {
			continue // node-bound; nothing to spread across domains
		}
		// A workload at zero replicas asks the scheduler for nothing, so there is no declaration in
		// force to contradict. Same reasoning as NodeSelectorNoNodeCarries.
		if w.Replicas == 0 {
			continue
		}
		offenders := topologyOffenders(w, keys)
		if len(offenders) == 0 {
			continue
		}
		hard := false
		var lines, modes []string
		for _, o := range offenders {
			if o.Hard {
				hard = true
			}
			lines = append(lines, fmt.Sprintf("%s %s/%s: %s topologyKey=%q (%s) — no node carries that label key",
				w.Kind, w.Namespace, w.Name, o.Field, o.Key, o.Mode))
			modes = append(modes, o.Mode)
		}
		evidence := append([]string{}, lines...)
		evidence = append(evidence,
			fmt.Sprintf("%s read; the label keys they carry: %s", nWord(len(inv.Nodes), "node", "nodes"), joinCapped(present, 12)),
			schedulerNotModelled,
			snapshotCaveat)

		desc := fmt.Sprintf(
			"%s %s/%s declares spread across %s that no node in this reading is labelled with: %s. ",
			w.Kind, w.Namespace, w.Name, nWord(len(offenders), "topology key", "topology keys"), joinCapped(offenderKeys(offenders), 6))
		severity := types.SeverityLow
		if hard {
			severity = types.SeverityMedium
			desc += fmt.Sprintf(
				"The operator declared it as a hard requirement (%s), so the cluster is being asked to place "+
					"pods across a domain it does not label. Both halves are read verbatim — the key from the "+
					"workload, the label set from the nodes.",
				joinCapped(dedupe(modes), 3))
		} else {
			desc += fmt.Sprintf(
				"The operator declared it as advisory (%s), so a key no node carries makes the term a silent "+
					"no-op rather than a requirement: it is written, it is read by the scheduler, and it can "+
					"express nothing. Both halves are read verbatim — the key from the workload, the label set "+
					"from the nodes.",
				joinCapped(dedupe(modes), 3))
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s/%s spreads across a label no node carries",
				w.Kind, w.Namespace, w.Name),
			Description: desc,
			WhyItMatters: "A spread declaration naming a domain the cluster does not label reads as " +
				"protection on review and expresses nothing, and no controller reports the difference.",
			Evidence:          evidence,
			Severity:          severity,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			PriceBasis:        types.PriceNotCost,
			Confidence:        1.0, // set membership over collected fields
			Provenance:        provenance(),
		})
	}
	return out
}

// topologyOffenders collects every declared topology key absent from the node label set, from both
// places a workload can declare one.
func topologyOffenders(w workload, keys map[string]bool) []topoOffender {
	var out []topoOffender
	for i, c := range w.PodSpec.TopologySpreadConstraints {
		if c.TopologyKey == "" || keys[c.TopologyKey] {
			continue
		}
		out = append(out, topoOffender{
			Field: fmt.Sprintf("spec.topologySpreadConstraints[%d]", i),
			Key:   c.TopologyKey,
			Mode:  "whenUnsatisfiable: " + string(c.WhenUnsatisfiable),
			// DoNotSchedule is the hard mode; ScheduleAnyway is advisory. An empty value defaults to
			// DoNotSchedule per the API, so treating "" as advisory would understate the operator's
			// own declaration.
			Hard: c.WhenUnsatisfiable != corev1.ScheduleAnyway,
		})
	}
	aff := w.PodSpec.Affinity
	if aff == nil {
		return out
	}
	collectTerms := func(field string, hard bool, terms []corev1.PodAffinityTerm) {
		for i, t := range terms {
			if t.TopologyKey == "" || keys[t.TopologyKey] {
				continue
			}
			mode := "preferredDuringSchedulingIgnoredDuringExecution"
			if hard {
				mode = "requiredDuringSchedulingIgnoredDuringExecution"
			}
			out = append(out, topoOffender{
				Field: fmt.Sprintf("%s[%d]", field, i),
				Key:   t.TopologyKey,
				Mode:  mode,
				Hard:  hard,
			})
		}
	}
	if pa := aff.PodAntiAffinity; pa != nil {
		collectTerms("spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution",
			true, pa.RequiredDuringSchedulingIgnoredDuringExecution)
		collectTerms("spec.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution",
			false, weightedTerms(pa.PreferredDuringSchedulingIgnoredDuringExecution))
	}
	if pa := aff.PodAffinity; pa != nil {
		collectTerms("spec.affinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution",
			true, pa.RequiredDuringSchedulingIgnoredDuringExecution)
		collectTerms("spec.affinity.podAffinity.preferredDuringSchedulingIgnoredDuringExecution",
			false, weightedTerms(pa.PreferredDuringSchedulingIgnoredDuringExecution))
	}
	return out
}

func weightedTerms(ws []corev1.WeightedPodAffinityTerm) []corev1.PodAffinityTerm {
	out := make([]corev1.PodAffinityTerm, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.PodAffinityTerm)
	}
	return out
}

func offenderKeys(os []topoOffender) []string {
	out := make([]string, 0, len(os))
	for _, o := range os {
		out = append(out, o.Key)
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A node label no node carries, named as a placement requirement
// ─────────────────────────────────────────────────────────────────────────────────────────────

type NodeSelectorNoNodeCarries struct{}

func (NodeSelectorNoNodeCarries) ID() string      { return "k8s.config.node-selector-no-node-carries" }
func (NodeSelectorNoNodeCarries) Version() string { return "1.0.0" }

// RequiredKinds — `nodes` is the load-bearing one and the only kind whose absence silences the rule.
// `pods` is declared because the bound-pod count changes the finding's SEVERITY and its second
// sentence, not merely its phrasing: with the pod list refused the rule states the weaker reading
// and says the list was not read, which is a different claim about the same object. The workload
// kinds are declared because each finding is about one of those objects.
// See deps.go for what belongs in this list.
func (NodeSelectorNoNodeCarries) RequiredKinds() []string {
	return withWorkloads("nodes", "pods")
}

func (r NodeSelectorNoNodeCarries) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: every finding here says no node carries something. Without the node list that
	// is a statement about a list we never read.
	if !observed(inv, "nodes") {
		return nil
	}
	podsObserved := observed(inv, "pods")
	keys := nodeLabelKeys(inv.Nodes)
	present := sortedSetKeys(keys)

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		// Nothing is being asked of the scheduler by a workload at zero replicas, and pinning a
		// parked workload to a cold pool is the ordinary way to hold it. DaemonSets carry -1 here
		// and are deliberately still assessed: a DaemonSet whose nodeSelector matches no node runs
		// nowhere, which is the same contradiction.
		if w.Replicas == 0 {
			continue
		}
		reasons := placementReasons(inv, w, keys)
		if len(reasons) == 0 {
			continue
		}

		bound, boundKnown := boundPodCount(inv, w, podsObserved)
		evidence := append([]string{}, reasons...)
		evidence = append(evidence,
			fmt.Sprintf("%s read; the label keys they carry: %s", nWord(len(inv.Nodes), "node", "nodes"), joinCapped(present, 12)))
		switch {
		case !boundKnown:
			evidence = append(evidence, "the pod list was not read, so whether any pod of this workload is "+
				"currently bound to a node is not known here")
		case bound == 0:
			evidence = append(evidence, "no pod of this workload is bound to a node in this reading")
		default:
			evidence = append(evidence, fmt.Sprintf(
				"%s of this workload are bound to a node in this reading — nodeSelector and "+
					"nodeAffinity are IgnoredDuringExecution, so a pod stays where it is when the labels it was "+
					"placed on change", nWord(bound, "pod", "pods")))
		}
		evidence = append(evidence, schedulerNotModelled, snapshotCaveat)

		// Two readings, two sentences. "Nothing has been placed against this declaration" and "these
		// pods were placed before the labels diverged" are statements about two different clusters,
		// and a rule that renders the second as the first has described the wrong one.
		severity := types.SeverityMedium
		tail := "No pod of this workload is bound to a node in this reading."
		if boundKnown && bound > 0 {
			severity = types.SeverityLow
			tail = fmt.Sprintf(
				"%s of it are nonetheless bound to nodes: these fields are IgnoredDuringExecution, so "+
					"the placement predates the difference between the declaration and the labels.", nWord(bound, "pod", "pods"))
		} else if !boundKnown {
			severity = types.SeverityLow
			tail = "Whether any pod of this workload is bound is not known — the pod list was not read."
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s/%s requires node labels no node carries",
				w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf(
				"%s %s/%s names node labels as a placement requirement that no node in this reading "+
					"satisfies (see evidence for each). The declaration is read from the pod template and the "+
					"labels from the node objects; both verbatim. %s",
				w.Kind, w.Namespace, w.Name, tail),
			WhyItMatters: "A placement requirement the cluster's labels do not satisfy is invisible in the " +
				"workload's own status, and nothing reports the difference between it and one that is met.",
			Evidence:          evidence,
			Severity:          severity,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			PriceBasis:        types.PriceNotCost,
			Confidence:        1.0, // set membership over collected fields
			Provenance:        provenance(),
		})
	}
	return out
}

// placementReasons returns one evidence line per unsatisfied placement declaration, or nothing when
// every declaration is satisfiable by some collected node.
func placementReasons(inv *collect.Inventory, w workload, keys map[string]bool) []string {
	var out []string

	// nodeSelector is an equality AND-match. nodeMatchesSelector (rightsizing.go) is reused rather
	// than copied: one mapping, so a fix reaches both callers.
	if sel := w.PodSpec.NodeSelector; len(sel) > 0 {
		matched := false
		for i := range inv.Nodes {
			if nodeMatchesSelector(inv.Nodes[i], sel) {
				matched = true
				break
			}
		}
		if !matched {
			// Which pairs are individually unsatisfiable, and — the case a per-pair check alone
			// would miss — whether every pair is individually fine while the conjunction is not,
			// because the labels sit on different nodes.
			var deadKeys, deadValues []string
			for _, k := range sortedMapKeys(sel) {
				v := sel[k]
				if !keys[k] {
					deadKeys = append(deadKeys, fmt.Sprintf("%s=%s (no node carries the key)", k, v))
					continue
				}
				if !anyNodeHasLabel(inv.Nodes, k, v) {
					deadValues = append(deadValues, fmt.Sprintf("%s=%s (the key exists; no node carries that value)", k, v))
				}
			}
			detail := strings.Join(append(deadKeys, deadValues...), "; ")
			if detail == "" {
				detail = "every pair is carried by some node, but no single node carries all of them at once"
			}
			out = append(out, fmt.Sprintf("%s %s/%s: spec.nodeSelector %v is satisfied by 0 of %s — %s",
				w.Kind, w.Namespace, w.Name, sel, nWord(len(inv.Nodes), "node", "nodes"), detail))
		}
	}

	// nodeAffinity.required: nodeSelectorTerms are OR'd, matchExpressions within a term are AND'd.
	// So the affinity is reportable ONLY when EVERY term is unsatisfiable. One dead term beside a
	// live one is how "pool A or pool B" is written with B held at zero, and flagging it would
	// report a correct declaration.
	if aff := w.PodSpec.Affinity; aff != nil && aff.NodeAffinity != nil {
		req := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
		if req != nil && len(req.NodeSelectorTerms) > 0 {
			var reasons []string
			allDead := true
			for i, term := range req.NodeSelectorTerms {
				dead, why := termIsUnsatisfiable(inv.Nodes, keys, term)
				if !dead {
					allDead = false
					break
				}
				reasons = append(reasons, fmt.Sprintf("nodeSelectorTerms[%d]: %s", i, why))
			}
			if allDead {
				out = append(out, fmt.Sprintf(
					"%s %s/%s: every one of the %d nodeSelectorTerms in "+
						"spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution is satisfied by "+
						"0 of %s (the terms are OR'd, so all of them must be for this to be reportable) — %s",
					w.Kind, w.Namespace, w.Name, len(req.NodeSelectorTerms), nWord(len(inv.Nodes), "node", "nodes"), strings.Join(reasons, "; ")))
			}
		}
	}
	return out
}

// termIsUnsatisfiable reports whether one nodeSelectorTerm can be satisfied by no collected node,
// with the reason.
//
// ONLY `In` AND `Exists` ARE MODELLED, AND THE ASYMMETRY IS THE POINT. `NotIn` and `DoesNotExist`
// are SATISFIED by a missing label, so treating them like the other two would invert the claim.
// `Gt`/`Lt` compare parsed integers and `matchFields` addresses a node by name; neither is modelled.
// A term containing anything unmodelled is treated as SATISFIABLE, so an unmodelled operator can
// only ever suppress a finding and never create one.
func termIsUnsatisfiable(nodes []corev1.Node, keys map[string]bool, term corev1.NodeSelectorTerm) (bool, string) {
	if len(term.MatchFields) > 0 {
		return false, ""
	}
	if len(term.MatchExpressions) == 0 {
		return false, ""
	}
	for _, e := range term.MatchExpressions {
		switch e.Operator {
		case corev1.NodeSelectorOpExists:
			if !keys[e.Key] {
				return true, fmt.Sprintf("%s Exists, and no node carries that label key", e.Key)
			}
		case corev1.NodeSelectorOpIn:
			if !keys[e.Key] {
				return true, fmt.Sprintf("%s In %v, and no node carries that label key", e.Key, e.Values)
			}
			any := false
			for _, v := range e.Values {
				if anyNodeHasLabel(nodes, e.Key, v) {
					any = true
					break
				}
			}
			if !any {
				return true, fmt.Sprintf("%s In %v, and no node carries any of those values", e.Key, e.Values)
			}
		default:
			// NotIn, DoesNotExist, Gt, Lt — see the doc comment. Not modelled, so not reported.
			return false, ""
		}
	}
	return false, ""
}

func anyNodeHasLabel(nodes []corev1.Node, key, value string) bool {
	for i := range nodes {
		if nodes[i].Labels[key] == value {
			return true
		}
	}
	return false
}

// boundPodCount counts this workload's pods that are bound to a node. The second return is false
// when the number is not knowable — the pod list was refused, or the template carries no labels to
// identify its pods with, in which case an empty selector would match every pod in the namespace.
func boundPodCount(inv *collect.Inventory, w workload, podsObserved bool) (int, bool) {
	if !podsObserved || len(w.PodLabels) == 0 {
		return 0, false
	}
	sel := labels.SelectorFromSet(labels.Set(w.PodLabels))
	n := 0
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Namespace != w.Namespace || p.Spec.NodeName == "" {
			continue
		}
		if sel.Matches(labels.Set(p.Labels)) {
			n++
		}
	}
	return n, true
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A ResourceQuota the namespace is already above
// ─────────────────────────────────────────────────────────────────────────────────────────────

type QuotaBelowCommitted struct{}

func (QuotaBelowCommitted) ID() string      { return "k8s.config.quota-below-committed" }
func (QuotaBelowCommitted) Version() string { return "1.0.0" }

// RequiredKinds — both numbers are published on the quota itself, by the quota controller. Nothing
// else is read, and nothing else is declared: this rule does not sum anybody's requests, which is
// the whole reason it can carry Confidence 1.0.
// See deps.go for what belongs in this list.
func (QuotaBelowCommitted) RequiredKinds() []string { return []string{"resourcequotas"} }

func (r QuotaBelowCommitted) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: an unlisted quota list would make the rule silent while looking identical to a
	// cluster whose quotas all agree with themselves.
	if !observed(inv, "resourcequotas") {
		return nil
	}
	var out []types.Finding
	for i := range inv.ResourceQuotas {
		q := &inv.ResourceQuotas[i]
		if !opts.IncludeSystem && isSystemNamespace(q.Namespace) {
			continue
		}
		var lines []string
		for _, name := range sortedResourceNames(q.Status.Hard) {
			hard := q.Status.Hard[name]
			// A ResourceQuota carries no observedGeneration, so the presence of the SAME key in
			// status.used is the only freshness signal there is. A missing key is the controller not
			// having answered for that resource, and reading it as zero would invent the finding out
			// of a missing reading — the absence-versus-denial trap one level down.
			used, ok := q.Status.Used[name]
			if !ok {
				continue
			}
			if used.Cmp(hard) <= 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf(
				"ResourceQuota %s/%s: status.used[%s]=%s is above status.hard[%s]=%s, both published by the "+
					"quota controller", q.Namespace, q.Name, name, used.String(), name, hard.String()))
		}
		if len(lines) == 0 {
			continue
		}
		evidence := append([]string{}, lines...)
		evidence = append(evidence,
			"a ResourceQuota is a ceiling applied when an object is admitted, never retroactively — so this "+
				"state is reached by lowering the ceiling, or by objects that predate the quota, and the pods "+
				"already running are untouched by it",
			"whether the API server has the ResourceQuota admission plugin enabled is not readable from a "+
				"read-only client, so what the cluster does with the difference is not stated here",
			fmt.Sprintf("reading taken %s", stamp(readingTime(inv))))

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "ResourceQuota", q.Namespace, q.Name),
			IDBasis:     &types.ResourceRef{Kind: "ResourceQuota", Namespace: q.Namespace, Name: q.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Quota %s/%s is below what the namespace already holds", q.Namespace, q.Name),
			Description: fmt.Sprintf(
				"ResourceQuota %s/%s publishes, for %s, a status.used above its own status.hard. "+
					"Both numbers are the quota controller's: it counts what the namespace holds and it echoes "+
					"the ceiling the operator declared, and here the two disagree. No arithmetic of ours is "+
					"involved.",
				q.Namespace, q.Name, nWord(len(lines), "resource", "resources")),
			WhyItMatters: "A ceiling the namespace is already above is a number nobody is looking at, and " +
				"the disagreement appears in no workload's status.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "ResourceQuota", Namespace: q.Namespace, Name: q.Name}},
			EstimatedEffort:   types.EffortLow,
			PriceBasis:        types.PriceNotCost,
			Confidence:        1.0, // two published fields, compared
			Provenance:        provenance(),
		})
	}
	return out
}

func sortedResourceNames(rl corev1.ResourceList) []corev1.ResourceName {
	out := make([]corev1.ResourceName, 0, len(rl))
	for n := range rl {
		out = append(out, n)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A NetworkPolicy peer that selects no namespace
// ─────────────────────────────────────────────────────────────────────────────────────────────

type NetPolPeerSelectsNoNamespace struct{}

func (NetPolPeerSelectsNoNamespace) ID() string {
	return "k8s.config.netpol-peer-selects-no-namespace"
}
func (NetPolPeerSelectsNoNamespace) Version() string { return "1.0.0" }

// RequiredKinds — the policies are the declaration and the namespaces are what it is compared
// against; deny either and the claim changes. `daemonsets` is deliberately NOT declared even though
// the rule reads them: detectCNIPosture only ever adds a caveat SENTENCE to a finding that fired
// anyway, and deps.go:19-25 draws exactly that line with the EndpointSlice example — declaring a
// wording dependency would make the report say a rule was not evaluated when it was.
// See deps.go for what belongs in this list.
func (NetPolPeerSelectsNoNamespace) RequiredKinds() []string {
	return sortedKinds([]string{"namespaces", "networkpolicies"})
}

func (r NetPolPeerSelectsNoNamespace) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: "no namespace matches this selector" is an absence claim over the namespace
	// list. With either list refused the rule would either fabricate a finding per peer or fall
	// silent while looking identical to a cluster whose policies all resolve.
	if !observed(inv, "networkpolicies") || !observed(inv, "namespaces") {
		return nil
	}
	// The CNI note is added only when it is readable, and it is a wording change — see RequiredKinds.
	cniNote := ""
	if observed(inv, "daemonsets") {
		if p := detectCNIPosture(inv); p.vpcCNINoAgent {
			cniNote = "the cluster's DaemonSets name the AWS VPC CNI with no separate policy agent alongside " +
				"it, and that combination ignores upstream NetworkPolicy objects entirely — so this policy may " +
				"express nothing regardless of its peers. The posture is inferred from DaemonSet names, not read."
		}
	}

	var out []types.Finding
	for i := range inv.NetworkPolicies {
		np := &inv.NetworkPolicies[i]
		if !opts.IncludeSystem && isSystemNamespace(np.Namespace) {
			continue
		}
		lines := deadPeerLines(np, inv.Namespaces)
		if len(lines) == 0 {
			continue
		}
		evidence := append([]string{}, lines...)
		evidence = append(evidence, fmt.Sprintf(
			"%s read; a peer's namespaceSelector is matched against their labels, and an EMPTY "+
				"selector (`namespaceSelector: {}`) means every namespace and is never reported here", nWord(len(inv.Namespaces), "namespace", "namespaces")))
		evidence = append(evidence,
			"the peer's podSelector is deliberately not judged: pods come and go inside one reading, while a "+
				"namespace is an object an operator names on purpose")
		if cniNote != "" {
			evidence = append(evidence, cniNote)
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "NetworkPolicy", np.Namespace, np.Name),
			IDBasis:     &types.ResourceRef{Kind: "NetworkPolicy", Namespace: np.Namespace, Name: np.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("NetworkPolicy %s/%s names a namespace label nothing carries", np.Namespace, np.Name),
			Description: fmt.Sprintf(
				"NetworkPolicy %s/%s has %s whose namespaceSelector matches none of the %d namespaces "+
					"in this reading. A peer that selects no namespace contributes no namespace to the rule it "+
					"is written in. The selector is read from the policy and the labels from the namespace "+
					"objects; both verbatim, and whether the difference is intended is not readable here.",
				np.Namespace, np.Name, nWord(len(lines), "peer", "peers"), len(inv.Namespaces)),
			WhyItMatters: "A peer selecting no namespace looks like a declared connection on review and " +
				"contributes nothing to the rule, and no controller reports the difference.",
			Evidence:          evidence,
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "NetworkPolicy", Namespace: np.Namespace, Name: np.Name}},
			EstimatedEffort:   types.EffortLow,
			PriceBasis:        types.PriceNotCost,
			Confidence:        1.0, // selector evaluation over collected labels
			Provenance:        provenance(),
		})
	}
	return out
}

// deadPeerLines returns one line per peer whose non-empty namespaceSelector matches no namespace.
//
// THE TWO CASES THAT MUST NEVER BE REPORTED. A nil namespaceSelector means "this policy's own
// namespace" and selects nothing by label at all. An EMPTY one (`{}`) means EVERY namespace — the
// widest selector the API has — and reporting it as matching zero would turn the broadest correct
// policy in the cluster into a finding.
func deadPeerLines(np *networkingv1.NetworkPolicy, namespaces []corev1.Namespace) []string {
	var out []string
	check := func(field string, ri, pi int, peer networkingv1.NetworkPolicyPeer) {
		sel := peer.NamespaceSelector
		if sel == nil {
			return
		}
		if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
			return // {} is every namespace
		}
		compiled, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			return // unparseable as written; not our claim to make
		}
		for i := range namespaces {
			if compiled.Matches(labels.Set(namespaces[i].Labels)) {
				return
			}
		}
		out = append(out, fmt.Sprintf(
			"NetworkPolicy %s/%s: %s[%d] peer[%d] namespaceSelector %q matches 0 of %s",
			np.Namespace, np.Name, field, ri, pi, compiled.String(), nWord(len(namespaces), "namespace", "namespaces")))
	}
	for ri, rule := range np.Spec.Ingress {
		for pi, peer := range rule.From {
			check("spec.ingress", ri, pi, peer)
		}
	}
	for ri, rule := range np.Spec.Egress {
		for pi, peer := range rule.To {
			check("spec.egress", ri, pi, peer)
		}
	}
	return out
}
