package rules

// node_drain.go — DRAIN PREFLIGHT: what stands between an operator and evacuating a given node.
//
// The question these rules answer is the one an SRE actually has on a Tuesday evening: "can I drain
// this node tonight, and if not, what stops me?" They answer it with arithmetic over the snapshot —
// how many pods are bound to the node, what the eviction API will do with them, and which of them
// cannot start anywhere else.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
// The tempting version of this feature says "draining node-a takes checkout down for 40 seconds".
// A read-only snapshot cannot support one word of that sentence, and an adversarial review
// established each refusal separately:
//
//   No durations. A floor derived from readiness probes inverts exactly where it is most dangerous:
//   a workload with no probe would score as the FASTEST recovery while being the most likely to
//   serve errors. And pod-recovery time is not service-downtime time.
//
//   No user impact, and not even the word "service". A pod matching a Service's selector is NOT
//   evidence it was in rotation — it may be NotReady or Terminating, and a selectorless Service may
//   point at endpoints we cannot see. Nor is type=LoadBalancer proof of internet exposure (internal
//   LBs are annotation-only), while a ClusterIP can be exposed through a mesh gateway. Cross-cluster
//   and DNS failover sit entirely outside the kubeconfig.
//
//   This paragraph used to open with "EndpointSlices are not collected", which stopped being true:
//   they are collected (collect.go, deploy/rbac.yaml) and these rules read them, appending a
//   registration count as evidence. ONLY THE SENTENCE CHANGED. Whether a published entry now lets any
//   claim here be strengthened is a separate question with its own tests and its own sign-off, and
//   nothing above has been widened — a published entry is still not a request, which is why
//   bannedDrainPhrases keeps "receives traffic", "serves traffic" and "rotation".
//
//   No "single point of failure". That is an outcome claim resting on the blind spots above. The
//   provable statement is placement: "every live Pod object of this workload is bound to this node".
//
//   No survival score, grade, or per-node rating. A single unknown falsifies a universal claim, so
//   the snapshot supports existential statements about mechanism only.
//
//   No rescheduling verdict. Requests-versus-usage is wrong in both directions — this project
//   already carries a founder-caught false positive of exactly that shape, where $1,121 of apparent
//   "headroom" was really an OOM — and reading affinity fields is not simulating the scheduler.
//
//   No control-plane timing. node-monitor-grace-period and DefaultTolerationSeconds are provider-set
//   flags, unreadable on EKS/AKS/GKE, and taint-based eviction can be disabled outright, so even
//   "the pods will be evicted" is not guaranteed.
//
//   No dollars. There is no traffic, revenue or SLA data in the snapshot.
//
// node_drain_test.go enforces the list mechanically. It is the structural guard for claims, in the
// same way the denial guards are the structural guard for absence.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// DRAIN AND NODE DEATH ARE DIFFERENT EVENTS
//
// A voluntary drain goes through the Eviction API, where PodDisruptionBudgets apply. A node dying
// does not: budgets are bypassed entirely, as they are by `kubectl delete pod`, by force-deletion,
// and by kubelet node-pressure eviction. A single blended verdict would therefore be false in one
// of the two cases, so every budget claim here is scoped to the voluntary path and names the bypass
// in the same breath.

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/labels"
	types2 "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ---------------------------------------------------------------------------------------------
// shared placement index
// ---------------------------------------------------------------------------------------------

// drainOwner identifies the workload a pod belongs to. Only Deployments and StatefulSets are
// assessable: a Job's pods are not redundancy, and a bare pod has no replacement mechanism at all.
type drainOwner struct {
	Kind, Namespace, Name string
}

// drainPlacement is what is bound to one node at snapshot time.
type drainPlacement struct {
	node *corev1.Node

	// livePods is EVERY live pod bound to the node, whatever owns it. Eviction questions read this:
	// the eviction API does not care who owns a pod, and the workloads most likely to block a drain
	// are operator-managed databases whose pods belong to a CR rather than to a Deployment or
	// StatefulSet. Coupling the budget arithmetic to byOwner silently discarded exactly those — see
	// TestNodeDrainBudget_CoversOperatorManagedPods.
	livePods []corev1.Pod

	// byOwner holds only assessable pods — those whose owner is a Deployment or StatefulSet. Only
	// the REDUNDANCY arithmetic uses this, because "how many copies remain" needs a workload.
	byOwner map[drainOwner][]corev1.Pod

	daemonPods int // node-local agents: lost with the node by design, never pooled redundancy
	unassessed int // Job/CronJob/bare/unresolved owners
	notLive    int // Terminating, Succeeded or Failed — bound but not capacity
	liveTotal  int // every live pod on the node, assessable or not
}

// isLivePod reports whether a pod is real capacity on its node right now.
//
// This is the first code in the tree to read Status.Phase or DeletionTimestamp, which makes it a new
// claim surface: getting the predicate subtly wrong — counting a Succeeded Job pod still bound to the
// node, or dropping a legitimately Pending replacement — silently corrupts every count in every
// finding these rules emit. A Pending pod IS counted: it is scheduled to this node and the drain has
// to move it.
func isLivePod(p corev1.Pod) bool {
	if p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
		return false
	}
	switch p.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return false
	}
	return true
}

// buildDrainPlacement indexes pods by node. Recomputed per rule because the Rule interface takes
// only (inv, opts) and inventing cross-rule state would be worse than the cost — the loop is over a
// slice already in memory.
//
// opts.IncludeSystem governs what is REPORTED, not what is counted: a system pod still has to be
// evicted for the drain to finish, so excluding it from the totals would understate the operation.
func buildDrainPlacement(inv *collect.Inventory) map[string]*drainPlacement {
	owners := newOwnerIndex(inv)
	out := map[string]*drainPlacement{}
	for i := range inv.Nodes {
		n := inv.Nodes[i]
		out[n.Name] = &drainPlacement{node: &inv.Nodes[i], byOwner: map[drainOwner][]corev1.Pod{}}
	}
	for _, p := range inv.Pods {
		pl := out[p.Spec.NodeName]
		if pl == nil {
			// A pod bound to a node absent from the node list. Each kind is listed independently
			// with no pinned resourceVersion, so the two views can genuinely disagree by seconds.
			// Skipping is the honest choice: we have no node to make a claim about.
			continue
		}
		if !isLivePod(p) {
			pl.notLive++
			continue
		}
		pl.liveTotal++
		pl.livePods = append(pl.livePods, p)
		if isDaemonSetPod(p) {
			pl.daemonPods++
			continue
		}
		owner, ok := owners.assessable(p)
		if !ok {
			pl.unassessed++
			continue
		}
		pl.byOwner[owner] = append(pl.byOwner[owner], p)
	}
	return out
}

// assessable resolves a pod to a Deployment or StatefulSet via the owner chain, which already collapses the
// ReplicaSet hop. Anything else is not assessable redundancy.
func (x *ownerIndex) assessable(p corev1.Pod) (drainOwner, bool) {
	for _, link := range x.chain(p) {
		switch link.Kind {
		case "Deployment", "StatefulSet":
			return drainOwner{Kind: link.Kind, Namespace: p.Namespace, Name: link.Name}, true
		}
	}
	return drainOwner{}, false
}

// desiredReplicas returns the workload's declared replica count, and whether it was found.
func (x *ownerIndex) desiredReplicas(o drainOwner) (int, bool) {
	k := types2.NamespacedName{Namespace: o.Namespace, Name: o.Name}
	switch o.Kind {
	case "Deployment":
		if d := x.deployments[k]; d != nil {
			if d.Spec.Replicas == nil {
				return 1, true // the API default
			}
			return int(*d.Spec.Replicas), true
		}
	case "StatefulSet":
		if s := x.statefulSets[k]; s != nil {
			if s.Spec.Replicas == nil {
				return 1, true
			}
			return int(*s.Spec.Replicas), true
		}
	}
	return 0, false
}

// livePodsByOwner counts each owner's live pods across the WHOLE cluster, which is what makes "N of N are on one
// node" a real statement rather than a per-node tautology.
//
// ONE PASS FOR EVERY OWNER. It was a walk of every pod for each workload on each node — on 34,000 pods, tens of
// thousands of walks of tens of thousands — for a count that does not depend on which node asked.
func (x *ownerIndex) livePodsByOwner(inv *collect.Inventory) map[drainOwner]int {
	out := map[drainOwner]int{}
	for _, p := range inv.Pods {
		if !isLivePod(p) {
			continue
		}
		if o, ok := x.assessable(p); ok {
			out[o]++
		}
	}
	return out
}

// snapshotNote time-scopes every drain finding. The kinds are listed independently with no pinned
// resourceVersion, so the node, pod and PDB views can differ by seconds — on a churning or
// autoscaled cluster a per-node claim may be stale by the time the report is read.
func snapshotNote(inv *collect.Inventory) string {
	return fmt.Sprintf(
		"Snapshot taken at %s. Each resource kind is listed independently, so the node, pod and "+
			"budget views can differ by moments; re-verify against the live cluster before acting.",
		inv.Meta.StartedAt.UTC().Format("2006-01-02T15:04:05Z"))
}

// pdbBypassNote is appended to every budget claim. Omitting it would let a reader take "the budget
// blocks this" as protection against the node failing, which is false.
const pdbBypassNote = "A PodDisruptionBudget constrains only the voluntary eviction path. It gives no " +
	"protection against this node failing, and `kubectl delete pod`, force-deletion and kubelet " +
	"node-pressure eviction all bypass it."

// sortedNodeNames keeps findings in a stable order across runs.
func sortedNodeNames(pl map[string]*drainPlacement) []string {
	names := make([]string, 0, len(pl))
	for n := range pl {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// drainInputsOK is the denial guard shared by all three rules: without both nodes and pods, an empty
// list is indistinguishable from a list we never read, and every count below would be fabricated.
func drainInputsOK(inv *collect.Inventory) bool {
	return observed(inv, "nodes") && observed(inv, "pods")
}

// ---------------------------------------------------------------------------------------------
// The client's own refusal: a pod no controller manages
// ---------------------------------------------------------------------------------------------

// NodeDrainUnmanaged reports, per node, the running pods no controller manages. `kubectl drain` refuses to evict
// such a pod unless it is given --force — before any disruption budget is consulted — and with --force it deletes
// the pod, which nothing then recreates. The model of a drain answered "nothing this model checks stops the drain"
// for a node carrying one, while the command it models would have stopped there.
//
// Every namespace counts, because the drain does: kubectl's check reads every pod on the node. Static (mirror)
// pods are excluded — kubectl skips them, their controller being a file on the node's disk — and so are pods in a
// terminal phase or already being deleted, which a drain does not wait for.
type NodeDrainUnmanaged struct{}

func (NodeDrainUnmanaged) ID() string      { return "k8s.reliability.node-drain-unmanaged-pod" }
func (NodeDrainUnmanaged) Version() string { return "1.0.0" }

func (r NodeDrainUnmanaged) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !drainInputsOK(inv) {
		return nil
	}
	byNode := map[string][]string{}
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if p.Spec.NodeName == "" || p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if controllerRef(*p) != nil {
			continue
		}
		if _, mirror := p.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
			continue
		}
		byNode[p.Spec.NodeName] = append(byNode[p.Spec.NodeName], p.Namespace+"/"+p.Name)
	}
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var out []types.Finding
	for _, node := range nodes {
		pods := byNode[node]
		sort.Strings(pods)
		refs := []types.ResourceRef{{Kind: "Node", Name: node}}
		for _, p := range pods {
			ns, name, _ := strings.Cut(p, "/")
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: ns, Name: name})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Node", "", node+"|unmanaged"),
			IDBasis:     &types.ResourceRef{Kind: "Node", Name: node + "|unmanaged"},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("Drain of %s stops on %s no controller manages", node,
				nWord(len(pods), "pod", "pods")),
			Description: fmt.Sprintf("kubectl drain refuses to evict %s on node %s unless it is given --force, "+
				"and with --force deletes %s: nothing recreates a pod no controller manages.",
				pick(len(pods), "the pod", "the pods"), node, pick(len(pods), "it", "them")),
			WhyItMatters: "A drain that stops halfway leaves its node cordoned and half-empty; one forced through " +
				"deletes the pod for good. Usually it is a debug shell somebody left behind, and occasionally it is " +
				"something load-bearing applied by hand.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("%s on node %s %s no controller ownerReference: %s", nWord(len(pods), "pod", "pods"),
					node, pick(len(pods), "carries", "carry"), strings.Join(pods, ", ")),
				"this is kubectl's own check, made before any eviction is requested and before any disruption " +
					"budget is consulted: without --force the drain stops, with it the pod is deleted",
				"static (mirror) pods are excluded — kubectl skips them, their controller being a file on the node's " +
					"disk — and so are pods in a terminal phase or already being deleted",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortLow,
			// No remediation command: whether the pod is deleted, adopted by a controller or forced through is a
			// person's decision about something this reading cannot see the purpose of.
			DollarImpactMonthly: 0,
			Confidence:          1.0,
			Provenance:          provenance(),
		})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Rule A — the eviction arithmetic
// ---------------------------------------------------------------------------------------------

// NodeDrainBudget reports, per (node, PodDisruptionBudget), what the eviction API would do with the
// pods that budget covers on that node.
//
// It reads status.disruptionsAllowed rather than re-deriving the budget from spec, because status is
// what the controller published and therefore what the eviction API will act on. The spec alone
// cannot tell you the answer: a percentage resolves against the number of pods the budget actually
// covers, which may span several workloads.
type NodeDrainBudget struct{}

func (NodeDrainBudget) ID() string      { return "k8s.reliability.node-drain-budget" }
func (NodeDrainBudget) Version() string { return "1.0.0" }

func (r NodeDrainBudget) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	if !drainInputsOK(inv) || !observed(inv, "poddisruptionbudgets") {
		return out
	}
	placement := buildDrainPlacement(inv)
	// ONE COMPILE PER BUDGET, not one per budget per node: a selector does not depend on the node it is asked
	// about, and compiling 500 of them for each of 2,000 nodes was half of what this rule cost on a large cluster.
	sels := make([]labels.Selector, len(inv.PDBs))
	for i := range inv.PDBs {
		sels[i] = pdbSelector(&inv.PDBs[i])
	}

	// ONLY THE BUDGETS IN A NAMESPACE WITH A POD ON THE NODE can cover one there; every other pairing is an empty
	// covered set, which the loop below skips. Asking all of them on every node was budgets × pods across the
	// cluster. The candidates are visited in inventory order, as the walk over every budget visited them.
	pdbsIn := map[string][]int{}
	for i := range inv.PDBs {
		pdbsIn[inv.PDBs[i].Namespace] = append(pdbsIn[inv.PDBs[i].Namespace], i)
	}

	for _, nodeName := range sortedNodeNames(placement) {
		pl := placement[nodeName]
		var cands []int
		seen := map[string]bool{}
		for _, p := range pl.livePods {
			if !seen[p.Namespace] {
				seen[p.Namespace] = true
				cands = append(cands, pdbsIn[p.Namespace]...)
			}
		}
		sort.Ints(cands)
		for _, i := range cands {
			pdb := &inv.PDBs[i]
			sel := sels[i]
			if sel == nil || sel.Empty() {
				continue
			}
			covered := coveredOnNode(pl, pdb.Namespace, sel)
			if len(covered) == 0 {
				continue
			}
			if f, ok := budgetFinding(inv, pl, pdb, covered, opts); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

// coveredOnNode returns EVERY live pod on this node that the PDB's selector matches, regardless of
// what owns it.
//
// Ownership is deliberately irrelevant here. A budget covers pods, and every covered pod is one the
// eviction API must permit before a drain can finish — including a DaemonSet pod, and including a pod
// owned by an operator's custom resource. An earlier version filtered through the owner index and
// therefore reported nothing at all on the real cluster's four zero-budget PostgreSQL primaries and
// its Kafka broker set, because none of them are owned by a Deployment or StatefulSet.
func coveredOnNode(pl *drainPlacement, ns string, sel labels.Selector) []corev1.Pod {
	var covered []corev1.Pod
	for _, p := range pl.livePods {
		if p.Namespace == ns && sel.Matches(labels.Set(p.Labels)) {
			covered = append(covered, p)
		}
	}
	sort.Slice(covered, func(i, j int) bool { return covered[i].Name < covered[j].Name })
	return covered
}

func budgetFinding(inv *collect.Inventory, pl *drainPlacement, pdb *policyv1.PodDisruptionBudget,
	covered []corev1.Pod, opts Options) (types.Finding, bool) {

	if !opts.IncludeSystem && isSystemNamespace(pdb.Namespace) {
		return types.Finding{}, false
	}
	node := pl.node.Name
	j := len(covered)
	st := pdb.Status
	// Status is only meaningful when the controller has caught up with the spec. Asserting a budget
	// from a stale status is precisely the class of claim the honesty policy exists to prevent.
	fresh := st.ObservedGeneration == pdb.Generation

	names := make([]string, 0, len(covered))
	for _, p := range covered {
		names = append(names, p.Namespace+"/"+p.Name)
	}

	ev := []string{snapshotNote(inv)}
	var headline, why string
	confidence := 1.0

	switch {
	case !fresh:
		headline = fmt.Sprintf("Drain of %s: budget for %s/%s not asserted", node, pdb.Namespace, pdb.Name)
		ev = append(ev, fmt.Sprintf(
			"PodDisruptionBudget %s/%s covers %d of the pods bound to node %s (%s), but its status is "+
				"stale relative to its spec (status.observedGeneration=%d, metadata.generation=%d). "+
				"The published budget was therefore NOT used, and this audit makes no claim about what "+
				"the eviction API would do.",
			pdb.Namespace, pdb.Name, j, node, strings.Join(names, ", "),
			st.ObservedGeneration, pdb.Generation))
		why = "A disruption budget read from a stale status could describe a policy that is no longer " +
			"in effect. The covered pods are listed so the check can be repeated by hand."
		confidence = 1.0

	case st.DisruptionsAllowed == 0 && structuralZeroBudget(pdb, st):
		headline = fmt.Sprintf("Drain of %s is blocked by budget %s/%s", node, pdb.Namespace, pdb.Name)
		ev = append(ev, fmt.Sprintf(
			"PodDisruptionBudget %s/%s reports status.disruptionsAllowed=0 with %s, over "+
				"status.expectedPods=%d (currentHealthy=%d, desiredHealthy=%d). It covers %s "+
				"bound to node %s: %s. The eviction API would reject %s, so "+
				"`kubectl drain %s` would not complete; finishing it requires force-deletion, which "+
				"bypasses the budget entirely.",
			pdb.Namespace, pdb.Name, zeroBudgetReason(pdb, st), st.ExpectedPods,
			st.CurrentHealthy, st.DesiredHealthy, nWord(j, "live pod", "live pods"), node,
			strings.Join(names, ", "), map[bool]string{true: "that eviction",
				false: fmt.Sprintf("each of those %d evictions", j)}[j == 1], node))
		why = "The budget is structurally zero: it is written so that no voluntary eviction can ever " +
			"be permitted, which makes routine node maintenance impossible on every node these pods " +
			"land on, not only this one."

	case st.DisruptionsAllowed == 0:
		headline = fmt.Sprintf("Drain of %s: budget %s/%s is at zero right now", node, pdb.Namespace, pdb.Name)
		ev = append(ev, fmt.Sprintf(
			"PodDisruptionBudget %s/%s reports status.disruptionsAllowed=0 at snapshot time because "+
				"currentHealthy=%d is below desiredHealthy=%d (status.expectedPods=%d). It covers %s "+
				"bound to node %s: %s. This may be a transient reconciling state rather than a "+
				"standing property — re-check the budget before concluding anything about a drain.",
			pdb.Namespace, pdb.Name, st.CurrentHealthy, st.DesiredHealthy, st.ExpectedPods,
			nWord(j, "live pod", "live pods"), node, strings.Join(names, ", ")))
		why = "A budget at zero because the workload is momentarily unhealthy behaves like a blocked " +
			"budget while it lasts, but it is not written that way and may clear on its own."
		confidence = 0.9

	case int32(j) > st.DisruptionsAllowed:
		rounds := (j + int(st.DisruptionsAllowed) - 1) / int(st.DisruptionsAllowed)
		headline = fmt.Sprintf("Drain of %s serializes under budget %s/%s", node, pdb.Namespace, pdb.Name)
		ev = append(ev, fmt.Sprintf(
			"PodDisruptionBudget %s/%s reports status.disruptionsAllowed=%d over "+
				"status.expectedPods=%d. It covers %s bound to node %s: %s. Evicting them "+
				"therefore takes at least %s, each waiting until a replacement "+
				"is counted healthy before the next eviction is permitted.",
			pdb.Namespace, pdb.Name, st.DisruptionsAllowed, st.ExpectedPods,
			nWord(j, "live pod", "live pods"), node, strings.Join(names, ", "),
			nWord(rounds, "budget-limited round", "budget-limited rounds")))
		why = "The drain is permitted but not immediate: the budget forces the evictions into rounds. " +
			"This audit states the number of rounds, which is arithmetic; how long a round takes " +
			"depends on the workload and is not knowable from a snapshot."

	default:
		return types.Finding{}, false
	}

	if p := pdb.Spec.UnhealthyPodEvictionPolicy; p != nil {
		ev = append(ev, fmt.Sprintf("spec.unhealthyPodEvictionPolicy=%s.", *p))
	} else {
		ev = append(ev, "spec.unhealthyPodEvictionPolicy is unset, so IfHealthyBudget semantics apply: "+
			"pods that are not already healthy are not evictable under the budget.")
	}
	ev = append(ev, pdbBypassNote)
	ev = append(ev, endpointEvidence(inv, covered)...)

	return types.Finding{
		ID:      findingID((NodeDrainBudget{}).ID(), "Node", pdb.Namespace, node+"|"+pdb.Name),
		IDBasis: &types.ResourceRef{Kind: "Node", Namespace: pdb.Namespace, Name: node + "|" + pdb.Name},
		// What THIS reading could not establish about these pods. The pipeline merges the family boundaries
		// in on top; this is the half no table can hold.
		ClaimBoundaries: endpointBoundaries(inv, covered),
		RuleID:          (NodeDrainBudget{}).ID(), RuleVersion: (NodeDrainBudget{}).Version(),
		Title:        headline,
		Description:  fmt.Sprintf("Evacuating node %s requires evicting %s covered by PodDisruptionBudget %s/%s. The budget's own published status decides whether the eviction API permits that. The budget's own remedy, where one is needed, is reported by rule k8s.reliability.pdb-blocks-drains.", node, nWord(j, "pod", "pods"), pdb.Namespace, pdb.Name),
		WhyItMatters: why,
		Evidence:     ev,
		Severity:     types.SeverityMedium,
		Category:     types.CategoryReliability,
		AffectedResources: []types.ResourceRef{
			{Kind: "Node", Name: node},
			{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
		},
		EstimatedEffort: types.EffortMedium,
		// No remediation on purpose: PDBBlocksDrains already owns the `kubectl patch pdb` fix, and
		// offering it from two cards would put the same change on one page twice.
		DollarImpactMonthly: 0,
		Confidence:          confidence,
		Provenance:          provenance(),
	}, true
}

// scaledBudgetValue resolves an int-or-percentage budget against the number of pods it covers,
// rounding up as the disruption controller does.
func scaledBudgetValue(v *intstr.IntOrString, total int) (int, error) {
	return intstr.GetScaledValueFromIntOrPercent(v, total, true)
}

// structuralZeroBudget reports whether the budget is written so that no eviction can ever be
// allowed, as opposed to being momentarily exhausted.
func structuralZeroBudget(pdb *policyv1.PodDisruptionBudget, st policyv1.PodDisruptionBudgetStatus) bool {
	if mu := pdb.Spec.MaxUnavailable; mu != nil && intOrStringIsZero(*mu) {
		return true
	}
	// minAvailable is resolved against status.expectedPods — the pods the budget actually covers,
	// which is authoritative and may span several workloads. Resolving it against one workload's
	// spec.replicas is wrong whenever a loose selector spans more than one.
	if ma := pdb.Spec.MinAvailable; ma != nil && st.ExpectedPods > 0 {
		if scaled, err := scaledBudgetValue(ma, int(st.ExpectedPods)); err == nil && scaled >= int(st.ExpectedPods) {
			return true
		}
	}
	return false
}

func zeroBudgetReason(pdb *policyv1.PodDisruptionBudget, st policyv1.PodDisruptionBudgetStatus) string {
	if mu := pdb.Spec.MaxUnavailable; mu != nil && intOrStringIsZero(*mu) {
		return "spec.maxUnavailable=" + mu.String()
	}
	if ma := pdb.Spec.MinAvailable; ma != nil {
		if scaled, err := scaledBudgetValue(ma, int(st.ExpectedPods)); err == nil {
			return fmt.Sprintf("spec.minAvailable=%s, which resolves to %d against the %d pods it covers",
				ma.String(), scaled, st.ExpectedPods)
		}
		return "spec.minAvailable=" + ma.String()
	}
	return "a zero budget"
}

// ---------------------------------------------------------------------------------------------
// Rule B — placement arithmetic
// ---------------------------------------------------------------------------------------------

// NodePlacementConcentration reports workloads whose every live pod is bound to one node.
//
// The statement is placement and nothing more. It does not say the workload is a single point of
// failure, does not say anything is user-facing, and does not predict what happens next — see the
// refusals at the top of this file.
type NodePlacementConcentration struct{}

func (NodePlacementConcentration) ID() string      { return "k8s.reliability.node-placement-concentration" }
func (NodePlacementConcentration) Version() string { return "1.0.0" }

func (r NodePlacementConcentration) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	if !drainInputsOK(inv) {
		return out
	}
	placement := buildDrainPlacement(inv)
	index := newOwnerIndex(inv)
	live := index.livePodsByOwner(inv)
	endpoints := newEndpointIndex(inv)

	for _, nodeName := range sortedNodeNames(placement) {
		pl := placement[nodeName]

		owners := make([]drainOwner, 0, len(pl.byOwner))
		for o := range pl.byOwner {
			owners = append(owners, o)
		}
		sort.Slice(owners, func(i, j int) bool {
			if owners[i].Namespace != owners[j].Namespace {
				return owners[i].Namespace < owners[j].Namespace
			}
			return owners[i].Name < owners[j].Name
		})

		for _, o := range owners {
			if !opts.IncludeSystem && isSystemNamespace(o.Namespace) {
				continue
			}
			onNode := len(pl.byOwner[o])
			total := live[o]

			// A single-replica workload is SingleReplicaNoPDB's finding. Reporting it here too would
			// put two cards on one page for one fact.
			if total < 2 || onNode != total {
				continue
			}
			desired, known := index.desiredReplicas(o)
			// More live pods than desired means a surge or a rollout in flight, and the arithmetic
			// stops meaning anything — suppress rather than report a number that will not reproduce.
			if known && total > desired {
				continue
			}

			ev := []string{
				snapshotNote(inv),
				fmt.Sprintf("Every live Pod object of %s %s/%s (%d of %d) is bound to node %s: %s.",
					o.Kind, o.Namespace, o.Name, onNode, total, nodeName, podNames(pl.byOwner[o])),
				"Evicting or losing this node removes all of them at once; no pod of this workload " +
					"would remain until replacements are scheduled and pass their readiness checks.",
				// Replaced the old "membership is unobserved" line: the data is read now, so the
				// honest thing is the count rather than the disclaimer. See endpointEvidence.
			}
			ev = append(ev, endpointEvidence(inv, pl.byOwner[o])...)
			// The placement universal goes ONLY on the concentration finding. On the budget finding
			// it would sit next to a sentence about the eviction path and invite the reader to join
			// the two into an availability prediction, which is exactly the outcome claim these
			// rules refuse to make — and it would add nothing there.
			ev = append(ev, endpoints.placementEvidence(inv, pl.byOwner[o], nodeName)...)
			if known && total < desired {
				ev = append(ev, fmt.Sprintf(
					"The workload declares %s but %s observed, so it appears "+
						"to be mid-rollout or reconciling and this placement is in flux.",
					nWord(desired, "replica", "replicas"), nWord(total, "live pod was", "live pods were")))
			}
			if pl.daemonPods > 0 {
				ev = append(ev, fmt.Sprintf(
					"%s on this node belong to DaemonSets. They are node-local agents, "+
						"lost with the node by design, and are not counted as lost redundancy.", nWord(pl.daemonPods, "further pod", "further pods")))
			}
			if pl.unassessed > 0 {
				ev = append(ev, fmt.Sprintf(
					"%s on this node have owners this audit does not assess (Jobs, "+
						"CronJobs, or bare pods), so they are excluded from the arithmetic above.", nWord(pl.unassessed, "further pod", "further pods")))
			}
			if collect.ClassifyCapacityType(providerOf(inv), *pl.node) == types.CapacitySpot {
				ev = append(ev, "This node is spot/preemptible capacity, so its removal is not "+
					"necessarily a voluntary operation.")
			}

			out = append(out, types.Finding{
				ID:      findingID(r.ID(), "Node", o.Namespace, nodeName+"|"+o.Kind+"/"+o.Name),
				IDBasis: &types.ResourceRef{Kind: "Node", Namespace: o.Namespace, Name: nodeName + "|" + o.Kind + "/" + o.Name},
				// What THIS reading could not establish about where this workload's pods sit in a Service.
				ClaimBoundaries: endpointBoundaries(inv, pl.byOwner[o]),
				RuleID:          r.ID(), RuleVersion: r.Version(),
				Title: fmt.Sprintf("All %d pods of %s/%s are on node %s", onNode, o.Namespace, o.Name, nodeName),
				Description: fmt.Sprintf(
					"%s %s/%s has %s and all of them are bound to node %s. This is a "+
						"statement about placement at snapshot time, not a prediction about availability.",
					o.Kind, o.Namespace, o.Name, nWord(total, "live pod", "live pods"), nodeName),
				WhyItMatters: "Redundancy that exists in the replica count but not in the placement is " +
					"redundancy only on paper: one node event removes every copy at once.",
				Evidence: ev,
				Severity: types.SeverityMedium,
				Category: types.CategoryReliability,
				AffectedResources: []types.ResourceRef{
					{Kind: "Node", Name: nodeName},
					{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name},
				},
				EstimatedEffort:     types.EffortMedium,
				DollarImpactMonthly: 0,
				// The placement fact is certain; whether it matters depends on things the snapshot
				// cannot see, which is the same fact/impact split single-replica uses.
				Confidence: 0.9,
				Provenance: provenance(),
			})
		}
	}
	return out
}

func podNames(pods []corev1.Pod) string {
	names := make([]string, 0, len(pods))
	for _, p := range pods {
		names = append(names, p.Namespace+"/"+p.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// providerOf derives the cloud tag for capacity classification without duplicating collect's logic.
func providerOf(inv *collect.Inventory) string {
	if len(inv.Nodes) == 0 {
		return "unknown"
	}
	pid := inv.Nodes[0].Spec.ProviderID
	switch {
	case strings.HasPrefix(pid, "aws://"):
		return "eks"
	case strings.HasPrefix(pid, "azure://"):
		return "aks"
	case strings.HasPrefix(pid, "gce://"):
		return "gke"
	}
	return "unknown"
}

// ---------------------------------------------------------------------------------------------
// Rule C — volumes that pin a pod to this node
// ---------------------------------------------------------------------------------------------

// NodePinnedVolume reports pods whose PersistentVolume pins them to this node by its own
// nodeAffinity — a hard scheduling constraint written on the volume, not an inference.
type NodePinnedVolume struct{}

func (NodePinnedVolume) ID() string { return "k8s.reliability.node-pinned-volume" }

// Version 2.0.0 (2026-08-29): the finding shape changed from one card per POD to one card per
// (node, VOLUME). Gate 2 (RuleChanged) exists so a comparison across this withholds rather than
// reporting every old per-pod finding as resolved — the facts are identical, the cards are not.
// Version 2.1.0 (2026-10-27): a volume that another node also satisfies does not pin (pvPinsToNode).
func (NodePinnedVolume) Version() string { return "2.1.0" }

func (r NodePinnedVolume) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	if !drainInputsOK(inv) ||
		!observed(inv, "persistentvolumes") || !observed(inv, "persistentvolumeclaims") {
		return out
	}
	pvByName := map[string]*corev1.PersistentVolume{}
	for i := range inv.PVs {
		pvByName[inv.PVs[i].Name] = &inv.PVs[i]
	}
	pvcByKey := map[string]*corev1.PersistentVolumeClaim{}
	for i := range inv.PVCs {
		pvcByKey[inv.PVCs[i].Namespace+"/"+inv.PVCs[i].Name] = &inv.PVCs[i]
	}

	placement := buildDrainPlacement(inv)
	for _, nodeName := range sortedNodeNames(placement) {
		pl := placement[nodeName]

		owners := make([]drainOwner, 0, len(pl.byOwner))
		for o := range pl.byOwner {
			owners = append(owners, o)
		}
		sort.Slice(owners, func(i, j int) bool {
			if owners[i].Namespace != owners[j].Namespace {
				return owners[i].Namespace < owners[j].Namespace
			}
			return owners[i].Name < owners[j].Name
		})

		// ONE FINDING PER VOLUME. The volume is the thing that pins; the pods are what it pins, and a
		// constraint belonging to one object was producing one card per pod that happened to mount it.
		// Collecting the mounters first is also what removes B-138's duplicate-ID failure at its cause:
		// one volume produces one finding however many pods mount it.
		byVolume := map[string]*pinnedVolume{}
		var volumeOrder []string
		for _, o := range owners {
			if !opts.IncludeSystem && isSystemNamespace(o.Namespace) {
				continue
			}
			for _, p := range pl.byOwner[o] {
				for _, pinned := range pinnedPVsFor(p, pvcByKey, pvByName, nodeName, inv.Nodes) {
					pvName := pinned.Name
					pin := byVolume[pvName]
					if pin == nil {
						pin = &pinnedVolume{pv: pinned}
						byVolume[pvName] = pin
						volumeOrder = append(volumeOrder, pvName)
					}
					pin.mounts = append(pin.mounts, pinnedMount{pod: p, owner: o})
				}
			}
		}
		sort.Strings(volumeOrder)
		for _, pvName := range volumeOrder {
			out = append(out, pinnedVolumeFinding(inv, r, nodeName, byVolume[pvName]))
		}
	}
	return out
}

// pinnedMount is one pod that mounts a pinned volume, with the workload that owns it. Both are carried
// because the evidence names both: collapsing the cards must not lose a fact either one supplied.
type pinnedMount struct {
	pod   corev1.Pod
	owner drainOwner
}

type pinnedVolume struct {
	pv     *corev1.PersistentVolume
	mounts []pinnedMount
}

// pinnedPVsFor returns the PVs bound to this pod that pin it to nodeName by their own nodeAffinity.
// An unbound PVC is skipped rather than guessed about.
func pinnedPVsFor(p corev1.Pod, pvcByKey map[string]*corev1.PersistentVolumeClaim,
	pvByName map[string]*corev1.PersistentVolume, nodeName string, nodes []corev1.Node) []*corev1.PersistentVolume {

	var pinned []*corev1.PersistentVolume
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		pvc := pvcByKey[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName]
		if pvc == nil || pvc.Spec.VolumeName == "" {
			continue // unbound or unreadable: no claim to make
		}
		pv := pvByName[pvc.Spec.VolumeName]
		if pv == nil || pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
			continue
		}
		if pvPinsToNode(pv, nodeName, nodes) {
			pinned = append(pinned, pv)
		}
	}
	sort.Slice(pinned, func(i, j int) bool { return pinned[i].Name < pinned[j].Name })
	return pinned
}

// pvPinsToNode reports whether the PV's required node affinity names this specific node by hostname.
//
// ONLY A HOSTNAME MATCH COUNTS HERE, AND ZONE LEVEL IS NOW COVERED ELSEWHERE. This comment used to say a
// zone-level requirement was "deliberately out of this pass" and stop there; it is in scope as of
// 2026-08-29, in ZonePinnedVolume (internal/rules/feasibility.go), and the old exclusion is rewritten rather
// than deleted because a widening that quietly removes a limit reads as if the limit never existed.
//
// HOW THE ZONE CLAIM IS WEAKER, exactly. A hostname-pinned volume names WHERE the pod is, so it blocks a
// drain of that node: there is no other node the volume permits. A ZONAL disk constrains where a pod MAY GO
// without naming where it is — another node in the same zone satisfies it, so a drain inside the zone is
// unaffected. What a zonal disk blocks is the pod leaving the zone at all, which is a zone-loss statement and
// not a drain statement. Two different claims, and this rule makes only the stronger one.
//
// NAMED AND ALONE. A volume whose affinity names this node AND another one (a hostname In list of two, or two
// terms) is satisfied by either, so a drain of this node leaves the pod the other: the first name used to match
// and the drain was reported blocked by a volume that does not block it. A pin holds only when no other node in
// the reading satisfies the volume, the same pvAdmits the placement model asks.
func pvPinsToNode(pv *corev1.PersistentVolume, nodeName string, nodes []corev1.Node) bool {
	if !pvNamesNode(pv, nodeName) {
		return false
	}
	for i := range nodes {
		if nodes[i].Name != nodeName && pvAdmits(pv, &nodes[i]) {
			return false
		}
	}
	return true
}

// pvNamesNode reports whether the volume's required affinity names this node by hostname or metadata.name.
func pvNamesNode(pv *corev1.PersistentVolume, nodeName string) bool {
	for _, term := range pv.Spec.NodeAffinity.Required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key != "kubernetes.io/hostname" || expr.Operator != corev1.NodeSelectorOpIn {
				continue
			}
			for _, v := range expr.Values {
				if v == nodeName {
					return true
				}
			}
		}
		for _, f := range term.MatchFields {
			if f.Key != "metadata.name" {
				continue
			}
			for _, v := range f.Values {
				if v == nodeName {
					return true
				}
			}
		}
	}
	return false
}

func pinnedVolumeFinding(inv *collect.Inventory, r NodePinnedVolume, nodeName string,
	pin *pinnedVolume) types.Finding {

	sort.Slice(pin.mounts, func(i, j int) bool {
		a, b := pin.mounts[i].pod, pin.mounts[j].pod
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	pv := pin.pv
	n := len(pin.mounts)

	// EVERY POD STAYS NAMED, WITH ITS OWNER. Collapsing changes the number of cards, never the number of
	// facts — a reader who had one card per pod must still be able to read every pod off this one.
	mountLines := make([]string, 0, n)
	refs := []types.ResourceRef{
		{Kind: "Node", Name: nodeName},
		{Kind: "PersistentVolume", Name: pv.Name},
	}
	ownersSeen := map[drainOwner]bool{}
	statefulOwner := false
	for _, m := range pin.mounts {
		mountLines = append(mountLines, fmt.Sprintf("pod %s/%s, owned by %s %s/%s",
			m.pod.Namespace, m.pod.Name, m.owner.Kind, m.owner.Namespace, m.owner.Name))
		refs = append(refs, types.ResourceRef{
			Kind: "Pod", Namespace: m.pod.Namespace, Name: m.pod.Name})
		if !ownersSeen[m.owner] {
			ownersSeen[m.owner] = true
			refs = append(refs, types.ResourceRef{
				Kind: m.owner.Kind, Namespace: m.owner.Namespace, Name: m.owner.Name})
		}
		if m.owner.Kind == "StatefulSet" {
			statefulOwner = true
		}
	}

	ev := []string{
		snapshotNote(inv),
		fmt.Sprintf("PersistentVolume %s is pinned to node %s by its own spec.nodeAffinity.required "+
			"(kubernetes.io/hostname).", pv.Name, nodeName),
		map[bool]string{true: "1 pod mounts it, and it can therefore only run on this node:",
			false: fmt.Sprintf("%d pods mount it, and each of them can therefore only run on this node:", n)}[n == 1],
	}
	ev = append(ev, mountLines...)
	ev = append(ev,
		"This is a hard scheduling constraint read verbatim from the volume, not an inference from "+
			"where the pods happen to be running.",
		"What this does NOT say: whether the workload tolerates losing this member. A correctly "+
			"replicated quorum system may be entirely unaffected, and a single-writer database may "+
			"not be — the same evidence supports both, and this audit does not distinguish them.")
	if statefulOwner {
		ev = append(ev, "At least one mounting pod is owned by a StatefulSet, so its at-most-one identity "+
			"guarantee also applies: while the node is unreachable the pod object is not deleted, so no "+
			"replacement with the same identity is created. Clearing that requires the Node object to be "+
			"removed (cloud controllers often do this for a terminated instance) or an operator to mark "+
			"the node out-of-service after confirming it is powered off.")
	}

	// THE KEY IS (node, volume), WHICH IS WHAT IT WAS BEFORE B-138 AND WHAT IT SHOULD HAVE STAYED. The
	// pod was appended to it as a narrow fix for the duplicate-ID crash; with the finding reshaped around
	// the volume, one volume produces one finding and the crash has no way to occur.
	ns := ""
	if pv.Spec.ClaimRef != nil {
		ns = pv.Spec.ClaimRef.Namespace
	}
	return types.Finding{
		ID:      findingID(r.ID(), "Node", ns, nodeName+"|"+pv.Name),
		IDBasis: &types.ResourceRef{Kind: "Node", Namespace: ns, Name: nodeName + "|" + pv.Name},
		RuleID:  r.ID(), RuleVersion: r.Version(),
		Title: fmt.Sprintf("Volume %s pins %s to node %s", pv.Name, nWord(n, "pod", "pods"), nodeName),
		Description: fmt.Sprintf(
			"PersistentVolume %s carries a required nodeAffinity naming node %s. %s that "+
				"volume and therefore cannot be placed on any other node while the pin stands.",
			pv.Name, nodeName, nWord(n, "pod mounts", "pods mount")),
		WhyItMatters: "A volume that names one node turns node maintenance into an application " +
			"question: the pods cannot simply move, so evacuating the node has to be planned around " +
			"the data rather than around the pods.",
		Evidence:            ev,
		Severity:            types.SeverityHigh,
		Category:            types.CategoryReliability,
		AffectedResources:   refs,
		EstimatedEffort:     types.EffortHigh,
		DollarImpactMonthly: 0,
		Confidence:          1.0,
		Provenance:          provenance(),
	}
}

// ---------------------------------------------------------------------------------------------
// endpoint registration — what a controller actually published, as opposed to what a selector matches
// ---------------------------------------------------------------------------------------------

// endpointTally counts, for one node's pods, how many were published as backends of some Service.
//
// Every field is a count over objects this audit listed. None of it is request data: an EndpointSlice
// entry records that a controller listed an address as a backend, never that a request reached it.
type endpointTally struct {
	registered  int    // deduped entries whose targetRef resolves to a pod in the finding
	ready       int    // conditions.ready == true
	readyUnset  int    // conditions.ready == nil — the API defines this as UNKNOWN, never as true
	terminating int    // conditions.terminating == true
	services    int    // distinct Services that published them
	addressType string // the family these counts cover; never summed across families
	unresolved  int    // pods in the finding that matched no entry
	foreignMgr  bool   // some contributing slice is not written by the EndpointSlice controller
	publishNR   bool   // some involved Service sets publishNotReadyAddresses
}

// tallyEndpoints builds the count for a specific set of pods on one node.
//
// Deliberate choices, each guarding a way this could lie:
//   - dedup by targetRef.uid, because the same pod legitimately appears in several slices (a
//     dual-stack Service publishes an IPv4 and an IPv6 slice for the same backends, and counting
//     both would double every figure);
//   - counts are computed for ONE addressType and never summed across families;
//   - conditions.ready == nil goes in its own bucket. The API defines an unset value as unknown, and
//     internal/prom/portforward.go deliberately treats nil as ready — correct when picking a
//     port-forward target, wrong as the basis of a published figure. Both behaviours are pinned by
//     tests so nobody "harmonises" them;
//   - endpoint.nodeName is never used to place a pod: it has no referential integrity, is a batched
//     copy that can disagree with the pod list read in the same audit, and is absent on manually
//     written slices. The join is targetRef.uid only.
func tallyEndpoints(inv *collect.Inventory, pods []corev1.Pod) endpointTally {
	want := map[types2.UID]bool{}
	for _, p := range pods {
		want[p.UID] = true
	}

	t := endpointTally{}
	svcSeen := map[string]bool{}
	countedUID := map[types2.UID]bool{}
	matchedPod := map[types2.UID]bool{}

	for _, s := range inv.EndpointSlices {
		// One address family only. IPv4 is chosen when present so the figure is stable; a
		// v6-only Service reports v6.
		if t.addressType != "" && string(s.AddressType) != t.addressType {
			continue
		}
		hit := false
		for _, ep := range s.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || !want[ep.TargetRef.UID] {
				continue
			}
			hit = true
			if countedUID[ep.TargetRef.UID] {
				continue
			}
			countedUID[ep.TargetRef.UID] = true
			matchedPod[ep.TargetRef.UID] = true
			t.registered++
			switch {
			case ep.Conditions.Ready == nil:
				t.readyUnset++
			case *ep.Conditions.Ready:
				t.ready++
			}
			if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
				t.terminating++
			}
		}
		if !hit {
			continue
		}
		if t.addressType == "" {
			t.addressType = string(s.AddressType)
		}
		if name := s.Labels[discoveryv1.LabelServiceName]; name != "" && !svcSeen[s.Namespace+"/"+name] {
			svcSeen[s.Namespace+"/"+name] = true
			t.services++
			if svcPublishesNotReady(inv, s.Namespace, name) {
				t.publishNR = true
			}
		}
		if mgr := s.Labels["endpointslice.kubernetes.io/managed-by"]; mgr != "" && mgr != "endpointslice-controller.k8s.io" {
			t.foreignMgr = true
		}
	}
	for uid := range want {
		if !matchedPod[uid] {
			t.unresolved++
		}
	}
	return t
}

func svcPublishesNotReady(inv *collect.Inventory, ns, name string) bool {
	for _, s := range inv.Services {
		if s.Namespace == ns && s.Name == name {
			return s.Spec.PublishNotReadyAddresses
		}
	}
	return false
}

// endpointEvidence renders the tally as Evidence lines, or the honest absence when the slices were
// not read.
//
// Every sentence is present-tense set membership over objects this audit listed. There is
// deliberately no future-tense verb anywhere: "N entries record X" is arithmetic, while "draining
// this removes X" is a prediction the snapshot cannot support — the eviction API may refuse the
// drain, a budget may serialise it so a replacement readies in between, and an endpoint that is both
// serving and terminating keeps taking requests after leaving the ready set.
//
// These go in Evidence and never in Title/Description/WhyItMatters: the priority function scans those
// three for hedging words and subtracts from the score, so a caveat placed there would silently
// demote the finding by wording rather than by data.
func endpointEvidence(inv *collect.Inventory, pods []corev1.Pod) []string {
	if !observed(inv, "endpointslices") {
		return []string{"EndpointSlices were not read in this audit, so whether these pods were " +
			"published as backends of any Service is unknown."}
	}
	t := tallyEndpoints(inv, pods)
	if t.registered == 0 {
		if len(pods) == 1 {
			return []string{"This pod does not appear as an endpoint entry in any EndpointSlice this audit read."}
		}
		return []string{fmt.Sprintf(
			"None of these %d pods appear as an endpoint entry in any EndpointSlice this audit read.",
			len(pods))}
	}

	var out []string
	head := fmt.Sprintf("At read time, %d of these %d pods were listed as endpoint entries in "+
		"EndpointSlices belonging to %s", t.registered, len(pods), nWord(t.services, "Service", "Services"))
	if t.publishNR {
		// A Service that publishes not-ready addresses makes the readiness figures meaningless
		// rather than merely noisy, so they are omitted entirely instead of footnoted.
		out = append(out, head+". Readiness figures are omitted: at least one of those Services sets "+
			"spec.publishNotReadyAddresses, so an entry's readiness says nothing about its state.")
	} else {
		out = append(out, fmt.Sprintf("%s: %d recorded conditions.ready=true, %d left ready unset "+
			"(the API defines an unset value as unknown, so they are counted apart and never added to "+
			"the ready figure), and %d recorded terminating=true.",
			head, t.ready, t.readyUnset, t.terminating))
	}

	out = append(out, "An EndpointSlice records that a controller listed an address as a backend of a "+
		"Service. It is not an observation that any request reached that address, and this audit reads "+
		"no request data of any kind.")
	out = append(out, fmt.Sprintf("Entries were counted after deduplication by targetRef UID, because "+
		"the same pod may legitimately appear in more than one slice. The figures cover addressType %s "+
		"only and are not summed across address families.", t.addressType))

	if t.unresolved > 0 {
		out = append(out, fmt.Sprintf("%d of these pods matched no endpoint entry; that is not evidence "+
			"they are unused, only that no slice this audit read named them.", t.unresolved))
	}
	if t.foreignMgr {
		out = append(out, "At least one contributing slice is not written by the EndpointSlice "+
			"controller, so its contents follow whatever wrote it rather than the selector model.")
	}
	return out
}

// endpointPlacementEvidence states where a Service's published backends sit, for the Services that
// published the given pods.
//
// The useful sentence here is stronger than the pod-level one above: not "these pods are on one node"
// but "every backend this Service publishes is on one node". A universal is falsified by a single
// exception, so it is emitted ONLY when every deduped entry of the chosen address family resolved to
// a node. When one cannot be placed, the count is stated and no universal is made — suppressing
// rather than hedging, because a hedged universal reads as a universal.
//
// Placement is resolved through targetRef UID to the pod's own spec.nodeName. endpoint.nodeName is
// never substituted for it: that field has no referential integrity, is a batched copy that can
// disagree with the pod list read in the same audit, and is absent on manually written slices.
//
// Headless Services are skipped entirely. They have no proxy in front of them, so "published for"
// would invite a routing reading this data cannot support.
func endpointPlacementEvidence(inv *collect.Inventory, pods []corev1.Pod, nodeName string) []string {
	return newEndpointIndex(inv).placementEvidence(inv, pods, nodeName)
}

// endpointIndex is what endpointPlacementEvidence reads about the whole cluster, built once for a rule's every
// finding rather than once per finding.
//
// A FINDING'S EVIDENCE SHOULD COST THE FINDING, NOT THE CLUSTER. Each concentration finding rebuilt a map of every
// pod's node and looked every slice's Service up by walking every Service — findings × (pods + slices × services),
// which on a large cluster with a few dozen findings was most of the rule. The answers are the ones the walks
// gave: the last pod with a UID names its node, as the map's overwrite did, and the first Service with a
// namespace and name decides whether it is headless, as the walk's early return did.
type endpointIndex struct {
	nodeOf map[types2.UID]string
	// headless is "<namespace>/<name>" → spec.clusterIP is None. Such a Service has no proxy in front of it, so
	// a statement about what is "published for" it would invite a routing reading the data cannot support.
	headless map[string]bool
}

func newEndpointIndex(inv *collect.Inventory) *endpointIndex {
	x := &endpointIndex{nodeOf: map[types2.UID]string{}, headless: map[string]bool{}}
	for _, p := range inv.Pods {
		x.nodeOf[p.UID] = p.Spec.NodeName
	}
	for _, s := range inv.Services {
		k := s.Namespace + "/" + s.Name
		if _, seen := x.headless[k]; !seen {
			x.headless[k] = s.Spec.ClusterIP == corev1.ClusterIPNone
		}
	}
	return x
}

func (x *endpointIndex) placementEvidence(inv *collect.Inventory, pods []corev1.Pod, nodeName string) []string {
	if !observed(inv, "endpointslices") {
		return nil
	}
	inFinding := map[types2.UID]bool{}
	for _, p := range pods {
		inFinding[p.UID] = true
	}
	nodeOf := x.nodeOf

	// Services that published at least one of this finding's pods, excluding headless ones.
	services := map[string]bool{}
	for _, s := range inv.EndpointSlices {
		name := s.Labels[discoveryv1.LabelServiceName]
		if name == "" || x.headless[s.Namespace+"/"+name] {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.TargetRef != nil && inFinding[ep.TargetRef.UID] {
				services[s.Namespace+"/"+name] = true
				break
			}
		}
	}
	if len(services) == 0 {
		return nil
	}

	var out []string
	for _, key := range sortedKeys(services) {
		ns, name := splitNSName(key)
		total, here, unplaceable, family := placementOfService(inv, nodeOf, ns, name, nodeName)
		if total == 0 {
			continue
		}
		switch {
		case unplaceable > 0:
			out = append(out, fmt.Sprintf(
				"Of the %d endpoint entries published for a Service in this namespace (addressType %s), "+
					"%d record pods bound to node %s and %d could not be placed from this snapshot, so no "+
					"statement is made about all of them.", total, family, here, nodeName, unplaceable))
		case here == total:
			out = append(out, fmt.Sprintf(
				"Every endpoint entry published for a Service in this namespace (%d of %d, addressType "+
					"%s) records a pod bound to node %s.", here, total, family, nodeName))
		default:
			out = append(out, fmt.Sprintf(
				"%d of the %d endpoint entries published for a Service in this namespace (addressType "+
					"%s) record pods bound to node %s; the rest are on other nodes.",
				here, total, family, nodeName))
		}
	}
	return out
}

// placementOfService counts, for one Service, how many of its deduped endpoint entries resolve to
// the target node, how many could not be placed at all, and which address family was counted.
//
// One family only, fixed by the first slice that contributes an entry: a dual-stack Service publishes
// the same backends twice and summing the families would double every figure.
func placementOfService(inv *collect.Inventory, nodeOf map[types2.UID]string, ns, name, target string) (total, here, unplaceable int, family string) {
	seen := map[types2.UID]bool{}
	for _, s := range inv.EndpointSlices {
		if s.Namespace != ns || s.Labels[discoveryv1.LabelServiceName] != name {
			continue
		}
		if family != "" && string(s.AddressType) != family {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || seen[ep.TargetRef.UID] {
				continue
			}
			seen[ep.TargetRef.UID] = true
			if family == "" {
				family = string(s.AddressType)
			}
			total++
			switch node, known := nodeOf[ep.TargetRef.UID]; {
			case !known || node == "":
				// The entry points at a pod this audit did not see, or one not yet bound. Either way
				// it cannot be placed, and a universal over the set is therefore not available.
				unplaceable++
			case node == target:
				here++
			}
		}
	}
	return total, here, unplaceable, family
}

// sortedKeys returns a map's keys in a stable order, so findings do not reshuffle between runs.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func splitNSName(key string) (ns, name string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", key
}

// RequiredKinds — EndpointSlices are deliberately absent: they add a registration count as evidence to a finding that
// already fired, and a run without them makes the identical claim about the identical nodes. Declaring
// them would make the report say this rule was not evaluated when it was.
// See deps.go for what belongs in this list.
func (r NodeDrainBudget) RequiredKinds() []string {
	return []string{"nodes", "poddisruptionbudgets", "pods"}
}

// RequiredKinds — The workload lists are a SUPPRESSION input, which is why they are load-bearing in the dangerous
// direction: desiredReplicas is how this rule declines to report a rollout in flight, so a denied
// Deployment list turns a suppressed non-finding into a false positive.
// See deps.go for what belongs in this list.
func (r NodePlacementConcentration) RequiredKinds() []string {
	return []string{"deployments", "nodes", "pods", "statefulsets"}
}

// RequiredKinds — the nodes the drain is asked about and the pods on them; nothing else decides the client's
// refusal. See deps.go for what belongs in this list.
func (r NodeDrainUnmanaged) RequiredKinds() []string {
	return []string{"nodes", "pods"}
}

// RequiredKinds — Both volume lists: a PVC without its PV says nothing about where the volume can be attached.
// See deps.go for what belongs in this list.
func (r NodePinnedVolume) RequiredKinds() []string {
	return []string{"nodes", "persistentvolumeclaims", "persistentvolumes", "pods"}
}

// endpointBoundaries is what THIS reading could not establish about these pods' place in a Service.
//
// It is the conditional half of the claim-boundary field, and it exists because a static table cannot hold
// it: "three of these pods matched no endpoint entry" is a fact about one run, and it is the sentence a
// reader — or a model — needs before drawing a conclusion the reading does not support. The family
// boundaries beside it say what a drain finding NEVER establishes; these say what THIS one could not.
//
// The same facts already appear in Evidence, as prose among a dozen other bullets. That is where a human
// reads them and it is not somewhere a machine can find them, which is the whole reason for the field.
func endpointBoundaries(inv *collect.Inventory, pods []corev1.Pod) []string {
	if !observed(inv, "endpointslices") {
		return []string{"EndpointSlices were not read in this reading, so nothing here says whether these " +
			"pods were published as backends of any Service."}
	}
	t := tallyEndpoints(inv, pods)
	var out []string
	if t.registered == 0 {
		out = append(out, "No pod here appeared as an endpoint entry in any EndpointSlice this reading saw, "+
			"which is not evidence that they serve nothing — only that no slice this reading read named them.")
		return out
	}
	if t.unresolved > 0 {
		out = append(out, fmt.Sprintf("%d of these pods matched no endpoint entry in this reading. That is "+
			"not evidence they are unused; it is the absence of a slice naming them.", t.unresolved))
	}
	if t.publishNR {
		out = append(out, "At least one Service involved sets spec.publishNotReadyAddresses, so an entry's "+
			"readiness says nothing about its state and no readiness figure is stated for these pods.")
	}
	if t.foreignMgr {
		out = append(out, "At least one contributing EndpointSlice was not written by the EndpointSlice "+
			"controller, so its contents follow whatever wrote it rather than the selector model.")
	}
	return out
}

// nWord says a count with its noun: "1 pod", "3 pods". Findings are read by people and quoted on the landing word
// for word, and "1 pod(s)" is the engine's grammar, not an answer.
func nWord[N ~int | ~int32 | ~int64](n N, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// pick is the word that agrees with a count: a verb ("is"/"are") or a noun said without its number.
func pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
