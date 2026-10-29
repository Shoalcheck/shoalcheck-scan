package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// feasibility.go — LOSE A ZONE, LOSE A NODE: WHICH WORK HAS NOWHERE MODELLED TO GO.
//
// The question is the one an SRE has after an availability-zone incident: if this zone were gone, which pods
// would have no remaining node that satisfies their constraints? The answer is arithmetic over the snapshot
// plus a NAMED, PARTIAL model of the scheduler's predicates.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY THE NEGATIVE IS SOUND AND THE POSITIVE IS NOT — the argument this whole file rests on
//
// A model that checks a SUBSET of the scheduler's predicates is MORE PERMISSIVE than the scheduler. So if the
// model finds no fit, the real scheduler — which checks everything the model checks plus more — also finds no
// fit. The negative is sound BY THE VERY FACT THAT THE MODEL IS PARTIAL, which is the opposite of the usual
// worry.
//
// The positive is unsound in the same breath and by the same argument. "Every evicted pod has a feasible home"
// would require the model to be a SUPERSET of the scheduler's constraints, and a read-only client cannot build
// one: the scheduler's own configuration is unreadable on EKS/AKS/GKE, the pod that gets placed is not the pod
// we read (admission injects sidecars — B-102 and B-103 in the ledger are both that gap), per-node volume
// attach limits and max-pods are uncollected or unread, and inter-pod affinity and topology skew are
// order-dependent so a fit found by OUR search order is not the one the scheduler's greedy pass reaches.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
//	No scheduler verdict. Every sentence is about THE MODEL. `will schedule`, `will not schedule` and
//	`cannot be scheduled` are banned in bannedDrainPhrases and this feature does not earn them; the
//	supportable form is "no node in this reading satisfies the constraints this model checks".
//
//	No positive placement, and no proposed assignment in any field. See above. There is no
//	RemediationYAML on any finding here, because that is where a placement would hide.
//
//	NO COST OUTPUT AT ALL. Not "these three nodes could be removed", not a dollar, not a smaller
//	configuration. The cost half of B-5 was refused in writing, and the reason it was refused in writing
//	rather than discovered in month three is that it is easier to erode than to argue with: an intermediate
//	result that makes consolidation look computable is that refusal returning under a different name.
//
//	No optimality. The model does not search for the best placement; it asks whether ANY candidate node
//	satisfies the predicates, and reports only when none does.
//
//	Preemption and autoscaling are named IN THE SENTENCE, not in a footnote. A higher-priority pod can
//	evict a lower-priority one and take its place — `priorityclasses` is not collected and Pod.Spec.Priority
//	is read nowhere, so preemption is unmodelled. And an autoscaler can add nodes: the claim is about the
//	EXISTING node set at the moment of the reading.
//
//	A pod bound to a custom scheduler is EXCLUDED AND COUNTED. Its feasibility is decided by code we cannot
//	read. Excluding it silently is the defect; the count is in the finding.
//
//	A snapshot is a snapshot. A node pool added five minutes later changes every answer here.
//
// feasibility_test.go enforces the phrase list mechanically, the way node_drain_test.go does for drains.

// modelledPredicates is published IN THE FINDING, not in documentation. A named partial model is true; a
// fidelity claim is not — and a reader cannot judge the claim without the list.
var modelledPredicates = []string{
	"the pod's cpu and memory requests against the candidate node's allocatable",
	"nodeSelector, as equality across every key",
	"required node affinity (requiredDuringSchedulingIgnoredDuringExecution), over the node's labels",
	"NoSchedule and NoExecute taints against the pod's tolerations",
	"node readiness and the unschedulable flag",
	"a PersistentVolume whose own nodeAffinity pins the pod to a node or a zone",
	"a host port the pod asks for, against the host ports the pods already on the node hold (a hostNetwork pod asks for its container ports)",
}

// unmodelledPredicates is published beside it. The list is the claim's boundary, and a boundary a reader
// cannot see is not one.
var unmodelledPredicates = []string{
	"preemption — a higher-priority pod can evict a lower-priority one and take its place; priorityclasses are not collected",
	"autoscaling — a node pool can add capacity; this reads the node set as it stands",
	"inter-pod affinity and anti-affinity, which are order-dependent",
	"topologySpread skew, which is computed against a domain set that changes as pods are placed",
	"max pods per node, ephemeral-storage and extended resources such as GPUs",
	"per-node volume attach limits (csinodes are not collected)",
	"two leaving pods that ask for the same host port, against each other",
	"the scheduler's own configuration: which plugins, profiles or extenders are enabled",
	"admission — the pod that would be created from a template is not the pod read here, because injectors add containers and requests",
}

// feasibilityRequests is the per-pod request sum, and it is podRequests.
//
// ONE WALKER, NOT A FOURTH. This package already carries three divergent request walkers and one of them says
// so in its header — templateRequests "DELIBERATELY DISAGREES WITH node_headroom.go's podRequests()". A fourth
// would make the same pod cost different amounts depending on which rule asked. The alias exists so the reuse
// is visible at the call site and so a test can assert it (TestFeasibility_ReusesOneRequestWalker).
//
// What podRequests gets right and matters here: a NATIVE SIDECAR — an initContainer with
// restartPolicy: Always — is reserved by the scheduler for the pod's whole life and counts, while a classic
// init container runs to completion and releases. B-102 and B-103 were both that boundary.
func feasibilityRequests(p corev1.Pod) (cpu, mem resource.Quantity) { return podRequests(p) }

// holdsRoom reports whether a pod's requests still occupy its node. A pod that has Succeeded or Failed stays bound
// until it is garbage-collected — a CronJob keeps its last few on purpose — but the scheduler does not count it
// (a terminal pod is not in its cache) and neither does the kubelet's admission, which counts active pods. Counting
// it here made a node holding finished Jobs look full, and "nowhere to go" was then reported for a pod the
// scheduler would place: the one direction the negative claim in fits() cannot afford to be wrong in. Measured on
// the engine bench (docs/engine/benchmark.md, "terminal pods").
func holdsRoom(p corev1.Pod) bool {
	return p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed
}

// candidate is a node the model may place a pod on.
type candidate struct {
	node *corev1.Node
	// free is allocatable minus what is already requested by pods bound to it. Deliberately NOT a repack:
	// the surviving pods stay where they are, and only the displaced ones are being asked about.
	freeCPU resource.Quantity
	freeMem resource.Quantity
	// ports are the host ports the pods bound to it hold, nil when none do. Read-only, like the room.
	ports map[hostPortKey]bool
}

// hostPortKey is a host port as the scheduler's NodePorts filter keys it: address, protocol and number, with an
// empty address read as every address and an empty protocol as TCP.
type hostPortKey struct {
	ip, protocol string
	port         int32
}

const everyAddress = "0.0.0.0"

// hostPortsOf is the host ports a pod asks for, as the scheduler reads them.
//
// THE REGULAR CONTAINERS ONLY, on both sides of the comparison, which is what NodePorts reads. A hostNetwork pod's
// container ports are its host ports: the API server defaults hostPort to containerPort for it, so a pod read from
// a cluster already carries them, and doing the same here keeps a pod built any other way honest.
func hostPortsOf(p corev1.Pod) []hostPortKey {
	var out []hostPortKey
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			port := cp.HostPort
			if port == 0 && p.Spec.HostNetwork {
				port = cp.ContainerPort
			}
			if port <= 0 {
				continue
			}
			k := hostPortKey{ip: cp.HostIP, protocol: string(cp.Protocol), port: port}
			if k.ip == "" {
				k.ip = everyAddress
			}
			if k.protocol == "" {
				k.protocol = string(corev1.ProtocolTCP)
			}
			out = append(out, k)
		}
	}
	return out
}

// portsFree reports whether none of the ports a pod asks for is already held on a node, by the scheduler's own
// conflict rule: a port on every address conflicts with that protocol and number on any address, and a port on
// one address conflicts with the same address or with every address. Two different specific addresses do not.
func portsFree(held map[hostPortKey]bool, asked []hostPortKey) bool {
	for _, a := range asked {
		if a.ip == everyAddress {
			for h := range held {
				if h.protocol == a.protocol && h.port == a.port {
					return false
				}
			}
			continue
		}
		if held[a] || held[hostPortKey{ip: everyAddress, protocol: a.protocol, port: a.port}] {
			return false
		}
	}
	return true
}

// fits reports whether the model's predicates admit this pod on this candidate.
//
// EVERY `false` HERE IS A REASON THE SCHEDULER WOULD ALSO REFUSE, which is what makes the aggregate negative
// sound. Every predicate absent from this function is a reason the scheduler MIGHT refuse that the model does
// not see — and that asymmetry is why the model can only ever say "no".
func fits(c candidate, p corev1.Pod, cpu, mem resource.Quantity) bool {
	if !admits(c, p) {
		return false
	}
	return c.freeCPU.Cmp(cpu) >= 0 && c.freeMem.Cmp(mem) >= 0
}

// admits is fits() WITHOUT the capacity check: whether the node's declarations and the pod's would ever allow
// this pairing, regardless of how full the node is right now.
//
// Split out because the two answers mean different things. A node that refuses on capacity refuses TODAY; a
// node that refuses on a nodeSelector, a taint or an affinity term refuses until somebody edits an object.
// Only the second is reported at node granularity.
func admits(c candidate, p corev1.Pod) bool {
	n := c.node
	// nodeIsReady is rollout_preflight.go's, reused rather than reimplemented. A node with no Ready condition
	// has not reported and is not eligible — the conservative direction, and one definition of it.
	if n.Spec.Unschedulable || !nodeIsReady(n) {
		return false
	}
	for k, v := range p.Spec.NodeSelector {
		if n.Labels[k] != v {
			return false
		}
	}
	if !nodeAffinityAdmits(p, n) {
		return false
	}
	return tolerates(p, n)
}

// nodeAffinityAdmits evaluates requiredDuringSchedulingIgnoredDuringExecution only.
//
// PREFERRED affinity is deliberately ignored: it is a scoring input, not a filter, so treating it as one would
// make the model STRICTER than the scheduler — and a stricter model breaks the soundness argument in the one
// direction that matters. NodeSelectorTerms are OR'd, matchExpressions within a term are AND'd, which is
// Kubernetes' own semantics.
func nodeAffinityAdmits(p corev1.Pod, n *corev1.Node) bool {
	aff := p.Spec.Affinity
	if aff == nil || aff.NodeAffinity == nil || aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return true
	}
	terms := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 {
		return true
	}
	for _, term := range terms {
		if termMatchesNode(term, n) {
			return true
		}
	}
	return false
}

func termMatchesNode(term corev1.NodeSelectorTerm, n *corev1.Node) bool {
	for _, e := range term.MatchExpressions {
		if !exprMatchesLabels(e, n.Labels) {
			return false
		}
	}
	for _, f := range term.MatchFields {
		// metadata.name is the only field selector the scheduler supports here. An unrecognised field is
		// treated as ADMITTING, so the model stays permissive rather than inventing a refusal.
		if f.Key != "metadata.name" {
			continue
		}
		if !exprMatchesLabels(corev1.NodeSelectorRequirement{
			Key: f.Key, Operator: f.Operator, Values: f.Values,
		}, map[string]string{"metadata.name": n.Name}) {
			return false
		}
	}
	return true
}

func exprMatchesLabels(e corev1.NodeSelectorRequirement, labels map[string]string) bool {
	v, present := labels[e.Key]
	switch e.Operator {
	case corev1.NodeSelectorOpIn:
		return present && containsString(e.Values, v)
	case corev1.NodeSelectorOpNotIn:
		return !present || !containsString(e.Values, v)
	case corev1.NodeSelectorOpExists:
		return present
	case corev1.NodeSelectorOpDoesNotExist:
		return !present
	}
	// Gt and Lt exist and are numeric. Unhandled operators ADMIT rather than refuse: the model must stay
	// more permissive than the scheduler, and an unparsed comparison is not evidence of a refusal.
	return true
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// tolerates checks NoSchedule and NoExecute taints only.
//
// PreferNoSchedule is a scoring input, not a filter, so it is not checked — for the same reason preferred
// affinity is not.
func tolerates(p corev1.Pod, n *corev1.Node) bool {
	for _, t := range n.Spec.Taints {
		if t.Effect != corev1.TaintEffectNoSchedule && t.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		if !tolerationFor(p.Spec.Tolerations, t) {
			return false
		}
	}
	return true
}

func tolerationFor(tols []corev1.Toleration, t corev1.Taint) bool {
	for _, tol := range tols {
		if tol.Effect != "" && tol.Effect != t.Effect {
			continue
		}
		switch tol.Operator {
		case corev1.TolerationOpExists:
			if tol.Key == "" || tol.Key == t.Key {
				return true
			}
		case corev1.TolerationOpEqual, "":
			if tol.Key == t.Key && tol.Value == t.Value {
				return true
			}
		}
	}
	return false
}

// ── the scenarios ────────────────────────────────────────────────────────────────────────────────

// displaced is one pod the model could not place, with why.
type displaced struct {
	pod corev1.Pod
	// immobileBy names the PV that pins the pod, or "" when the pod is merely unplaceable. A pinned pod is
	// the strongest statement in the feature: it cannot move at all, and that is arithmetic over the
	// operator's own object rather than a scheduler model.
	immobileBy string
	// structural marks a refusal caused by a DECLARATION — a nodeSelector, a required node affinity, a taint,
	// or a volume pin — rather than by how full the surviving nodes happen to be right now.
	//
	// THE DISTINCTION IS WHY THE NODE-LOSS RULE IS USABLE. Capacity is transient and repackable: it changes
	// with every deploy, and "the cluster is full" is node_headroom's finding from the other side. Reporting
	// it per node made this rule fire on TEN of the persona's twelve nodes — which is not a problem being
	// reported, it is a cluster being described. A declaration is durable and names its own cause.
	structural bool
}

// scenario is a hypothetical loss: a set of nodes removed, and everything that ran on them.
type scenario struct {
	// kind is "zone" or "node", label is which one.
	kind, label string
	// removed are the node names that would be gone.
	removed map[string]bool
}

// placementModel is one inventory as the scenarios read it, built once per evaluation and shared by every
// scenario in it.
//
// BUILT ONCE, NOT PER SCENARIO. Every scenario used to recompute each surviving node's free room by walking every
// pod in the cluster, and the node-loss rule runs one scenario per node — nodes × nodes × pods. On a 2,000-node,
// 34,000-pod cluster that is 1.4×10¹¹ request sums, and a reading of it did not finish in ten minutes. A surviving
// node's room depends only on the pods bound to THAT node, which no scenario moves — the model never repacks — so
// it is the same in every scenario, and is computed once here in the same order as before.
//
// READ-ONLY AFTER CONSTRUCTION. A candidate's quantities can share their decimal backing with every copy of the
// candidate, so a scenario that subtracted from one would change the room every later scenario reads.
type placementModel struct {
	inv *collect.Inventory
	// cands is every node in inventory order, with its free room. A scenario skips the ones it removes.
	cands []candidate
	// podsOn is the indices into inv.Pods bound to each node name, ascending — including names absent from the
	// node list, since a scenario's removed set can name one.
	podsOn map[string][]int
	// volumes is each claim's bound PersistentVolumes that carry a required nodeAffinity, keyed namespace/claim.
	volumes map[string][]*corev1.PersistentVolume
	// all is every index into cands; byLabel is the indices of the nodes carrying each label key and value, and
	// byName the indices of each node name, all ascending. See candidatesFor and nodesFor.
	all     []int
	byLabel map[string]map[string][]int
	byName  map[string][]int
}

func newPlacementModel(inv *collect.Inventory) *placementModel {
	m := &placementModel{inv: inv, podsOn: map[string][]int{}, byLabel: map[string]map[string][]int{},
		byName: map[string][]int{}}
	byName := m.byName
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		m.all = append(m.all, i)
		for k, v := range n.Labels {
			if m.byLabel[k] == nil {
				m.byLabel[k] = map[string][]int{}
			}
			m.byLabel[k][v] = append(m.byLabel[k][v], i)
		}
		m.cands = append(m.cands, candidate{node: n,
			freeCPU: n.Status.Allocatable[corev1.ResourceCPU].DeepCopy(),
			freeMem: n.Status.Allocatable[corev1.ResourceMemory].DeepCopy()})
		byName[n.Name] = append(byName[n.Name], i)
	}
	for j := range inv.Pods {
		name := inv.Pods[j].Spec.NodeName
		m.podsOn[name] = append(m.podsOn[name], j)
		if len(byName[name]) == 0 || !holdsRoom(inv.Pods[j]) {
			continue
		}
		cpu, mem := feasibilityRequests(inv.Pods[j])
		ports := hostPortsOf(inv.Pods[j])
		for _, i := range byName[name] {
			m.cands[i].freeCPU.Sub(cpu)
			m.cands[i].freeMem.Sub(mem)
			for _, k := range ports {
				if m.cands[i].ports == nil {
					m.cands[i].ports = map[hostPortKey]bool{}
				}
				m.cands[i].ports[k] = true
			}
		}
	}
	m.volumes = boundVolumes(inv)
	return m
}

// boundVolumes maps each claim, namespace/name, to the PersistentVolume bound to it when that volume carries a
// required nodeAffinity with at least one term. An unbound claim, or a volume that constrains nothing, is left
// out: there is no claim to make about it.
func boundVolumes(inv *collect.Inventory) map[string][]*corev1.PersistentVolume {
	pvByName := map[string]*corev1.PersistentVolume{}
	for i := range inv.PVs {
		pvByName[inv.PVs[i].Name] = &inv.PVs[i]
	}
	out := map[string][]*corev1.PersistentVolume{}
	for i := range inv.PVCs {
		pvc := &inv.PVCs[i]
		if pvc.Spec.VolumeName == "" {
			continue
		}
		pv := pvByName[pvc.Spec.VolumeName]
		if pv == nil || pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil ||
			len(pv.Spec.NodeAffinity.Required.NodeSelectorTerms) == 0 {
			continue
		}
		key := pvc.Namespace + "/" + pvc.Name
		out[key] = append(out[key], pv)
	}
	return out
}

// volumesOf is the constraining volumes p mounts through its claims.
func (m *placementModel) volumesOf(p corev1.Pod) []*corev1.PersistentVolume {
	var out []*corev1.PersistentVolume
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			out = append(out, m.volumes[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName]...)
		}
	}
	return out
}

// pvAdmits is the scheduler's VolumeBinding filter for one bound volume: whether the node's labels satisfy the
// volume's required nodeAffinity. Terms are OR'd and expressions within a term AND'd, through the same
// termMatchesNode the pod's own affinity uses.
//
// WHATEVER THE KEY. A zone written by a CSI driver in its own key (topology.disk.csi.azure.com/zone and the like)
// is matched against the label the driver's node plugin puts on each node, exactly as the scheduler matches it.
// Recognising pins by key name was how a driver-provisioned disk came to read as no pin at all.
func pvAdmits(pv *corev1.PersistentVolume, n *corev1.Node) bool {
	if pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
		return true
	}
	terms := pv.Spec.NodeAffinity.Required.NodeSelectorTerms
	if len(terms) == 0 {
		return true
	}
	for _, term := range terms {
		if termMatchesNode(term, n) {
			return true
		}
	}
	return false
}

// volumesAdmit reports whether every volume the pod mounts admits the node.
func volumesAdmit(pvs []*corev1.PersistentVolume, n *corev1.Node) bool {
	for _, pv := range pvs {
		if !pvAdmits(pv, n) {
			return false
		}
	}
	return true
}

// nodesFor is a superset of the nodes one term can match, read from the indexes: the nodes carrying a value its
// first In expression names, or the nodes its metadata.name field names, or every node. termMatchesNode then
// decides; this only keeps a hostname-pinned volume from being checked against all 2,000 nodes.
func (m *placementModel) nodesFor(term corev1.NodeSelectorTerm) []int {
	for _, e := range term.MatchExpressions {
		if e.Operator == corev1.NodeSelectorOpIn {
			var out []int
			for _, v := range e.Values {
				out = append(out, m.byLabel[e.Key][v]...)
			}
			return out
		}
	}
	for _, f := range term.MatchFields {
		if f.Key == "metadata.name" && f.Operator == corev1.NodeSelectorOpIn {
			var out []int
			for _, v := range f.Values {
				out = append(out, m.byName[v]...)
			}
			return out
		}
	}
	return m.all
}

// survivorAdmits reports whether a node the scenario leaves satisfies the volume's required nodeAffinity.
func (m *placementModel) survivorAdmits(pv *corev1.PersistentVolume, removed map[string]bool) bool {
	for _, term := range pv.Spec.NodeAffinity.Required.NodeSelectorTerms {
		for _, i := range m.nodesFor(term) {
			n := m.cands[i].node
			if !removed[n.Name] && termMatchesNode(term, n) {
				return true
			}
		}
	}
	return false
}

// candidatesFor is the nodes that could admit p as far as its nodeSelector says: those carrying every key and
// value it names — the shortest of their lists, since admits checks the rest — or every node for a pod with none.
//
// WHY. A pod the model places nowhere is checked against every surviving node, since only then is "every node
// refuses it on a declaration" known; with a pool retired under one workload in twenty, that was each of its
// pods against all 2,000 nodes in every scenario its node was lost. A node without a selected label refuses the
// pod at admits' first check, so leaving it out changes neither answer — whether the pod fits somewhere, and
// whether every refusal was a declaration — and the order the nodes are asked in changes neither either.
func (m *placementModel) candidatesFor(p corev1.Pod) []int {
	if len(p.Spec.NodeSelector) == 0 {
		return m.all
	}
	var best []int
	first := true
	for k, v := range p.Spec.NodeSelector {
		l := m.byLabel[k][v]
		if first || len(l) < len(best) {
			best, first = l, false
		}
	}
	return best
}

// assess runs one scenario and returns the pods with nowhere modelled to go, plus the excluded count.
//
// EXCLUSIONS ARE COUNTED, NOT SILENT. A pod bound to a custom scheduler is not ours to model, and a reader who
// is not told that concludes the check covered everything.
func assess(m *placementModel, sc scenario, opts Options) (out []displaced, excludedScheduler int) {
	for _, p := range m.leaving(sc, opts, &excludedScheduler) {
		pvs := m.volumesOf(p)
		// IMMOBILITY FIRST, because it is the stronger statement and it does not depend on the model at all.
		if pv := m.pinsIntoLoss(pvs, sc); pv != "" {
			out = append(out, displaced{pod: p, immobileBy: pv})
			continue
		}
		cpu, mem := feasibilityRequests(p)
		ports := hostPortsOf(p)
		placeable, structural := false, true
		// THE SURVIVORS IN PLACE, not a copy of them per scenario: copying every surviving node for each lost
		// one was nodes² candidate copies, the one part of this model that still grew with the square of the
		// cluster (4,000 nodes: 16 million).
		for _, i := range m.candidatesFor(p) {
			c := m.cands[i]
			if sc.removed[c.node.Name] {
				continue
			}
			// A NODE ITS VOLUME REFUSES IS REFUSED ON A DECLARATION. A pod with a zonal disk was placed on a node
			// in the other zone whenever the nodes left in its own zone refused it, which the scheduler never does.
			if !volumesAdmit(pvs, c.node) {
				continue
			}
			// A HOST PORT HELD THERE IS A DECLARATION ON BOTH SIDES: the pod asks for the port and a pod that stays
			// on the node holds it. An ingress controller with one replica per worker had somewhere to go when a
			// worker was drained, and sat Pending on "didn't have free ports for the requested pod ports".
			if !portsFree(c.ports, ports) {
				continue
			}
			if fits(c, p, cpu, mem) {
				placeable = true
				break
			}
			// If ANY surviving candidate refuses this pod only on capacity, the refusal is not structural: a
			// deploy tomorrow, or a pod finishing, changes the answer. Only when every candidate refuses on a
			// DECLARATION is the statement durable.
			if admits(c, p) {
				structural = false
			}
		}
		if !placeable {
			out = append(out, displaced{pod: p, structural: structural})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].pod.Namespace != out[j].pod.Namespace {
			return out[i].pod.Namespace < out[j].pod.Namespace
		}
		return out[i].pod.Name < out[j].pod.Name
	})
	return out, excludedScheduler
}

// survivors are the nodes a scenario leaves, each with what is actually free on it. NOT a repack: the pods that
// are not displaced stay where they are, and asking whether a displaced pod fits somewhere is a question about
// the room that is left.
func (m *placementModel) survivors(sc scenario) []candidate {
	cands := make([]candidate, 0, len(m.cands))
	for _, c := range m.cands {
		if !sc.removed[c.node.Name] {
			cands = append(cands, c)
		}
	}
	return cands
}

// leaving is the work a scenario displaces: the pods on the removed nodes that would need a home, with the ones
// that are not this model's to place left out — and the custom-scheduler ones counted into excluded.
//
// IN INVENTORY ORDER, read from the per-node index rather than from a walk of every pod: a scenario that removes one
// node reads that node's pods.
func (m *placementModel) leaving(sc scenario, opts Options, excludedScheduler *int) []corev1.Pod {
	var idx []int
	for name := range sc.removed {
		idx = append(idx, m.podsOn[name]...)
	}
	sort.Ints(idx)
	var out []corev1.Pod
	for _, i := range idx {
		p := m.inv.Pods[i]
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue // a Succeeded or Failed pod is not work that needs a home
		}
		// A DAEMONSET POD IS NOT DISPLACED WORK. Since Kubernetes 1.12 the DaemonSet controller schedules its
		// pods by writing a required nodeAffinity of `metadata.name In [thatNode]` onto each one, so the
		// predicate model reads it faithfully and concludes — correctly — that no other node satisfies it. And
		// then reports a pod that was never going to move as a pod with nowhere to go.
		//
		// A DaemonSet pod is not rescheduled when its node goes away; the DaemonSet simply has one fewer node
		// to cover. buildDrainPlacement had already learned this and skips them for the same reason.
		//
		// FOUND BY THE INDEPENDENT RECOUNT ON THE KIND TESTBED, not by a test: the recount said zero pods had
		// nowhere to go and this rule said six findings, every one of them kindnet, kube-proxy or
		// node-exporter. It would have fired on every cluster in existence, because every cluster runs
		// DaemonSets — and it would have been this epic's headline finding, wrong.
		if isDaemonSetPod(p) {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Spec.SchedulerName != "" && p.Spec.SchedulerName != "default-scheduler" {
			*excludedScheduler++
			continue
		}
		out = append(out, p)
	}
	return out
}

// pinsIntoLoss names the volume that makes a pod immobile under the scenario — one whose required nodeAffinity no
// node the scenario leaves satisfies — or "".
//
// ONE TEST FOR EVERY PIN. A hostname pin is immobilising when its node is removed, a zone pin when every node of
// its zone is (losing one node of a three-node zone leaves the pod two homes, and saying otherwise would be the
// claim this file's header refuses), and a pin in a key this file has never heard of when no node left carries
// it. All three are the same question asked of the survivors, and asking it that way is what reads a CSI driver's
// zone key.
func (m *placementModel) pinsIntoLoss(pvs []*corev1.PersistentVolume, sc scenario) string {
	for _, pv := range pvs {
		if !m.survivorAdmits(pv, sc.removed) {
			return pv.Name
		}
	}
	return ""
}

// pvPinIndex maps a PVC key to the zone each of its PVs pins it to, for ZonePinnedVolume: a WEAKER statement than
// a node pin — a zonal disk constrains where a pod may go without naming where it is.
func pvPinIndex(inv *collect.Inventory) (zones map[string]map[string]string) {
	zones = map[string]map[string]string{}

	pvByName := map[string]*corev1.PersistentVolume{}
	for i := range inv.PVs {
		pvByName[inv.PVs[i].Name] = &inv.PVs[i]
	}
	for i := range inv.PVCs {
		pvc := &inv.PVCs[i]
		if pvc.Spec.VolumeName == "" {
			continue // unbound: no claim to make
		}
		pv := pvByName[pvc.Spec.VolumeName]
		if pv == nil || pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
			continue
		}
		key := pvc.Namespace + "/" + pvc.Name
		if z := pvZone(pv); z != "" {
			if zones[key] == nil {
				zones[key] = map[string]string{}
			}
			zones[key][pv.Name] = z
		}
	}
	return zones
}

// pvZone returns the single zone a PV's required nodeAffinity pins to, or "".
//
// ONE ZONE ONLY. A term listing three zones is a constraint the pod can satisfy in any of them, which is not
// immobility — and a PV with several NodeSelectorTerms is an OR, so it is not immobility either. Returning ""
// for both is the permissive direction, which is the one that keeps the negative sound.
//
// Reads the GA key, the beta one and the zone keys CSI drivers write (collect.IsVolumeZoneKey): a disk an Azure,
// EBS or Compute Engine driver provisioned is exactly as zonal as one labelled with the GA key.
func pvZone(pv *corev1.PersistentVolume) string {
	terms := pv.Spec.NodeAffinity.Required.NodeSelectorTerms
	if len(terms) != 1 {
		return ""
	}
	var found string
	for _, e := range terms[0].MatchExpressions {
		if !collect.IsVolumeZoneKey(e.Key) || e.Operator != corev1.NodeSelectorOpIn {
			continue
		}
		if len(e.Values) != 1 {
			return "" // several zones is a choice, not a pin
		}
		if found != "" && found != e.Values[0] {
			return "" // contradictory: not our business to resolve
		}
		found = e.Values[0]
	}
	return found
}

// ── Rule: zone loss ──────────────────────────────────────────────────────────────────────────────

// ZoneLossFeasibility reports, per availability zone, the pods that would have no remaining node satisfying
// the modelled constraints if that zone were gone.
type ZoneLossFeasibility struct{}

func (ZoneLossFeasibility) ID() string { return "k8s.reliability.zone-loss-feasibility" }

// 1.1.0 (2026-10-21): a finished pod's requests no longer occupy a candidate node (holdsRoom).
// 1.2.0 (2026-10-27): a bound volume's nodeAffinity is evaluated against each node's labels, whatever its key
// (pvAdmits), both for immobility and for every candidate.
// 1.3.0 (2026-10-28): a host port held on a candidate refuses a pod that asks for it (portsFree).
func (ZoneLossFeasibility) Version() string { return "1.3.0" }

// RequiredKinds gates the COMPARISON, not the run. All four are load-bearing: nodes and pods are what the
// scenario is built from, and the volume pair is what the strongest claim in the family rests on — a reading
// without PVs would report a pinned pod as merely unplaceable, which is a weaker and different statement.
func (ZoneLossFeasibility) RequiredKinds() []string {
	return []string{"nodes", "persistentvolumeclaims", "persistentvolumes", "pods"}
}

func (r ZoneLossFeasibility) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !drainInputsOK(inv) {
		return nil
	}
	// NOTHING TO ABSTAIN ABOUT. An abstention saying "no node carries a zone label" is true and useless on a
	// cluster with no nodes, and equally useless with no pods to displace — caught by
	// TestRun_FakeClientsetProducesValidReport, which asserts an empty cluster yields zero findings, and it
	// is right to: a disclosure about a scenario that cannot exist is noise, and noise is what teaches a
	// reader to skip disclosures that matter.
	if len(inv.Nodes) == 0 || len(inv.Pods) == 0 {
		return nil
	}

	// THE HARD PRECONDITION, not a caveat. A cluster whose nodes carry no zone label would resolve to ONE
	// zone containing everything, and losing it would read as the entire cluster having nowhere to go. Zero
	// findings with a NAMED REASON — never zero findings in silence.
	byZone := map[string][]string{}
	for i := range inv.Nodes {
		if z := collect.ZoneOf(inv.Nodes[i]); z != "" {
			byZone[z] = append(byZone[z], inv.Nodes[i].Name)
		}
	}
	if len(byZone) == 0 {
		return []types.Finding{r.unzonedAbstention(inv)}
	}
	if len(byZone) == 1 {
		// A genuinely single-zone cluster. Losing its only zone is losing the cluster, which is a true
		// statement and a useless one — every pod would be listed, and the finding would be about the shape
		// of the cluster rather than about anything an operator can act on.
		return []types.Finding{r.singleZoneAbstention(inv, byZone)}
	}

	zones := make([]string, 0, len(byZone))
	for z := range byZone {
		zones = append(zones, z)
	}
	sort.Strings(zones)

	m := newPlacementModel(inv)
	var out []types.Finding
	for _, z := range zones {
		removed := map[string]bool{}
		for _, n := range byZone[z] {
			removed[n] = true
		}
		lost, excluded := assess(m, scenario{kind: "zone", label: z, removed: removed}, opts)
		if len(lost) == 0 && excluded == 0 {
			continue
		}
		if len(lost) == 0 {
			continue // nothing to report; the exclusion count rides on a finding, never alone
		}
		out = append(out, r.finding(inv, z, byZone[z], lost, excluded, len(inv.Nodes)))
	}
	return out
}

func (r ZoneLossFeasibility) finding(inv *collect.Inventory, zone string, zoneNodes []string,
	lost []displaced, excluded, totalNodes int) types.Finding {

	immobile := 0
	for _, d := range lost {
		if d.immobileBy != "" {
			immobile++
		}
	}

	ev := []string{
		snapshotNote(inv),
		fmt.Sprintf("zone %s holds %d of this reading's %s: %s",
			zone, len(zoneNodes), nWord(totalNodes, "node", "nodes"), strings.Join(sortedCopy(zoneNodes), ", ")),
	}
	ev = append(ev, displacedEvidence(lost)...)
	if immobile > 0 {
		ev = append(ev, fmt.Sprintf("%d of them hold a PersistentVolume whose own nodeAffinity names this zone, "+
			"so they could not move within the reading at all — that is arithmetic over the volume object, not "+
			"a model of the scheduler", immobile))
	}
	if excluded > 0 {
		ev = append(ev, fmt.Sprintf("%s in this zone bound to a custom scheduler (spec.schedulerName) "+
			"and not assessed: placement there is decided by code this reading cannot see",
			nWord(excluded, "pod is", "pods are")))
	}
	ev = append(ev, "modelled here: "+strings.Join(modelledPredicates, "; "))
	ev = append(ev, "not modelled: "+strings.Join(unmodelledPredicates, "; "))

	return types.Finding{
		ID:              findingID(r.ID(), "Zone", "", zone),
		IDBasis:         &types.ResourceRef{Kind: "Zone", Namespace: "", Name: zone},
		ClaimBoundaries: zoneLabelBoundaries(inv),
		RuleID:          r.ID(),
		RuleVersion:     r.Version(),
		Title: fmt.Sprintf("Losing zone %s leaves %s with no node this model accepts",
			zone, nWord(len(lost), "pod", "pods")),
		Description: fmt.Sprintf("If every node in zone %s were unavailable, %s running there would have "+
			"no remaining node in this reading that satisfies the constraints this model checks. The model checks "+
			"a subset of what the Kubernetes scheduler checks, which is why it can report that nothing satisfies "+
			"it and cannot report the opposite: preemption could free room the model does not see, and an "+
			"autoscaler could add nodes this reading does not contain.",
			zone, nWord(len(lost), "pod", "pods")),
		WhyItMatters: "A zone becoming unavailable is a routine cloud event, and the pods listed here are the ones " +
			"whose declared constraints leave them nothing to fall back to in the node set as it stands. The " +
			"pinned ones are the sharper case: a volume that names a zone cannot follow its pod out of it.",
		Evidence:          ev,
		Severity:          types.SeverityHigh,
		Category:          types.CategoryReliability,
		AffectedResources: displacedRefs(lost),
		EstimatedEffort:   types.EffortHigh,
		// 1.0 for the immobility half and for the arithmetic; the model's partiality is a claim boundary
		// published in the finding, not an uncertainty about what was observed.
		Confidence: 1.0,
		Provenance: provenance(),
	}
}

func (r ZoneLossFeasibility) unzonedAbstention(inv *collect.Inventory) types.Finding {
	return types.Finding{
		ID:          findingID(r.ID(), "Cluster", "", "unzoned"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "unzoned"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       "Zone-loss feasibility not assessed — no node carries a zone label",
		Description: "No node in this reading carries topology.kubernetes.io/zone or the older " +
			"failure-domain.beta.kubernetes.io/zone, so this audit cannot tell which nodes share a failure " +
			"domain. Treating an unlabelled cluster as one zone would mean reporting that losing it leaves every " +
			"pod with nowhere to go, which would be a statement about the missing labels rather than about the " +
			"cluster. Label the nodes with their zone and re-run to assess this.",
		WhyItMatters: "Zone-loss reasoning rests entirely on the zone label. Without it there is no failure " +
			"domain to reason about, and inventing one would produce a finding about every pod at once.",
		Evidence: []string{
			snapshotNote(inv),
			fmt.Sprintf("%s read, none carrying either zone label", nWord(len(inv.Nodes), "node", "nodes")),
		},
		Severity:          types.SeverityInfo,
		Category:          types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "Cluster"}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        0.0,
		Provenance:        provenance(),
	}
}

func (r ZoneLossFeasibility) singleZoneAbstention(inv *collect.Inventory, byZone map[string][]string) types.Finding {
	var zone string
	for z := range byZone {
		zone = z
	}
	return types.Finding{
		ID:          findingID(r.ID(), "Cluster", "", "single-zone"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "single-zone"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       "Zone-loss feasibility not assessed — every node is in one zone",
		Description: fmt.Sprintf("Every node in this reading is in zone %s, so the only zone-loss scenario is "+
			"losing the whole cluster. Listing every pod as having nowhere to go would be a statement about the "+
			"cluster having one zone, which the architecture section already shows, rather than about any "+
			"individual workload.", zone),
		WhyItMatters: "A single-zone cluster has no zone to fall back to by construction. That is a topology " +
			"decision rather than a per-workload finding.",
		Evidence: []string{
			snapshotNote(inv),
			map[bool]string{true: "the one node is in zone " + zone,
				false: fmt.Sprintf("all %d nodes are in zone %s", len(byZone[zone]), zone)}[len(byZone[zone]) == 1],
		},
		Severity:          types.SeverityInfo,
		Category:          types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "Cluster"}},
		EstimatedEffort:   types.EffortLow,
		Confidence:        0.0,
		Provenance:        provenance(),
	}
}

// ── Rule: node loss ──────────────────────────────────────────────────────────────────────────────

// NodeLossFeasibility asks the same question one node at a time.
//
// DISTINCT FROM NodeDrainBudget, which asks whether the EVICTION API would let the pods leave. This asks
// whether, once they have left, the remaining node set contains anywhere the model accepts. A budget that
// permits an eviction and a cluster with nowhere to put the pod are different problems with the same symptom.
type NodeLossFeasibility struct{}

func (NodeLossFeasibility) ID() string { return "k8s.reliability.node-loss-feasibility" }

// 1.1.0 (2026-10-21): a finished pod's requests no longer occupy a candidate node (holdsRoom).
// 1.2.0 (2026-10-27): a bound volume's nodeAffinity is evaluated against each node's labels, whatever its key
// (pvAdmits), both for immobility and for every candidate.
// 1.3.0 (2026-10-28): a host port held on a candidate refuses a pod that asks for it (portsFree).
func (NodeLossFeasibility) Version() string { return "1.3.0" }

func (NodeLossFeasibility) RequiredKinds() []string {
	return []string{"nodes", "persistentvolumeclaims", "persistentvolumes", "pods"}
}

func (r NodeLossFeasibility) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !drainInputsOK(inv) {
		return nil
	}
	// A one-node cluster has no scenario worth reporting: losing the node loses everything, which is not a
	// per-workload finding.
	if len(inv.Nodes) < 2 {
		return nil
	}

	names := make([]string, 0, len(inv.Nodes))
	for i := range inv.Nodes {
		names = append(names, inv.Nodes[i].Name)
	}
	sort.Strings(names)

	m := newPlacementModel(inv)
	var out []types.Finding
	for _, name := range names {
		lost, excluded := assess(m, scenario{kind: "node", label: name, removed: map[string]bool{name: true}}, opts)
		// STRUCTURAL ONLY, at node granularity. A pod that fits nowhere because the surviving nodes are full is
		// a capacity statement, and capacity is node_headroom's subject from the other side — reporting it once
		// per node made this rule fire on ten of twelve nodes on the persona, which describes a cluster rather
		// than reporting a problem. The count of capacity-only cases rides on a finding when there is one and
		// vanishes with it when there is not, because a finding whose only content is "the cluster is full"
		// belongs to the rule that owns that claim.
		var structural []displaced
		capacityOnly := 0
		for _, d := range lost {
			if d.immobileBy != "" || d.structural {
				structural = append(structural, d)
				continue
			}
			capacityOnly++
		}
		if len(structural) == 0 {
			continue
		}
		out = append(out, r.finding(inv, name, structural, excluded, capacityOnly))
	}
	return out
}

func (r NodeLossFeasibility) finding(inv *collect.Inventory, nodeName string, lost []displaced,
	excluded, capacityOnly int) types.Finding {

	ev := []string{snapshotNote(inv)}
	ev = append(ev, displacedEvidence(lost)...)
	if capacityOnly > 0 {
		ev = append(ev, fmt.Sprintf("a further %s on this node would find no room on the surviving nodes "+
			"as they are currently packed. That is a capacity observation rather than a constraint, it changes "+
			"with the next deploy, and this reading discusses aggregate slack in the cost section instead",
			nWord(capacityOnly, "pod", "pods")))
	}
	if excluded > 0 {
		ev = append(ev, fmt.Sprintf("%s on this node bound to a custom scheduler "+
			"(spec.schedulerName) and not assessed", nWord(excluded, "pod is", "pods are")))
	}
	ev = append(ev, "modelled here: "+strings.Join(modelledPredicates, "; "))
	ev = append(ev, "not modelled: "+strings.Join(unmodelledPredicates, "; "))

	return types.Finding{
		ID:          findingID(r.ID(), "Node", "", nodeName),
		IDBasis:     &types.ResourceRef{Kind: "Node", Namespace: "", Name: nodeName},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("Losing node %s leaves %s with no node this model accepts",
			nodeName, nWord(len(lost), "pod", "pods")),
		Description: fmt.Sprintf("If node %s were unavailable, %s running on it would have no remaining "+
			"node in this reading that satisfies the constraints this model checks. This is a different question "+
			"from whether a disruption budget would permit the eviction: a budget that allows a pod to leave "+
			"does not produce anywhere for it to arrive. The model checks a subset of the scheduler's "+
			"predicates, so it can report that nothing satisfies it and cannot report the opposite — preemption "+
			"could free room it does not see, and an autoscaler could add nodes this reading does not contain.",
			nodeName, nWord(len(lost), "pod", "pods")),
		WhyItMatters: "A node is lost routinely: a spot reclaim, a kernel panic, a node-pool upgrade. The pods " +
			"listed here are the ones whose declared constraints leave them nothing in the node set as it stands.",
		Evidence:          ev,
		Severity:          types.SeverityMedium,
		Category:          types.CategoryReliability,
		AffectedResources: displacedRefs(lost),
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}

// ── several nodes at once: the drain preflight's set question ─────────────────────────────────────

// NodeSetLoss answers the question `preflight drain A B …` asks: if every one of these nodes were drained
// TOGETHER, would the work leaving them have anywhere modelled to go?
//
// NOT THE UNION OF THE SINGLE-NODE ANSWERS, and that is the defect this exists to close. NodeLossFeasibility
// removes one node per scenario, and the drain preflight unioned those answers — so on a cluster of a tainted
// control plane and two workers, draining both workers was "nothing this model checks stops the drain": each
// worker alone can lean on the other, and together they leave every workload pod nothing but a node none of
// them tolerates. One scenario, the whole set removed, is the only honest model of the request.
//
// TWO NEGATIVES, both sound in the direction this model may speak (see the file's header):
//
//   - a pod for which no surviving node satisfies the modelled predicates, whether the refusal is a declaration
//     or capacity — for an explicit drain, "the room left is not enough" is the operator's question, not
//     node_headroom's;
//   - THE AGGREGATE. Each leaving pod fitting somewhere on its own does not mean they fit together: two pods of 3
//     CPU and one surviving node with 4 CPU free is room for one of them. If the total the leaving pods request
//     exceeds the total free on every surviving node that admits any of them, no packing finds room, whatever
//     order a scheduler tries. The reverse is not claimed — fitting in total says nothing about fitting in
//     pieces.
//
// A pod its OWN node's scenario already strands by a declaration or a volume pin is left to that node's finding:
// it is not stranded by the set, and naming it here would make every other node of the set look blocked by it.
//
// Nil for fewer than two nodes: a single node is NodeLossFeasibility's question, answered exactly as before.
func NodeSetLoss(inv *collect.Inventory, nodes []string, opts Options) []types.Finding {
	if len(nodes) < 2 || !drainInputsOK(inv) {
		return nil
	}
	names := sortedCopy(nodes)
	removed := map[string]bool{}
	for _, n := range names {
		removed[n] = true
	}
	sc := scenario{kind: "node", label: strings.Join(names, ", "), removed: removed}
	m := newPlacementModel(inv)
	lost, excluded := assess(m, sc, opts)

	// What each node's own scenario already strands by a declaration, by pod. Left to that node's finding.
	ownStrands := map[string]bool{}
	for _, n := range names {
		own, _ := assess(m, scenario{kind: "node", label: n, removed: map[string]bool{n: true}}, opts)
		for _, d := range own {
			if d.immobileBy != "" || d.structural {
				ownStrands[d.pod.Namespace+"/"+d.pod.Name] = true
			}
		}
	}
	var stranded []displaced
	lostKey := map[string]bool{}
	for _, d := range lost {
		k := d.pod.Namespace + "/" + d.pod.Name
		lostKey[k] = true
		if !ownStrands[k] {
			stranded = append(stranded, d)
		}
	}

	// THE AGGREGATE, over the pods that each found a home on their own.
	var ignore int
	var movers []corev1.Pod
	var askCPU, askMem resource.Quantity
	for _, p := range m.leaving(sc, opts, &ignore) {
		if lostKey[p.Namespace+"/"+p.Name] {
			continue
		}
		cpu, mem := feasibilityRequests(p)
		askCPU.Add(cpu)
		askMem.Add(mem)
		movers = append(movers, p)
	}
	var roomCPU, roomMem resource.Quantity
	for _, c := range m.survivors(sc) {
		admitsAny := false
		for _, p := range movers {
			if admits(c, p) && volumesAdmit(m.volumesOf(p), c.node) && portsFree(c.ports, hostPortsOf(p)) {
				admitsAny = true
				break
			}
		}
		if !admitsAny {
			continue
		}
		if c.freeCPU.Sign() > 0 {
			roomCPU.Add(c.freeCPU)
		}
		if c.freeMem.Sign() > 0 {
			roomMem.Add(c.freeMem)
		}
	}
	short := len(movers) > 0 && (askCPU.Cmp(roomCPU) > 0 || askMem.Cmp(roomMem) > 0)

	if len(stranded) == 0 && !short {
		return nil
	}
	return []types.Finding{nodeSetFinding(inv, names, stranded, movers, short, askCPU, askMem, roomCPU, roomMem, excluded)}
}

func nodeSetFinding(inv *collect.Inventory, names []string, stranded []displaced, movers []corev1.Pod, short bool,
	askCPU, askMem, roomCPU, roomMem resource.Quantity, excluded int) types.Finding {

	set := strings.Join(names, ", ")
	ev := []string{snapshotNote(inv)}
	ev = append(ev, displacedEvidence(stranded)...)
	var title, first string
	refs := displacedRefs(stranded)
	if len(stranded) > 0 {
		title = fmt.Sprintf("Draining %s together leaves %s with no node this model accepts",
			set, nWord(len(stranded), "pod", "pods"))
		first = fmt.Sprintf("If nodes %s were drained together, %s running on them would have no remaining node "+
			"in this reading that satisfies the constraints this model checks.", set, nWord(len(stranded), "pod", "pods"))
	}
	if short {
		line := fmt.Sprintf("the %s that each have a candidate node on their own request %s cpu and %s memory "+
			"in total, and the remaining nodes that accept any of them have %s cpu and %s memory free between them "+
			"— no order of placement makes the larger fit in the smaller",
			nWord(len(movers), "pod leaving these nodes", "pods leaving these nodes"),
			askCPU.String(), askMem.String(), roomCPU.String(), roomMem.String())
		ev = append(ev, line)
		for _, p := range movers {
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name})
		}
		if title == "" {
			title = fmt.Sprintf("Draining %s together asks for more room than the remaining nodes have free", set)
			first = fmt.Sprintf("If nodes %s were drained together, the %s leaving them would request more cpu or "+
				"memory in total than the remaining nodes have free.", set, nWord(len(movers), "pod", "pods"))
		}
	}
	if excluded > 0 {
		ev = append(ev, fmt.Sprintf("%s on these nodes bound to a custom scheduler "+
			"(spec.schedulerName) and not assessed", nWord(excluded, "pod is", "pods are")))
	}
	ev = append(ev, "modelled here: "+strings.Join(modelledPredicates, "; "))
	ev = append(ev, "not modelled: "+strings.Join(unmodelledPredicates, "; "))

	r := NodeLossFeasibility{}
	return types.Finding{
		ID:          findingID(r.ID(), "NodeSet", "", strings.Join(names, "+")),
		IDBasis:     &types.ResourceRef{Kind: "NodeSet", Name: strings.Join(names, "+")},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       title,
		Description: first + " Each node drained on its own is a different question, answered separately: what " +
			"stops this is the set. The model checks a subset of the scheduler's predicates, so it can report " +
			"that nothing satisfies it and cannot report the opposite — preemption could free room it does not " +
			"see, and an autoscaler could add nodes this reading does not contain.",
		WhyItMatters: "A drain of several nodes at once — a node-pool rotation, a maintenance window — takes their " +
			"room away together. Work that each node's neighbours could absorb one at a time can have nowhere to " +
			"go when the neighbours leave too.",
		Evidence:          ev,
		Severity:          types.SeverityMedium,
		Category:          types.CategoryReliability,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}

// ── Rule: a volume that pins a pod to a zone (Drain Preflight's fourth) ──────────────────────────

// ZonePinnedVolume reports pods whose PersistentVolume pins them to a ZONE rather than to a node.
//
// THE FOURTH DRAIN PREFLIGHT RULE, AND ITS CLAIM IS WEAKER THAN NodePinnedVolume's — deliberately, and the
// difference is the whole reason it is a separate rule rather than a widening of that one. A hostname-pinned
// volume names WHERE the pod is and so blocks a drain of that node. A ZONAL disk constrains where a pod MAY
// GO without naming where it is: a drain inside the zone is unaffected, because another node in the same zone
// satisfies the volume. What it blocks is leaving the zone.
type ZonePinnedVolume struct{}

func (ZonePinnedVolume) ID() string { return "k8s.reliability.zone-pinned-volume" }

// 1.1.0 (2026-10-27): reads the zone keys CSI drivers write, and counts the nodes the volume admits.
func (ZonePinnedVolume) Version() string { return "1.1.0" }

func (ZonePinnedVolume) RequiredKinds() []string {
	return []string{"nodes", "persistentvolumeclaims", "persistentvolumes", "pods"}
}

func (r ZonePinnedVolume) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !drainInputsOK(inv) || !observed(inv, "persistentvolumes") || !observed(inv, "persistentvolumeclaims") {
		return nil
	}
	zones := pvPinIndex(inv)
	if len(zones) == 0 {
		return nil
	}

	// THE NODES THE VOLUME ADMITS, not the nodes whose GA label names the zone. They are the same set when the
	// volume is pinned in the GA key; for a CSI driver's key they are the nodes its node plugin labelled, which
	// is the set the scheduler will consider.
	pinned := map[string]bool{}
	for _, byPV := range zones {
		for pvName := range byPV {
			pinned[pvName] = true
		}
	}
	admitted := map[string][]string{}
	for i := range inv.PVs {
		pv := &inv.PVs[i]
		if !pinned[pv.Name] {
			continue
		}
		for j := range inv.Nodes {
			if pvAdmits(pv, &inv.Nodes[j]) {
				admitted[pv.Name] = append(admitted[pv.Name], inv.Nodes[j].Name)
			}
		}
	}

	var out []types.Finding
	for i := range inv.Pods {
		p := inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			for pvName, zone := range zones[p.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] {
				out = append(out, r.finding(inv, p, pvName, zone, admitted[pvName]))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r ZonePinnedVolume) finding(inv *collect.Inventory, p corev1.Pod, pvName, zone string,
	zoneNodes []string) types.Finding {

	ev := []string{
		snapshotNote(inv),
		fmt.Sprintf("PersistentVolume %s declares a required nodeAffinity naming zone %s", pvName, zone),
		fmt.Sprintf("pod %s/%s mounts it and is running on %s", p.Namespace, p.Name, p.Spec.NodeName),
		fmt.Sprintf("zone %s holds %s in this reading: %s",
			zone, nWord(len(zoneNodes), "node", "nodes"), strings.Join(sortedCopy(zoneNodes), ", ")),
	}
	sev := types.SeverityMedium
	if len(zoneNodes) <= 1 {
		// One node in the zone means the zone pin reaches as far as a node pin does — and NodePinnedVolume
		// will not catch it, because the volume names a zone and not a hostname.
		sev = types.SeverityHigh
		ev = append(ev, "that zone holds one node in this reading, so the volume reaches no further than a "+
			"hostname pin would — and the hostname rule does not see it, because the volume names a zone")
	}

	return types.Finding{
		ID:          findingID(r.ID(), "Pod/"+pvName, p.Namespace, p.Name),
		IDBasis:     &types.ResourceRef{Kind: "Pod/" + pvName, Namespace: p.Namespace, Name: p.Name},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("A volume ties %s/%s to zone %s", p.Namespace, p.Name, zone),
		Description: fmt.Sprintf("PersistentVolume %s carries a required nodeAffinity naming zone %s, so the "+
			"pod that mounts it can only run on a node in that zone. This is weaker than a node-level pin and "+
			"the difference matters: draining a node WITHIN the zone is unaffected, because another node in the "+
			"same zone satisfies the volume. What the volume prevents is the pod leaving the zone at all.",
			pvName, zone),
		WhyItMatters: "A zonal disk is a real constraint written on the operator's own object, and it is the " +
			"reason a pod can survive a node going away and not a zone going away. Knowing which pods are held " +
			"in a zone is what makes a zone-loss plan possible.",
		Evidence:          ev,
		Severity:          sev,
		Category:          types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}},
		EstimatedEffort:   types.EffortHigh,
		Confidence:        1.0,
		Provenance:        provenance(),
	}
}

// ── shared rendering ─────────────────────────────────────────────────────────────────────────────

// maxListedPods caps the per-finding pod list. A cap is honest only when the finding says what it dropped.
const maxListedPods = 12

func displacedEvidence(lost []displaced) []string {
	var ev []string
	shown := lost
	if len(shown) > maxListedPods {
		shown = shown[:maxListedPods]
	}
	for _, d := range shown {
		if d.immobileBy != "" {
			ev = append(ev, fmt.Sprintf("%s/%s holds PersistentVolume %s, which names the lost failure domain — "+
				"it could not move at all", d.pod.Namespace, d.pod.Name, d.immobileBy))
			continue
		}
		cpu, mem := feasibilityRequests(d.pod)
		// NEVER THE ADDRESS. A port bound to one host address is said to be, and the address is not printed: it is a
		// node's IP, and redaction tokenises names, not addresses, so a redacted reading would carry it out.
		var ports []string
		for _, k := range hostPortsOf(d.pod) {
			s := fmt.Sprintf("%d/%s", k.port, k.protocol)
			if k.ip != everyAddress {
				s += " on one host address"
			}
			ports = append(ports, s)
		}
		asks := ""
		switch len(ports) {
		case 0:
		case 1:
			asks = " and host port " + ports[0]
		default:
			asks = " and host ports " + strings.Join(ports, ", ")
		}
		ev = append(ev, fmt.Sprintf("%s/%s requests %s cpu and %s memory%s; no surviving node in this reading "+
			"satisfies the modelled constraints", d.pod.Namespace, d.pod.Name, cpu.String(), mem.String(), asks))
	}
	if len(lost) > len(shown) {
		ev = append(ev, fmt.Sprintf("%s in the same position not listed here",
			nWord(len(lost)-len(shown), "further pod is", "further pods are")))
	}
	return ev
}

func displacedRefs(lost []displaced) []types.ResourceRef {
	refs := make([]types.ResourceRef, 0, len(lost))
	for _, d := range lost {
		refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: d.pod.Namespace, Name: d.pod.Name})
	}
	return refs
}

func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

// zoneLabelBoundaries is what THIS reading could not establish about failure domains.
//
// A cluster labelled only with the retired beta key is still readable — everything here uses the same GA-then-
// beta fallback — but the older key was never guaranteed to mean what the GA one means on every provider, and
// a reader drawing a blast-radius conclusion should know which key the reasoning rested on. That is a fact
// about one run and no static table can hold it.
func zoneLabelBoundaries(inv *collect.Inventory) []string {
	var ga, beta int
	for i := range inv.Nodes {
		if _, ok := inv.Nodes[i].Labels[collect.GAZoneLabel]; ok {
			ga++
			continue
		}
		if _, ok := inv.Nodes[i].Labels[collect.BetaZoneLabel]; ok {
			beta++
		}
	}
	if beta == 0 {
		return nil
	}
	if ga == 0 {
		return []string{"Every node in this reading carries only the retired " + collect.BetaZoneLabel +
			" label, so the failure domains here are the ones that key describes rather than the ones " +
			"topology.kubernetes.io/zone would."}
	}
	return []string{fmt.Sprintf("%d of the nodes in this reading carry only the retired %s label while %d "+
		"carry the current one, so the failure domains are assembled from two keys that a provider is not "+
		"required to keep in agreement.", beta, collect.GAZoneLabel, ga)}
}
