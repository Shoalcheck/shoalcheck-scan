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

// node label keys, matching what internal/collect's architecture builder reads.
const (
	labelInstanceType = "node.kubernetes.io/instance-type"
	labelAKSMode      = "kubernetes.azure.com/mode" // value "system" on AKS system/addon pools
)

// NodeHeadroom flags node pools (grouped by instance type) whose pods REQUEST
// far less than the pool's allocatable capacity — request-packing slack that
// *might* let whole nodes be drained. It is deliberately a CANDIDATE /
// "verify-first" signal, NOT a confident saving, because it sees only requests,
// never live usage:
//
//   - If pod requests are set below real usage (very common), the pool can be
//     request-packed onto fewer nodes that then OOM/evict at runtime; the
//     cluster-autoscaler gates on the same requests, so lowering minCount drains
//     straight into that OOM. Requests-only "removable nodes" is therefore NOT a
//     safe basis for node removal, and this rule never bills it as realisable
//     savings — DollarImpactMonthly stays 0 and the would-be figure is shown only
//     as an explicitly UNVERIFIED upper bound.
//   - Realisable node-removal savings require actual utilisation: connect
//     Prometheus (--prometheus-url); the usage-based Rightsizing rule then sizes
//     requests to real p95 usage, the safe path to reclaiming capacity.
//
// Three honesty guards keep the count from over-claiming reclaimable nodes:
//   - DaemonSet-owned pods are EXCLUDED from the request sum — their footprint
//     re-spawns per node and never consolidates, so counting it as "unused"
//     would inflate the slack on agent-heavy pools.
//   - The slack figure is framed as an AGGREGATE CEILING (total-unused ÷
//     per-node), not a drainable count: it assumes free repacking and does NOT
//     model PDBs, anti-affinity, topologySpread, or bin-packing fragmentation.
//   - A provider-neutral HA floor never proposes draining below TWO nodes
//     (removable capped at nodeCount-2), and every finding carries an HA caveat;
//     AKS system pools (kubernetes.azure.com/mode=system) get an extra note.
//
// The rule also skips entirely when pods were not collected (RBAC-denied /
// timed out), since a missing request side would fabricate phantom headroom.
type NodeHeadroom struct{}

func (NodeHeadroom) ID() string { return "k8s.cost.node-headroom" }

// 1.1.0 (2026-10-21): a finished pod's requests no longer count as reserved (holdsRoom).
func (NodeHeadroom) Version() string { return "1.1.0" }

// pool aggregates the nodes of one instance type + capacity type and their
// request load. Keying on capacity (not instance-type alone) keeps this seam's
// grouping identical to the collect seam's, so cluster spend and per-finding
// savings can never disagree on whether a pool is spot.
type pool struct {
	instanceType string
	capacity     types.CapacityType
	region       string // first region label seen in the pool
	nodeNames    []string
	allocCPU     resource.Quantity // summed allocatable across the pool
	allocMem     resource.Quantity
	reqCPU       resource.Quantity // summed container requests scheduled here (DaemonSet pods EXCLUDED)
	reqMem       resource.Quantity
	isSystem     bool // hosts control-plane addons (AKS system pool) — HA floor applies
	hasDaemonSet bool // at least one DaemonSet pod runs here — its footprint never consolidates
}

// poolKey is the (instance-type, capacity) grouping key shared in spirit with
// the collect seam — a mixed on-demand/spot pool of the same type splits.
type poolKey struct {
	itype    string
	capacity types.CapacityType
}

func (r NodeHeadroom) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	provider := providerFromNodes(inv.Nodes) // one cloud per cluster
	pools := map[poolKey]*pool{}
	nodeToKey := map[string]poolKey{} // nodeName → pool key, to bucket pods

	// DENIAL GUARD: the whole rule reasons about summed pod REQUESTS vs
	// allocatable. If pods were never collected (RBAC-denied / timed out), the
	// request side reads as ~0, which would fabricate "the pool is almost
	// entirely idle" headroom out of a collection gap. Skip the rule entirely
	// rather than emit phantom slack. (Meta.Collected uses the lowercase kind
	// token "pods", set in internal/collect/collect.go.)
	if !nhMetaCollected(inv, "pods") {
		return nil
	}

	for i := range inv.Nodes {
		n := inv.Nodes[i]
		itype := n.Labels[labelInstanceType] // "" groups untyped nodes together
		// SHARED classifier — identical to the collect seam (collect.ClassifyCapacityType)
		// so both seams classify the same node the same way (cross-seam parity).
		k := poolKey{itype: itype, capacity: collect.ClassifyCapacityType(provider, n)}
		nodeToKey[n.Name] = k
		p := pools[k]
		if p == nil {
			p = &pool{instanceType: itype, capacity: k.capacity, region: collect.RegionOf(n)}
			pools[k] = p
		}
		// THE SMALLEST REGION LABEL SEEN, NOT THE FIRST. This slot is hashed into the finding's id, and
		// "first" means whichever node the API server happened to return first — so a pool spanning two
		// regions got a different id between two readings of one cluster. Rare, and a real hole in the
		// id-stability claim; min() closes it without inventing a value the pool does not carry.
		if r := collect.RegionOf(n); r != "" && (p.region == "" || r < p.region) {
			p.region = r
		}
		p.nodeNames = append(p.nodeNames, n.Name)
		p.allocCPU.Add(*n.Status.Allocatable.Cpu())
		p.allocMem.Add(*n.Status.Allocatable.Memory())
		if n.Labels[labelAKSMode] == "system" {
			p.isSystem = true
		}
	}

	// Sum container requests onto the pool of the node each pod is bound to.
	// DaemonSet-owned pods are EXCLUDED from the consolidation math: their
	// requests do not repack onto fewer nodes — draining a node deletes that
	// node's replica and the survivors keep theirs, so the DaemonSet footprint
	// scales 1:1 with node count and frees nothing when a node is removed.
	// Counting them as "unused" capacity (the previous behaviour) overstated
	// reclaimable nodes on pools that are mostly DaemonSet overhead (CNI,
	// kube-proxy, log/metric agents, CSI node plugins). We still track whether a
	// pool carries any DaemonSet pods so the evidence can caveat honestly.
	for i := range inv.Pods {
		p := inv.Pods[i]
		k, ok := nodeToKey[p.Spec.NodeName]
		if !ok {
			continue // unscheduled pod or node we didn't collect
		}
		pl := pools[k]
		if pl == nil {
			continue
		}
		if isDaemonSetPod(p) {
			pl.hasDaemonSet = true
			continue // per-node footprint, not consolidatable — see comment above
		}
		// A pod that has Succeeded or Failed reserves nothing: the scheduler stopped counting it when it
		// terminated, though it stays bound until it is collected (holdsRoom, feasibility.go).
		if !holdsRoom(p) {
			continue
		}
		cpu, mem := podRequests(p)
		pl.reqCPU.Add(cpu)
		pl.reqMem.Add(mem)
	}

	// Deterministic finding order: by instance type, then capacity.
	keys := make([]poolKey, 0, len(pools))
	for k := range pools {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].itype != keys[j].itype {
			return keys[i].itype < keys[j].itype
		}
		return keys[i].capacity < keys[j].capacity
	})

	var out []types.Finding
	for _, k := range keys {
		p := pools[k]
		t := p.instanceType
		nodeCount := len(p.nodeNames)
		if nodeCount < 2 {
			continue // can't remove the only node in a pool
		}

		perNodeCPU := float64(p.allocCPU.MilliValue()) / float64(nodeCount)
		perNodeMem := float64(p.allocMem.Value()) / float64(nodeCount)
		if perNodeCPU == 0 || perNodeMem == 0 {
			continue // can't reason about a pool with no allocatable signal
		}

		unusedCPU := float64(p.allocCPU.MilliValue()) - float64(p.reqCPU.MilliValue())
		unusedMem := float64(p.allocMem.Value()) - float64(p.reqMem.Value())

		// Removable nodes = how many whole nodes' worth of capacity sits unused,
		// taken as the TIGHTER (min) of the CPU and memory dimensions — you
		// can only drain a node if both fit on the survivors.
		removableCPU := int(unusedCPU / perNodeCPU) // floor via int truncation
		removableMem := int(unusedMem / perNodeMem)
		removable := removableCPU
		if removableMem < removable {
			removable = removableMem
		}
		if removable < 1 {
			continue
		}
		// HA floor: never propose draining a multi-node pool below TWO nodes.
		// Leaving exactly one node is itself an availability anti-pattern — no
		// failure-domain redundancy and no rolling-update headroom for whatever
		// is scheduled here. So for any pool of 2+ nodes we cap the suggestion at
		// nodeCount-2 (a 2-node pool therefore yields no suggestion). This is a
		// provider-neutral floor: it protects EKS/GKE/self-managed DNS/ingress/
		// single-AZ tiers that carry no AKS system-pool label.
		if removable > nodeCount-2 {
			removable = nodeCount - 2
		}
		if removable < 1 {
			continue // 2-node pool, or slack that can't survive the HA floor
		}

		name := t
		if name == "" {
			name = "unknown"
		}
		// idName keeps the finding ID byte-identical to the pre-Layer-1 output for
		// the common no-label case (capacity unknown ⇒ no suffix). Only a
		// meaningful spot/on-demand split appends a discriminator so two pools of
		// the same type+region get distinct, stable IDs.
		idName := name
		if p.capacity == types.CapacitySpot || p.capacity == types.CapacityOnDemand {
			idName = name + "/" + string(p.capacity)
		}

		monthly, priceOK := opts.nodeMonthly(provider, p.region, t, p.capacity)
		evidence := []string{
			fmt.Sprintf("pool %s (%d nodes): summed pod REQUESTS %.1f CPU / %s (DaemonSet pods excluded) vs allocatable %.1f CPU / %s -> %s of aggregate request-slack",
				name, nodeCount,
				millicoresToCores(p.reqCPU), humanGi(p.reqMem),
				millicoresToCores(p.allocCPU), humanGi(p.allocMem), nWord(removable, "node", "nodes")),
			"REQUESTS-ONLY, not live usage: if pods request less CPU/memory than they actually consume, packing this pool onto fewer nodes will OOM/evict at runtime — and the cluster-autoscaler, which gates on the same requests, would drain straight into it. Do NOT remove nodes on this signal alone.",
			"AGGREGATE CEILING, not a drainable count: this number is total-unused-capacity divided by per-node-capacity — it assumes every remaining request can be freely repacked onto the survivors. It does NOT model per-node bin-packing fragmentation (many pods that each fit the slack but collectively don't), PodDisruptionBudgets that block the eviction draining requires, or pod anti-affinity / topologySpreadConstraints that pin one replica per node. Real reclaimable nodes are at most this many and often fewer; treat it as an upper limit to investigate.",
			"Verify before acting: connect Prometheus (--prometheus-url) so the usage-based Rightsizing rule sizes requests to real p95 usage — the safe path to reclaiming capacity.",
		}
		if p.hasDaemonSet {
			evidence = append(evidence,
				"This pool runs DaemonSet pods (e.g. CNI, kube-proxy, node-exporter, log/metric agents, CSI node plugins). Their requests are EXCLUDED from the slack above because a DaemonSet replica re-spawns on every node and cannot be drained away — its footprint scales 1:1 with node count and frees nothing when a node is removed.")
		}
		// The dollar figure is shown ONLY as an explicitly-unverified upper bound
		// and is NOT billed (DollarImpactMonthly stays 0): requests-only slack is
		// not realisable savings — see the rule doc. This is what keeps a
		// memory-bound pool (requests << real usage) from topping the savings
		// headline with a number that would cause an OOM outage if acted on.
		if priceOK {
			potential := float64(removable) * monthly
			line := fmt.Sprintf("UNVERIFIED upper bound, only if usage is at or below requests: region %s %s about $%.2f/node/mo × %d, about $%.2f/mo — NOT counted in savings until real usage confirms it.",
				p.region, t, monthly, removable, potential)
			if p.capacity == types.CapacitySpot {
				line += " (spot list price is itself an UPPER BOUND; real spot spend is lower and variable.)"
			}
			evidence = append(evidence, line)
		} else {
			evidence = append(evidence, fmt.Sprintf(
				"region/type %q/%q not in price table — no dollar figure.", p.region, t))
		}
		// Provider-neutral HA caveat on EVERY pool: the removable count is already
		// floored to leave ≥2 nodes, but a reader must still confirm what lives
		// here before reclaiming, because a pool's identity isn't visible from
		// requests alone. EKS/GKE/self-managed clusters carry no system-pool label.
		evidence = append(evidence,
			"HA floor: this suggestion already leaves at least 2 nodes (dropping below 2 removes failure-domain redundancy and rolling-update headroom). Before reclaiming, confirm this pool isn't the cluster's DNS/ingress tier or home to a single-AZ-pinned / single-replica critical workload — none of which is distinguishable from request data alone.")
		if p.isSystem {
			evidence = append(evidence,
				"SYSTEM/addon pool (kubernetes.azure.com/mode=system): keep at least 2 nodes for control-plane addon HA (CoreDNS, metrics-server, konnectivity) — never drain to 1 even if slack exists.")
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "NodePool", p.region, idName),
			IDBasis:     &types.ResourceRef{Kind: "NodePool", Namespace: p.region, Name: idName},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Node pool %s: up to %s of request-slack — verify usage before reclaiming", name, nWord(removable, "node", "nodes")),
			Description: fmt.Sprintf(
				"Node pool %s (%d × %s) shows %s of AGGREGATE slack between summed pod requests (DaemonSet pods excluded) and allocatable capacity. This is an upper-bound ceiling, not a drainable count: it is requests-only and is NOT a safe basis for removing nodes — pods that request less than they use will OOM when packed onto fewer nodes, the autoscaler gates on the same requests, and the figure assumes free repacking it never verifies (it does not model PDBs, anti-affinity/topology-spread, or bin-packing fragmentation). Treat it as a candidate to INVESTIGATE with real utilisation (connect Prometheus), not a realisable saving — the dollar impact here is 0 until usage confirms the headroom.",
				name, nodeCount, name, nWord(removable, "node", "nodes")),
			WhyItMatters:        "Over-provisioned nodes bill full price — but reclaiming them safely requires confirming real usage is below requests; acting on request-slack alone risks an OOM outage.",
			Evidence:            evidence,
			Severity:            types.SeverityLow, // a verify-first candidate, not a confident finding
			Category:            types.CategoryCost,
			AffectedResources:   poolResourceRefs(p),
			DollarImpactMonthly: 0, // requests-only is not bankable; the would-be figure is in evidence as UNVERIFIED

			SpendKind:          types.SpendCompute,
			EstimatedEffort:    types.EffortMedium,
			RemediationCommand: fmt.Sprintf("# DO NOT drain blindly. First confirm real usage < requests for pool %s (kubectl top nodes/pods, or Prometheus). Only then lower the node group's min/desired count and `kubectl drain`.", name),
			Confidence:         0.3, // requests-only candidate, not measured usage — unverified
			Provenance:         provenance(),
		})
	}
	return out
}

// nhMetaCollected reports whether the given collect-seam kind token appears in
// inv.Meta.Collected — i.e. that kind was actually listed, not RBAC-denied or
// timed out. The token strings ("pods", "nodes", …) are the ones registered in
// internal/collect/collect.go's step() calls. File-private name to avoid
// colliding with sibling rules that define their own collected-check helper.
func nhMetaCollected(inv *collect.Inventory, kind string) bool {
	for _, k := range inv.Meta.Collected {
		if k == kind {
			return true
		}
	}
	return false
}

// isDaemonSetPod reports whether a pod is owned by a DaemonSet. Such pods are
// pinned one-per-node by design, so their requests do not consolidate when a
// node is drained and must be excluded from reclaimable-capacity math.
func isDaemonSetPod(p corev1.Pod) bool {
	for i := range p.OwnerReferences {
		if p.OwnerReferences[i].Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// podRequests sums the requests the scheduler reserves for a RUNNING pod: every regular container,
// plus every init container that is a NATIVE SIDECAR.
//
// A native sidecar (KEP-753) is an initContainer with restartPolicy: Always. It starts before the
// app containers and then keeps running for the pod's whole life, so its request is held for the
// pod's whole life. A classic init container runs to completion and releases, so it is not
// additive to the steady-state footprint and is still skipped here.
//
// This function counted only Spec.Containers until B-102, on a comment that was true before native
// sidecars existed and is now false for every mesh-injected pod. The error direction is the
// unfavourable one: undercounting what is bound OVERSTATES how much of a pool is idle, and "this
// pool looks drainable" is this rule's entire output. Found by recounting the testbed against raw
// kubectl — Shoalcheck said 4230m, the first jq pass said 4130m, and Shoalcheck was right: the 100m was ten
// istio-proxy sidecars.
//
// The peak-init case is deliberately not modelled. The scheduler's full formula also considers
// max(non-restartable init request + preceding sidecars), which can exceed the steady-state sum for
// a pod with a very large classic init container. That peak is transient by construction, and this
// rule reasons about steady-state occupancy; modelling it would overstate what is bound, which is
// the same error in the opposite direction.
func podRequests(p corev1.Pod) (cpu, mem resource.Quantity) {
	for i := range p.Spec.InitContainers {
		c := &p.Spec.InitContainers[i]
		if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			continue // classic init container: runs to completion, then releases
		}
		req := c.Resources.Requests
		if q, ok := req[corev1.ResourceCPU]; ok {
			cpu.Add(q)
		}
		if q, ok := req[corev1.ResourceMemory]; ok {
			mem.Add(q)
		}
	}
	for i := range p.Spec.Containers {
		req := p.Spec.Containers[i].Resources.Requests
		if c, ok := req[corev1.ResourceCPU]; ok {
			cpu.Add(c)
		}
		if m, ok := req[corev1.ResourceMemory]; ok {
			mem.Add(m)
		}
	}
	return cpu, mem
}

func poolResourceRefs(p *pool) []types.ResourceRef {
	refs := make([]types.ResourceRef, 0, len(p.nodeNames))
	names := append([]string(nil), p.nodeNames...)
	sort.Strings(names)
	for _, n := range names {
		refs = append(refs, types.ResourceRef{Kind: "Node", Name: n})
	}
	return refs
}

func millicoresToCores(q resource.Quantity) float64 {
	return float64(q.MilliValue()) / 1000.0
}

// humanGi renders a memory quantity as a "<n>Gi" string for evidence.
func humanGi(q resource.Quantity) string {
	gi := float64(q.Value()) / (1024 * 1024 * 1024)
	return fmt.Sprintf("%.1fGi", gi)
}

// regionFromNodes returns the first region label found on any node, or "" when
// none carry one. Shared by the cost rules that price cluster-wide resources.
func regionFromNodes(nodes []corev1.Node) string {
	for i := range nodes {
		if r := collect.RegionOf(nodes[i]); r != "" {
			return r
		}
	}
	return ""
}

// providerFromNodes derives the cloud provider the pricing package expects
// ("aws"/"azure"/"gcp") from the cluster's nodes. Rules don't carry the
// provider the way internal/collect does, so we recover it here:
//
//  1. Prefer the node's spec.providerID scheme (aws:// / azure:// / gce://) —
//     authoritative when present.
//  2. Otherwise fall back to the instance-type format, which is genuinely
//     distinctive: Azure SKUs start with "Standard_"; GCP types match a
//     "<family>-<class>-<n>" shape with families e2/n2/n2d/c2/t2d/...; the AWS
//     form is "<family>.<size>" and the dot is the signal.
//
// It returns "" when nothing gives a signal, and that is the whole point. This
// used to end in `return "aws"`, with a comment saying the default preserved
// behaviour for AWS-format FIXTURES — a test convenience deciding what a
// customer's report says. A bare-metal or kind cluster whose nodes carry no
// providerID was then priced against AWS tables and produced dollars nothing
// supported, which is the one thing this project's honesty policy names
// outright. internal/collect derives the same fact honestly (kind:// -> "kind",
// empty -> "unknown"), so the two halves of the codebase disagreed about the
// same cluster and the half that produced money was the dishonest one.
//
// Callers already handle the empty case: every price lookup is guarded by its
// ok return, so an unknown provider yields a finding with no dollar rather than
// a finding with a fabricated one.
// CloudProvider is providerFromNodes for callers outside this package: the pipeline's calendar places a
// version in kubeversions' window, and that table is keyed by the same aws|azure|gcp this returns — not by the
// report's eks|aks|gke display enum. One detector, so the two can never disagree about which table applies.
func CloudProvider(nodes []corev1.Node) string { return providerFromNodes(nodes) }

func providerFromNodes(nodes []corev1.Node) string {
	for i := range nodes {
		switch pid := nodes[i].Spec.ProviderID; {
		case strings.HasPrefix(pid, "aws://"):
			return "aws"
		case strings.HasPrefix(pid, "azure://"):
			return "azure"
		case strings.HasPrefix(pid, "gce://"):
			return "gcp"
		}
	}
	for i := range nodes {
		if p := providerFromInstanceType(nodes[i].Labels[labelInstanceType]); p != "" {
			return p
		}
	}
	return ""
}

// providerFromInstanceType classifies a single instance-type string by its
// naming convention. Returns "" when the type is empty or gives no signal.
func providerFromInstanceType(itype string) string {
	if itype == "" {
		return ""
	}
	if strings.HasPrefix(itype, "Standard_") {
		return "azure" // e.g. Standard_D4lds_v5
	}
	// GCP types look like "<family>-<class>-<vcpu>", e.g. e2-standard-4,
	// n2-standard-8, n2d-standard-4, c2-standard-8, t2d-standard-2.
	if i := strings.IndexByte(itype, '-'); i > 0 {
		switch itype[:i] {
		case "e2", "n2", "n2d", "n1", "c2", "c2d", "c3", "t2d", "t2a", "n4", "c4":
			return "gcp"
		}
	}
	// AWS form is "<family>.<size>" — the dot IS the signal, so it is inferred rather than defaulted to.
	// A string matching none of the three shapes gives no signal at all and must not be guessed: an on-prem
	// label like "bare-metal-r640" is not an AWS instance type, and pricing it as one invents money.
	if strings.Contains(itype, ".") {
		return "aws"
	}
	return ""
}

// RequiredKinds — Allocatable capacity against what is bound to it.
// See deps.go for what belongs in this list.
func (r NodeHeadroom) RequiredKinds() []string { return []string{"nodes", "pods"} }
