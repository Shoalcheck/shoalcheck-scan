package rules

import (
	"fmt"
	"math"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Rightsizing flags containers whose CPU/memory *requests* sit well above their
// observed 7-day p95 usage — reserved capacity that bills full price while no
// replica ever touches it. This is the headline $-savings finding and the ONLY
// rule that consumes Prometheus usage data.
//
// Honesty contract: without Prometheus there is no usage signal, so the rule is
// a strict no-op when opts.Usage == nil. It NEVER guesses utilization.
//
// Method (documented because this is the most-scrutinized number in the product):
//
//   - Usage is keyed by pod name ("ns/pod/container"); workloads expose pod
//     *labels*, not names. We attribute a workload's pods by OWNER REFERENCE
//     (pod → ReplicaSet → Deployment, or pod → StatefulSet/DaemonSet) so each pod
//     belongs to exactly one workload — usage is never double-counted across two
//     findings. Label-superset matching (pod labels ⊇ the workload's pod-template
//     labels, the equality-AND a Service selector uses) is a fallback for pods
//     with no resolvable controller owner.
//   - A replica is the unit of capacity. Across a workload's matched pods we take
//     the MAX p95 per container — sizing to the busiest replica, never the mean,
//     so a hot replica is never starved by an average.
//   - headroomFactor (1.3) leaves 30% above p95 for spikes the p95 elides.
//   - CPU is compressible (throttled, not killed): recommended CPU =
//     ceil(p95 * 1.3), rounded UP to 10m.
//   - MEMORY is non-compressible (a too-low request is an OOMKill): recommended
//     memory = ceil(max(p95 * 1.3, observed_7d_max * 1.05)), rounded UP to 16Mi.
//     The 7d max is a hard floor so a bursty/GC-heavy workload is never down-sized
//     below a working set it provably reaches. We never flag memory when the
//     observed 7d max already meets or exceeds the current request.
//   - We flag only when request > recommended AND the gap is material
//     (CPU gap ≥ 100m OR mem gap ≥ 128Mi) — trivial slivers are noise.
//
// Dollar model (conservative, per dimension, take the larger):
//
//	reclaimable_per_replica = request - recommended       (per container)
//	reclaimable_cores       = reclaimable_per_replica_cores * replicaCount
//	cpu_$ = (reclaimable_cores / perNodeAllocatableCores) * nodeMonthlyUSD
//	mem_$ = (reclaimable_bytes / perNodeAllocatableBytes) * nodeMonthlyUSD
//	dollar = max(cpu_$, mem_$)
//
// We price reclaimed resources as the fraction of ONE node they represent,
// using the cluster's dominant priced node type. Taking the MAX (not the sum)
// of the two dimensions is deliberately conservative: freeing CPU and memory on
// the same replica reclaims overlapping node capacity, so we credit only the
// binding dimension rather than double-counting. When region/type is unpriced
// the dollar impact is 0 with a note — we never fabricate a savings number.
//
// The dollar is an UPPER BOUND, not a realised saving: freed requests turn into
// a smaller bill only if the cluster is node-count-bound on the freed dimension
// AND an autoscaler (or a human shrinking the pool) actually removes a node. On
// a memory-bound cluster, freeing CPU saves $0; on a fixed-size pool, freeing
// anything saves $0 until the pool shrinks. A read-only scan can confirm neither
// precondition, so the figure is labelled "up to $X/mo if consolidated" and the
// realisation caveat is stated in the finding's evidence.
type Rightsizing struct{}

func (Rightsizing) ID() string      { return "k8s.cost.overprovisioned-resources" }
func (Rightsizing) Version() string { return "1.0.0" }

const (
	// headroomFactor multiplies p95 to leave room for spikes above the 95th
	// percentile before we call a request "over-provisioned".
	headroomFactor = 1.3

	// memMaxSafetyFactor is the margin applied to the observed 7d memory MAX
	// when it becomes the floor for the recommended memory request. Memory is
	// non-compressible — a request below a working set the workload provably
	// reaches gets the container OOMKilled — so the recommendation may never
	// drop below ceil(MemBytesMax * memMaxSafetyFactor).
	memMaxSafetyFactor = 1.05

	// Materiality floors: gaps smaller than these are not worth a finding.
	minCPUGapMillis = 100               // 100m
	minMemGapBytes  = 128 * 1024 * 1024 // 128Mi

	// Rounding granularity for recommended requests.
	cpuRoundMillis = 10               // round CPU up to 10m
	memRoundBytes  = 16 * 1024 * 1024 // round memory up to 16Mi
)

// usageSpan is how this rule names the period its figures rest on: the window the run actually had, or
// "observed" when nothing measured it. It never prints the span the QUERIES ask for — that is what made a
// finding say "7d p95" over an hour of Prometheus while the methodology block beside it said 1h (M-127).
func usageSpan(opts Options) string {
	if w := strings.TrimSpace(opts.UsageWindow); w != "" {
		return w
	}
	return "observed"
}

func (r Rightsizing) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Honest no-op: no Prometheus → no usage → no rightsizing claim.
	if opts.Usage == nil {
		return nil
	}

	// Per-node pricing basis: the cluster's dominant priced node type. We use a
	// single basis (rather than per-pod node lookup) because workloads span pods
	// on many nodes; the dominant type is the defensible cluster-wide unit cost.
	basis := pricingBasis(inv.Nodes, opts)
	// Every sentence below names the same span, and it is the one the run actually had.
	span := usageSpan(opts)

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		pods := podsForWorkload(inv, w)
		if len(pods) == 0 {
			continue // no live pods to read usage from
		}

		// replicaCount drives $ scaling. For Deployments/StatefulSets the DECLARED
		// spec replica count is the reproducible unit — using the live matched-pod
		// count would make the headline $ wobble run-to-run under HPA scaling. For
		// DaemonSets (Replicas==-1, node-bound) the declared count is meaningless;
		// scale by the number of nodes the DaemonSet actually schedules onto, which
		// is its real replica count, rather than a transient matched-pod count that
		// undercounts on partial rollout / scrape gaps.
		replicaCount := int(w.Replicas)
		replicaBasisNote := "declared spec replicas"
		if w.Kind == "DaemonSet" {
			replicaCount = daemonSetNodeCount(inv, w)
			replicaBasisNote = "nodes the DaemonSet schedules onto"
		}
		if replicaCount < 1 {
			// Last-resort fallback (e.g. unparseable DaemonSet scheduling): the
			// matched-pod count. Sensitive to scrape gaps — noted in evidence.
			replicaCount = len(pods)
			replicaBasisNote = "matched live-pod count (declared replicas unavailable — $ may be sensitive to transient pod state)"
		}

		var (
			evidence   []string
			recommends []containerReco
			cpuReclaim resource.Quantity // summed over flagged containers, per replica
			memReclaim resource.Quantity
			minSeries  int  // fewest pod series backing any flagged container (evidence depth)
			anyMemFlag bool // a memory dimension was flagged (drives burstiness note)
			memBurstHi bool // observed mem MAX >> p95 on a flagged container (high burstiness)
		)

		for _, c := range w.PodSpec.Containers {
			reqCPU := c.Resources.Requests[corev1.ResourceCPU]
			reqMem := c.Resources.Requests[corev1.ResourceMemory]

			st := maxP95(opts.Usage, pods, c.Name)
			if !st.found {
				continue // no usage series for this container — skip, don't guess
			}

			// CPU is compressible (throttled, not killed), so p95×headroom is a safe
			// recommendation. MEMORY is non-compressible: a request below the working
			// set the workload provably reaches is an OOMKill. The recommended memory
			// therefore floors at the observed 7d MAX (×a small safety margin), so we
			// never down-size a bursty / GC-heavy workload below its real ceiling.
			// NEVER ZERO. ceil(0 × 1.3) rounds up to 0, so an idle container was recommended `cpu: 0m` — no
			// request at all, the minimum CPU shares, the first container starved under contention — and the whole
			// request was counted as reclaimable. The floor is the rounding step itself, the smallest value this
			// rule ever recommends; memory has its own below.
			recCPUm := max(roundUpMillis(st.cpuP95Cores*headroomFactor*1000, cpuRoundMillis), cpuRoundMillis)
			memP95Reco := st.memP95Bytes * headroomFactor
			memMaxFloor := st.memMaxBytes * memMaxSafetyFactor
			memRecoRaw := memP95Reco
			memFlooredByMax := false
			if memMaxFloor > memRecoRaw {
				memRecoRaw = memMaxFloor
				memFlooredByMax = true
			}
			recMemB := max(roundUpBytes(memRecoRaw, memRoundBytes), memRoundBytes)

			cpuGap := reqCPU.MilliValue() - recCPUm
			memGap := reqMem.Value() - recMemB

			cpuMaterial := !reqCPU.IsZero() && cpuGap >= minCPUGapMillis
			// Never flag memory when the observed 7d MAX already meets or exceeds the
			// current request — there is no safe room to reclaim; cutting it OOMKills.
			memMaterial := !reqMem.IsZero() && memGap >= minMemGapBytes &&
				memMaxFloor < float64(reqMem.Value())
			if !cpuMaterial && !memMaterial {
				continue
			}

			reco := containerReco{name: c.Name}
			parts := []string{}
			if cpuMaterial {
				reco.cpuMillis = recCPUm
				reco.hasCPU = true
				cpuReclaim.Add(*resource.NewMilliQuantity(cpuGap, resource.DecimalSI))
				parts = append(parts, fmt.Sprintf(
					"requests %s CPU, %s p95 usage %s (×%.1f headroom = %s) -> recommend %s%s, reclaim %s × %d replica%s",
					millis(reqCPU.MilliValue()), span, millis(int64(math.Round(st.cpuP95Cores*1000))),
					headroomFactor, millis(int64(math.Ceil(st.cpuP95Cores*headroomFactor*1000))),
					millis(recCPUm), cpuFloorClause(st.cpuP95Cores), millis(cpuGap), replicaCount, plural(replicaCount)))
			}
			if memMaterial {
				reco.memBytes = recMemB
				reco.hasMem = true
				reco.memFromMax = memFlooredByMax
				anyMemFlag = true
				memReclaim.Add(*resource.NewQuantity(memGap, resource.BinarySI))
				// Burstiness signal: observed MAX materially above p95 means the p95
				// under-represents real demand — lowers confidence (see below).
				if st.memMaxBytes > st.memP95Bytes*headroomFactor {
					memBurstHi = true
				}
				floorClause := ""
				if memFlooredByMax {
					floorClause = ", recommend floored at " + span + " max"
				}
				parts = append(parts, fmt.Sprintf(
					"requests %s mem, %s p95 usage %s / %s max %s (recommend = max(p95×%.1f, max×%.2f)%s = %s), reclaim %s × %d replica%s",
					humanMi(reqMem.Value()), span, humanMi(int64(st.memP95Bytes)), span, humanMi(int64(st.memMaxBytes)),
					headroomFactor, memMaxSafetyFactor, floorClause,
					humanMi(recMemB), humanMi(memGap), replicaCount, plural(replicaCount)))
			}
			recommends = append(recommends, reco)
			if minSeries == 0 || st.series < minSeries {
				minSeries = st.series
			}
			evidence = append(evidence, fmt.Sprintf("container %s in %s %s/%s: %s",
				c.Name, w.Kind, w.Namespace, w.Name, strings.Join(parts, "; ")))
		}

		if len(recommends) == 0 {
			continue
		}

		// Dollar impact: fraction-of-node model, per dimension, take the larger.
		// This is an UPPER BOUND on reclaimable spend, not a realised saving (see
		// rightsizingDollar) — realisation requires the cluster to be bound on the
		// freed dimension AND a way to shrink the node pool.
		dollar, dollarNote := rightsizingDollar(basis, cpuReclaim, memReclaim, replicaCount)
		evidence = append(evidence, dollarNote)
		evidence = append(evidence, fmt.Sprintf(
			"$ scaled by %s (%s)", nWord(replicaCount, "replica", "replicas"), replicaBasisNote))
		// Honest precondition for the dollar: freed requests only become money if
		// a node can actually be removed.
		evidence = append(evidence,
			"realisation caveat: reclaimed requests convert to a real bill reduction only if the cluster is node-count-bound on the freed dimension AND an autoscaler/manual pool-shrink removes a node; on a memory-bound or fixed-size pool, freeing CPU saves $0 until the pool shrinks")

		// Confidence is derived from data quality, not hardcoded. We start from a
		// usage-based baseline and DOWN-rank when the evidence is thin: a single
		// pod/series backing the recommendation, or a memory recommendation whose
		// observed 7d MAX sits well above p95 (high burstiness ⇒ p95 under-states
		// demand). The 7d window itself is assumed, not verified — short Prometheus
		// retention is silently observed as a shorter range (see usage.go), so the
		// baseline already reflects that the window is unconfirmed.
		confidence := 0.85
		var qualityNotes []string
		if minSeries <= 1 {
			confidence -= 0.2
			qualityNotes = append(qualityNotes,
				"only one pod series backed the p95 — a single short-lived or just-restarted replica yields a p95 over an unrepresentative range")
		}
		if memBurstHi {
			confidence -= 0.1
			qualityNotes = append(qualityNotes,
				fmt.Sprintf("observed %s memory MAX is well above p95 (bursty/GC-heavy) — the recommendation is floored at the max, but p95 alone would have under-sized it", span))
		}
		if confidence < 0.4 {
			confidence = 0.4
		}
		evidence = append(evidence,
			historyBasis(span))
		for _, n := range qualityNotes {
			evidence = append(evidence, "data-quality: "+n)
		}

		memClause := ""
		if anyMemFlag {
			memClause = " The memory recommendation is floored at the observed " + span + " max so a bursty or GC-heavy workload is not down-sized below a working set it provably reaches."
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Right-size over-provisioned requests on %s/%s", w.Namespace, w.Name),
			Description: fmt.Sprintf(
				"%s %s/%s reserves CPU/memory above what its %s usage ever needed, across %s. CPU is sized to the busiest replica's p95 plus 30%% headroom; memory to the larger of p95×1.3 and the observed %s max.%s This reclaims reserved capacity the workload's %s p95 never used — but the 95th percentile excludes tail bursts, so verify against the container's %s max and your latency SLOs before applying: CPU below request is throttled, memory below peak is OOMKilled.",
				w.Kind, w.Namespace, w.Name, span, nWord(replicaCount, "replica", "replicas"), span, memClause, span, span),
			WhyItMatters:        "Requests far above real usage reserve node capacity nothing consumes, inflating the cluster's node count and bill.",
			Evidence:            evidence,
			Severity:            types.SeverityMedium, // cost / efficiency gap — no outage or security exposure
			Category:            types.CategoryCost,
			AffectedResources:   []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			DollarImpactMonthly: dollar,

			SpendKind:       types.SpendCompute,
			EstimatedEffort: types.EffortLow,
			RemediationYAML: rightsizingPatch(w, recommends, span),
			Confidence:      confidence,
			Provenance:      provenance(),
		})
	}
	return out
}

// daemonSetNodeCount returns the number of nodes a DaemonSet actually schedules
// onto, from inv.Nodes filtered by the pod template's nodeSelector. This is the
// DaemonSet's real replica count — more reproducible than the transient matched
// live-pod count (which undercounts on partial rollout, scrape gaps, or pods in
// Pending/Terminating). Node affinity / taint-toleration interplay can still
// shrink the real set, but nodeSelector covers the common targeting case; the
// finding's evidence flags the basis so the number is never presented as exact.
func daemonSetNodeCount(inv *collect.Inventory, w workload) int {
	sel := w.PodSpec.NodeSelector
	count := 0
	for i := range inv.Nodes {
		n := inv.Nodes[i]
		if nodeMatchesSelector(n, sel) {
			count++
		}
	}
	return count
}

// nodeMatchesSelector reports whether a node's labels satisfy every key/value in
// sel (equality-AND). An empty selector matches every node (a DaemonSet with no
// nodeSelector runs on all schedulable nodes).
func nodeMatchesSelector(n corev1.Node, sel map[string]string) bool {
	for k, v := range sel {
		if n.Labels[k] != v {
			return false
		}
	}
	return true
}

// containerReco holds the recommended request values for one container.
type containerReco struct {
	name           string
	hasCPU, hasMem bool
	cpuMillis      int64
	memBytes       int64
	// memFromMax: memBytes is the observed max ×memMaxSafetyFactor, not p95 ×headroomFactor — the patch
	// comment names whichever figure the value came from.
	memFromMax bool
}

// nodeBasis is the per-node pricing unit derived from the cluster.
type nodeBasis struct {
	region       string
	instanceType string
	capacity     types.CapacityType
	allocCPUm    int64 // allocatable CPU millicores per node
	allocMemB    int64 // allocatable memory bytes per node
	monthlyUSD   float64
	priced       bool
}

// pricingBasis picks the cluster's dominant priced node type as the per-node
// cost unit. "Dominant" = the priced instance type backing the most nodes;
// ties break alphabetically for determinism. When no node carries a priced
// (region, type) pair, priced=false and the dollar impact will be 0.
func pricingBasis(nodes []corev1.Node, opts Options) nodeBasis {
	type agg struct {
		count     int
		allocCPUm int64
		allocMemB int64
		monthly   float64
		region    string
		itype     string
		capacity  types.CapacityType
	}
	provider := providerFromNodes(nodes) // one cloud per cluster
	byType := map[string]*agg{}
	for i := range nodes {
		n := nodes[i]
		region := collect.RegionOf(n)
		itype := n.Labels[labelInstanceType]
		// SHARED classifier — identical to the collect seam so both seams agree on
		// whether a node is spot (cross-seam parity).
		capacity := collect.ClassifyCapacityType(provider, n)
		monthly, ok := opts.nodeMonthly(provider, region, itype, capacity)
		if !ok {
			continue // unpriced node can't anchor a defensible $ basis
		}
		key := region + "/" + itype + "/" + string(capacity)
		a := byType[key]
		if a == nil {
			a = &agg{region: region, itype: itype, capacity: capacity}
			byType[key] = a
		}
		a.count++
		a.allocCPUm = n.Status.Allocatable.Cpu().MilliValue()
		a.allocMemB = n.Status.Allocatable.Memory().Value()
		a.monthly = monthly
	}
	if len(byType) == 0 {
		return nodeBasis{priced: false}
	}
	keys := make([]string, 0, len(byType))
	for k := range byType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	best := byType[keys[0]]
	for _, k := range keys {
		if byType[k].count > best.count {
			best = byType[k]
		}
	}
	return nodeBasis{
		region:       best.region,
		instanceType: best.itype,
		capacity:     best.capacity,
		allocCPUm:    best.allocCPUm,
		allocMemB:    best.allocMemB,
		monthlyUSD:   best.monthly,
		priced:       best.allocCPUm > 0 && best.allocMemB > 0,
	}
}

// rightsizingDollar prices the reclaimable resources as the fraction of one
// node they represent (see Rightsizing doc). cpuReclaim/memReclaim are
// per-replica gaps summed across flagged containers; we scale by replicaCount.
// The figure is an UPPER BOUND on reclaimable spend — it is the bill reduction
// IF the freed capacity lets the cluster shed a node, which requires the cluster
// to be bound on the freed dimension and an autoscaler/manual pool-shrink to act
// (the rule cannot confirm either from a read-only scan). Returns ($/mo, note).
// Unpriced → (0, "price unknown" note).
func rightsizingDollar(b nodeBasis, cpuReclaimPerReplica, memReclaimPerReplica resource.Quantity, replicaCount int) (float64, string) {
	if !b.priced {
		return 0, "node region/type not in price table — dollar impact left at $0 (price unknown)"
	}
	totalCPUm := cpuReclaimPerReplica.MilliValue() * int64(replicaCount)
	totalMemB := memReclaimPerReplica.Value() * int64(replicaCount)

	cpuFrac := float64(totalCPUm) / float64(b.allocCPUm)
	memFrac := float64(totalMemB) / float64(b.allocMemB)
	cpuUSD := cpuFrac * b.monthlyUSD
	memUSD := memFrac * b.monthlyUSD

	dollar := cpuUSD
	dim := "CPU"
	if memUSD > dollar {
		dollar, dim = memUSD, "memory"
	}
	note := fmt.Sprintf(
		"$ model (UPPER BOUND, if consolidated): reclaim %s CPU / %s mem across %s, divided by %s allocatable (%s CPU / %s) × $%.2f/node/mo (%s) -> %s-bound up to $%.2f/mo",
		millis(totalCPUm), humanMi(totalMemB), nWord(replicaCount, "replica", "replicas"), b.instanceType, millis(b.allocCPUm), humanMi(b.allocMemB), b.monthlyUSD, b.region,
		dim, dollar)
	return dollar, note
}

// podsForWorkload returns the inventory pods belonging to a workload, attributing
// each pod to EXACTLY ONE workload so usage (and therefore $) is never double-
// counted across two findings.
//
// Primary attribution is by owner reference: resolve the pod's controller chain
// (pod → ReplicaSet → Deployment, or pod → StatefulSet/DaemonSet directly) and
// keep the pod only when the OUTERMOST owner matches this workload's Kind+Name.
// This is exact, and it fixes the label-superset false positive where a canary's
// pod-template labels {app:api} are a subset of a sibling's pod labels
// {app:api,track:stable}: a plain label match would attribute the sibling's pods
// (and usage) to BOTH workloads. Owner refs partition the pods cleanly.
//
// Label-superset matching (pod labels ⊇ the workload's pod-template labels,
// equality-AND, same semantics as a Service selector) is the FALLBACK, used only
// for pods that carry no resolvable controller owner — and even then we exclude
// any pod whose owner resolves to a DIFFERENT collected workload, so a pod is
// never attributed to a workload it does not belong to. An empty PodLabels set
// matches nothing (we won't claim every pod in the namespace).
func podsForWorkload(inv *collect.Inventory, w workload) []corev1.Pod {
	sel := labels.SelectorFromSet(labels.Set(w.PodLabels))
	hasLabels := len(w.PodLabels) > 0
	var out []corev1.Pod
	for i := range inv.Pods {
		p := inv.Pods[i]
		if p.Namespace != w.Namespace {
			continue
		}
		owner := outermostOwner(inv, p)
		if owner != nil {
			// Pod has a resolvable controller: attribute by owner identity only.
			if owner.Kind == w.Kind && owner.Name == w.Name {
				out = append(out, p)
			}
			continue
		}
		// No resolvable owner: fall back to label-superset, but only if this
		// workload declares pod-template labels to match on.
		if hasLabels && sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// outermostOwner returns the OUTERMOST owner link for a pod (e.g. the Deployment
// behind a ReplicaSet, or a StatefulSet/DaemonSet that owns pods directly), or
// nil when the pod has no resolvable controller. Reuses the package's
// owner-chain resolution so attribution matches the rest of the engine.
func outermostOwner(inv *collect.Inventory, p corev1.Pod) *types.OwnerLink {
	chain := ownerChain(inv, p)
	if len(chain) == 0 {
		return nil
	}
	return &chain[0]
}

// containerStats is the per-container usage signal aggregated across a
// workload's replicas: the MAX p95 (size to the busiest replica) AND the MAX of
// the observed 7d max (the real ceiling the memory floor must respect), plus how
// many distinct pod series actually backed the numbers.
type containerStats struct {
	cpuP95Cores float64 // max p95 across replicas (compressible dimension)
	memP95Bytes float64 // max p95 across replicas
	memMaxBytes float64 // max of observed 7d MemBytesMax across replicas
	series      int     // number of pod series that contributed (evidence depth)
	found       bool
}

// maxP95 returns the busiest-replica p95 for container `cname` across the given
// pods, AND the observed 7d memory max (used as a hard floor so we never size
// memory below a working set the workload provably reaches), AND the count of
// series that backed the result. Memory is non-compressible: a request below
// the real max is an OOMKill, so the max must clamp the recommendation.
func maxP95(usage map[string]prom.ContainerUsage, pods []corev1.Pod, cname string) containerStats {
	var s containerStats
	for i := range pods {
		key := pods[i].Namespace + "/" + pods[i].Name + "/" + cname
		u, ok := usage[key]
		if !ok {
			continue
		}
		s.found = true
		s.series++
		if u.CPUCoresP95 > s.cpuP95Cores {
			s.cpuP95Cores = u.CPUCoresP95
		}
		if u.MemBytesP95 > s.memP95Bytes {
			s.memP95Bytes = u.MemBytesP95
		}
		if u.MemBytesMax > s.memMaxBytes {
			s.memMaxBytes = u.MemBytesMax
		}
	}
	return s
}

// rightsizingPatch emits a kubectl-applyable resources.requests patch carrying
// the recommended values for each flagged container.
func rightsizingPatch(w workload, recos []containerReco, span string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apps/v1\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      containers:\n", w.Kind, w.Name, w.Namespace)
	for _, rc := range recos {
		fmt.Fprintf(&b, "        - name: %s\n          resources:\n            requests:\n", rc.name)
		if rc.hasCPU {
			fmt.Fprintf(&b, "              cpu: %s      # %s p95 ×%.1f, right-sized\n", millis(rc.cpuMillis), span, headroomFactor)
		}
		if rc.hasMem && rc.memFromMax {
			fmt.Fprintf(&b, "              memory: %s  # %s max ×%.2f, right-sized\n", humanMi(rc.memBytes), span, memMaxSafetyFactor)
		} else if rc.hasMem {
			fmt.Fprintf(&b, "              memory: %s  # %s p95 ×%.1f, right-sized\n", humanMi(rc.memBytes), span, headroomFactor)
		}
	}
	return b.String()
}

// cpuFloorClause says when the recommendation is the floor rather than p95 ×headroom, so the evidence line that
// shows "×1.3 headroom = 0m -> recommend 10m" says where the 10m came from.
func cpuFloorClause(p95Cores float64) string {
	if p95Cores*headroomFactor*1000 < cpuRoundMillis {
		return fmt.Sprintf(" (floored at %s: a zero request is no request)", millis(cpuRoundMillis))
	}
	return ""
}

// historyBasis is the data-quality line about the window. A run whose source reported no window names it
// "observed", and "rest on observed of history" is not a sentence.
func historyBasis(span string) string {
	if span == "observed" {
		return "data-quality: the usage source reported no window, so the figures above rest on however much history " +
			"it held; a short one biases a p95 toward the quiet hours it happened to cover"
	}
	return fmt.Sprintf("data-quality: the figures above rest on %s of history, as the usage source reported it; a "+
		"shorter window biases a p95 toward the quiet hours it happened to cover", span)
}

// roundUpMillis rounds value (millicores) UP to the nearest `unit` millicores.
func roundUpMillis(value float64, unit int64) int64 {
	v := int64(math.Ceil(value))
	if r := v % unit; r != 0 {
		v += unit - r
	}
	return v
}

// roundUpBytes rounds value (bytes) UP to the nearest `unit` bytes.
func roundUpBytes(value float64, unit int64) int64 {
	v := int64(math.Ceil(value))
	if r := v % unit; r != 0 {
		v += unit - r
	}
	return v
}

// millis renders a millicore count as a "<n>m" string.
func millis(m int64) string { return fmt.Sprintf("%dm", m) }

// humanMi renders a byte count as a whole-number "<n>Mi" string (recommended
// values are 16Mi-aligned, so this is exact for them).
func humanMi(bytes int64) string {
	return fmt.Sprintf("%dMi", bytes/(1024*1024))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// RequiredKinds — Requests come from the templates, the ceiling from the nodes, the observed figures are keyed by pod.
// See deps.go for what belongs in this list.
func (r Rightsizing) RequiredKinds() []string { return withWorkloads("nodes", "pods") }

// RequiresUsage — this rule compares declared requests against OBSERVED consumption. With no usage
// source it emits nothing, so a comparison between a run with Prometheus and one without must not read
// the silence as the cluster having been rightsized.
func (r Rightsizing) RequiresUsage() bool { return true }
