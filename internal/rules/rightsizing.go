package rules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
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
//	cpu_$ = Σ over replicas (reclaimable_cores / that node's allocatable cores) × that node's monthly price
//	mem_$ = Σ over replicas (reclaimable_bytes / that node's allocatable bytes) × that node's monthly price
//	dollar = max(cpu_$, mem_$)
//
// Each replica is priced on the node it runs on (ENG-02). Taking the MAX (not the sum) of the two dimensions is
// deliberately conservative: freeing CPU and memory on the same replica reclaims overlapping node capacity. A
// replica on a node the table does not price adds $0 and is counted — we never fabricate a savings number.
//
// Two things withhold a dollar the arithmetic would give. An autoscaler that scales on a dimension's utilization
// governs that dimension's request (ENG-01). And only usage over a proven window banks: a metrics.k8s.io sample
// or a VPA target gives a candidate at $0 (ENG-04).
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
	fs, _ := r.evaluate(inv, opts)
	return fs
}

// RightsizingWithheld is every workload whose over-provisioned request was not offered because an autoscaler
// governs it, as "Kind ns/name (CPU)" — what the methodology counts beside the findings. The same pass as Evaluate.
func RightsizingWithheld(inv *collect.Inventory, opts Options) []string {
	_, w := Rightsizing{}.evaluate(inv, opts)
	return w
}

func (r Rightsizing) evaluate(inv *collect.Inventory, opts Options) ([]types.Finding, []string) {
	// Honest no-op: no Prometheus → no usage → no rightsizing claim.
	if opts.Usage == nil {
		return nil, nil
	}

	// Every sentence below names the same span, and it is the one the run actually had.
	runSpan := usageSpan(opts)
	banks, basisSaid := usageBanks(opts)
	stat := usageStat(opts)
	prices := newReplicaPricer(inv, opts)
	pods := derived(inv, opts).podIndex()
	hpas := autoscaled(inv)
	history := newUsageHistory(opts.Usage)
	reading := readingTime(inv)

	var out []types.Finding
	var withheld []string
	for _, w := range workloads(inv, opts) {
		live := pods.podsFor(w)
		if len(live) == 0 {
			continue // no live pods to read usage from
		}
		// THE WORKLOAD'S OWN SPAN when its namespace was read over a shorter window than the run's: a sharded read
		// retries a refused shard over 3d or 1d (ENG-05), and its sentences name that window, not the week.
		span := shardSpan(runSpan, opts.Usage, live)
		// THE WORKLOAD'S SERIES, NOT ONLY ITS LIVE PODS' (ENG-06). A rollout replaces every pod, and a pod's series
		// ends with it: reading only the live pods' usage threw away the week before the last deploy. The earlier
		// pods' series are found by the names their controller gave them.
		names, past := history.seriesOf(w, live)
		wBanks, wBasisSaid := banks, basisSaid

		// figure is how the number beside a request is introduced: "7d p95 usage", "usage at one moment", "VPA target".
		figure := map[string]string{"p95": span + " p95 usage", "one-moment sample": "usage at one moment", "VPA target": "VPA target"}[stat]

		// replicaCount is the reproducible unit the dollar is stated over. For Deployments/StatefulSets the
		// DECLARED spec replica count — the live matched-pod count makes the headline $ wobble run-to-run under
		// scaling. For a DaemonSet the count is its controller's own: status.desiredNumberScheduled, after
		// affinity, taints and tolerations, which a nodeSelector match over-counted (ENG-10).
		replicaCount := int(w.Replicas)
		replicaBasisNote := "declared spec replicas"
		if w.Kind == "DaemonSet" {
			replicaCount = int(w.Scheduled)
			replicaBasisNote = "the nodes the DaemonSet controller schedules it onto (status.desiredNumberScheduled)"
		}
		if replicaCount < 1 {
			// Last-resort fallback: the matched-pod count. Sensitive to scrape gaps — noted in evidence.
			replicaCount = len(live)
			replicaBasisNote = "matched live-pod count (declared replicas unavailable — $ may be sensitive to transient pod state)"
		}
		governed := hpas[workloadKey{w.Kind, w.Namespace, w.Name}]
		oomed := oomKilledContainers(live)

		var (
			evidence   []string
			recommends []containerReco
			cpuReclaim int64 // millicores per replica, summed over flagged containers
			memReclaim int64 // bytes per replica
			minSeries  int   // fewest pod series backing any flagged container (evidence depth)
			anyMemFlag bool  // a memory dimension was flagged (drives burstiness note)
			memBurstHi bool  // observed mem MAX >> p95 on a flagged container (high burstiness)
			held       = map[string]string{}
		)

		for _, c := range w.PodSpec.Containers {
			reqCPU := c.Resources.Requests[corev1.ResourceCPU]
			reqMem := c.Resources.Requests[corev1.ResourceMemory]

			st := maxP95(opts.Usage, w.Namespace, names, c.Name)
			if !st.found {
				continue // no usage series for this container — skip, don't guess
			}

			// CPU is compressible (throttled, not killed), so p95×headroom is a safe recommendation. MEMORY is
			// non-compressible: the recommended memory floors at the observed max (×a small margin), so a bursty
			// or GC-heavy workload is never down-sized below its real ceiling. NEVER ZERO: an idle container's
			// recommendation is the rounding step, the smallest value this rule ever recommends.
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
			// Never flag memory when the observed max already meets or exceeds the current request — there is
			// no safe room to reclaim; cutting it OOMKills.
			memMaterial := !reqMem.IsZero() && memGap >= minMemGapBytes &&
				memMaxFloor < float64(reqMem.Value())

			// AN AUTOSCALER THAT SCALES ON A DIMENSION'S UTILIZATION GOVERNS ITS REQUEST (ENG-01). Utilization is
			// usage ÷ request, and the autoscaler holds it at its target: a container at its 50% target looks
			// half idle, and lowering the request makes the autoscaler add replicas until it is back at 50% —
			// the same capacity reserved, and $0 saved. The dimension is withheld: no dollar, no patch line, and
			// the reason stated.
			if why, ok := governed.governs(corev1.ResourceCPU, c.Name); ok && cpuMaterial {
				cpuMaterial, held["CPU"] = false, why
			}
			if why, ok := governed.governs(corev1.ResourceMemory, c.Name); ok && memMaterial {
				memMaterial, held["memory"] = false, why
			}
			// A CONTAINER THE KERNEL ALREADY KILLED FOR MEMORY IS NEVER OFFERED LESS (ENG-30): its last life ended at
			// its working set's ceiling, whatever a p95 says about the others.
			if at, ok := oomed[c.Name]; ok && memMaterial {
				when := "at a time the status does not record"
				if !at.IsZero() {
					when = "at " + at.UTC().Format("2006-01-02T15:04:05Z")
				}
				memMaterial, held["memory"] = false, fmt.Sprintf("container %s's last life ended OOMKilled %s; a lower "+
					"memory request on a container the kernel already killed for memory is not offered", c.Name, when)
			}
			if !cpuMaterial && !memMaterial {
				continue
			}

			reco := containerReco{name: c.Name}
			parts := []string{}
			if cpuMaterial {
				reco.cpuMillis = recCPUm
				reco.hasCPU = true
				cpuReclaim += cpuGap
				parts = append(parts, fmt.Sprintf(
					"requests %s CPU, %s %s (×%.1f headroom = %s) -> recommend %s%s, reclaim %s × %d replica%s",
					millis(reqCPU.MilliValue()), figure, millis(int64(math.Round(st.cpuP95Cores*1000))),
					headroomFactor, millis(int64(math.Ceil(st.cpuP95Cores*headroomFactor*1000))),
					millis(recCPUm), cpuFloorClause(st.cpuP95Cores), millis(cpuGap), replicaCount, plural(replicaCount)))
			}
			if memMaterial {
				reco.memBytes = recMemB
				reco.hasMem = true
				reco.memFromMax = memFlooredByMax
				anyMemFlag = true
				memReclaim += memGap
				// Burstiness signal: observed MAX materially above p95 means the p95 under-represents real
				// demand — lowers confidence (see below).
				if st.memMaxBytes > st.memP95Bytes*headroomFactor {
					memBurstHi = true
				}
				floorClause := ""
				if memFlooredByMax {
					floorClause = ", recommend floored at " + span + " max"
				}
				parts = append(parts, fmt.Sprintf(
					"requests %s mem, %s %s / %s max %s (recommend = max(%s×%.1f, max×%.2f)%s = %s), reclaim %s × %d replica%s",
					humanMi(reqMem.Value()), figure, humanMi(int64(st.memP95Bytes)), span, humanMi(int64(st.memMaxBytes)),
					stat, headroomFactor, memMaxSafetyFactor, floorClause,
					humanMi(recMemB), humanMi(memGap), replicaCount, plural(replicaCount)))
			}
			recommends = append(recommends, reco)
			if minSeries == 0 || st.series < minSeries {
				minSeries = st.series
			}
			evidence = append(evidence, fmt.Sprintf("container %s in %s %s/%s: %s",
				c.Name, w.Kind, w.Namespace, w.Name, strings.Join(parts, "; ")))
		}

		for _, dim := range []string{"CPU", "memory"} {
			if why := held[dim]; why != "" {
				evidence = append(evidence, "withheld: "+dim+" — "+why)
			}
		}
		if len(recommends) == 0 {
			if len(held) > 0 {
				withheld = append(withheld, fmt.Sprintf("%s %s/%s (%s)", w.Kind, w.Namespace, w.Name, heldDims(held)))
			}
			continue
		}

		// Dollar impact: each replica priced on the node it runs on (ENG-02), per dimension, the larger of the
		// two. An UPPER BOUND on reclaimable spend, not a realised saving — and banked only on usage that proves
		// a window (ENG-04).
		// THE PER-SERIES AGE GATE (ENG-03), where no earlier pod left a series: every figure then rests on pods the
		// reading can date, and pods younger than a day cannot have seen a daily peak.
		if wBanks && past == 0 {
			if age, ok := youngestSpan(live, reading); ok && age < 24*time.Hour {
				wBanks = false
				wBasisSaid = fmt.Sprintf("the oldest pod behind this usage was created %s before the reading and no earlier "+
					"pod of the workload left a series, so its usage covers under the day a daily peak needs", humanAge(age))
			}
		}
		if past > 0 {
			evidence = append(evidence, fmt.Sprintf("the usage includes %s from pods of this workload that are no longer "+
				"running (earlier rollouts), found by the names their controller gave them", nWord(past, "series", "series")))
		}
		dollar, dollarNote, shares, facts := prices.price(w, live, replicaCount, cpuReclaim, memReclaim)
		facts = append(facts, types.NewFact("rightsizing.banked", wBanks))
		for _, dim := range []string{"CPU", "memory"} {
			if held[dim] != "" {
				facts = append(facts, types.NewFact("rightsizing.withheld", dim))
			}
		}
		if !wBanks {
			dollar, shares = 0, nil
			dollarNote = "dollars withheld (basis: unverified): " + wBasisSaid + "; the figure below is what the same reclaim would be worth, not a saving — " + dollarNote
		}
		evidence = append(evidence, dollarNote)
		evidence = append(evidence, fmt.Sprintf(
			"$ scaled by %s (%s)", nWord(replicaCount, "replica", "replicas"), replicaBasisNote))
		// Honest precondition for the dollar: freed requests only become money if a node can actually be removed.
		evidence = append(evidence,
			"realisation caveat: reclaimed requests convert to a real bill reduction only if the cluster is node-count-bound on the freed dimension AND an autoscaler/manual pool-shrink removes a node; on a memory-bound or fixed-size pool, freeing CPU saves $0 until the pool shrinks")

		// Confidence is derived from data quality, not hardcoded: down-ranked for a single series behind the
		// recommendation, for high memory burstiness, and to a candidate's level when the usage proves no window.
		confidence := 0.85
		var qualityNotes []string
		if !wBanks {
			confidence = 0.5
		}
		if minSeries <= 1 {
			confidence -= 0.2
			qualityNotes = append(qualityNotes,
				"only one pod series backed the "+stat+" — a single short-lived or just-restarted replica yields a figure over an unrepresentative range")
		}
		if memBurstHi {
			confidence -= 0.1
			qualityNotes = append(qualityNotes,
				fmt.Sprintf("observed %s memory MAX is well above the %s (bursty/GC-heavy) — the recommendation is floored at the max, but the %s alone would have under-sized it", span, stat, stat))
		}
		if confidence < 0.3 {
			confidence = 0.3
		}
		evidence = append(evidence, historyBasis(span, opts.UsageBasis))
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
				"%s %s/%s reserves CPU/memory above what its %s usage ever needed, across %s. CPU is sized to the busiest replica's %s plus 30%% headroom; memory to the larger of %s×1.3 and the observed %s max.%s This reclaims reserved capacity the workload's %s %s never used — but the figure excludes tail bursts, so verify against the container's %s max and your latency SLOs before applying: CPU below request is throttled, memory below peak is OOMKilled.",
				w.Kind, w.Namespace, w.Name, span, nWord(replicaCount, "replica", "replicas"), stat, stat, span, memClause, span, stat, span),
			WhyItMatters:        "Requests far above real usage reserve node capacity nothing consumes, inflating the cluster's node count and bill.",
			Evidence:            evidence,
			Severity:            types.SeverityMedium, // cost / efficiency gap — no outage or security exposure
			Category:            types.CategoryCost,
			AffectedResources:   []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			DollarImpactMonthly: dollar,
			SpendNodes:          shares,
			Facts:               facts,

			SpendKind:       types.SpendCompute,
			EstimatedEffort: types.EffortLow,
			RemediationYAML: rightsizingPatch(w, recommends, span, stat),
			Confidence:      confidence,
			Provenance:      provenance(),
		})
	}
	sort.Strings(withheld)
	return out, withheld
}

// heldDims names the withheld dimensions in a fixed order.
func heldDims(held map[string]string) string {
	var d []string
	for _, k := range []string{"CPU", "memory"} {
		if held[k] != "" {
			d = append(d, k)
		}
	}
	return strings.Join(d, ", ")
}

// usageBanks reports whether the usage can carry a dollar, and how its basis is said when it cannot. A saving is
// banked only on a WINDOWED source over at least a day: Prometheus with its probed coverage of 24 hours or more.
// One metrics.k8s.io sample is one moment, a VPA target is the autoscaler's own estimate, and a window under a
// day cannot represent a daily peak — each gives a candidate the reader can check, at $0 (ENG-04).
func usageBanks(opts Options) (bool, string) {
	b := opts.UsageBasis
	if b == nil || b.Source == "" || b.Source == "none" {
		return false, "the usage source is not recorded, so no window is proven"
	}
	if b.Source != "prometheus" {
		return false, "the usage is " + b.Basis() + ", not a window of history"
	}
	if h, ok := windowHours(b.Window); !ok || h < 24 {
		return false, "the usage is " + b.Basis() + ", under the day a daily peak needs"
	}
	if b.Confidence != types.UsageConfidenceHigh {
		return false, "the usage is " + b.Basis() + " at " + string(b.Confidence) + " confidence"
	}
	return true, ""
}

// usageStat is the word for the figure the usage gives: a p95 only over a window. One sample is a sample, and the
// word "p95" never appears for it (ENG-04); a VPA's figure is its target.
func usageStat(opts Options) string {
	if b := opts.UsageBasis; b != nil {
		switch {
		case b.Source == "vpa":
			return "VPA target"
		case b.Window == "instant":
			return "one-moment sample"
		}
	}
	return "p95"
}

// windowHours reads a window as the usage provider writes it: "7d", "36h", "45m". "under 1h" and anything else
// is not a span this can prove.
func windowHours(w string) (float64, bool) {
	w = strings.TrimSpace(w)
	if len(w) < 2 {
		return 0, false
	}
	var n float64
	if _, err := fmt.Sscanf(w[:len(w)-1], "%g", &n); err != nil || n < 0 {
		return 0, false
	}
	switch w[len(w)-1] {
	case 'd':
		return n * 24, true
	case 'h':
		return n, true
	case 'm':
		return n / 60, true
	}
	return 0, false
}

// workloadKey names a workload across the indexes below.
type workloadKey struct{ kind, ns, name string }

// governance is what the autoscalers targeting one workload scale on: per resource, the containers whose
// utilization they hold ("" is every container), with the sentence that says so.
type governance map[corev1.ResourceName]map[string]string

// governs reports whether the request of resource in container is governed, and why.
func (g governance) governs(res corev1.ResourceName, container string) (string, bool) {
	if why, ok := g[res][""]; ok {
		return why, true
	}
	why, ok := g[res][container]
	return why, ok
}

// autoscaled indexes every HorizontalPodAutoscaler by its scale target. An autoscaler governs a dimension's
// request when it scales on that dimension's UTILIZATION — usage as a share of the request. A target in absolute
// units (AverageValue) does not move with the request and governs nothing here. An autoscaler with no metrics
// scales on CPU at 80%, the API's default.
func autoscaled(inv *collect.Inventory) map[workloadKey]governance {
	out := map[workloadKey]governance{}
	for i := range inv.HPAs {
		h := &inv.HPAs[i]
		k := workloadKey{h.Spec.ScaleTargetRef.Kind, h.Namespace, h.Spec.ScaleTargetRef.Name}
		add := func(res corev1.ResourceName, container string, target *int32) {
			if out[k] == nil {
				out[k] = governance{}
			}
			if out[k][res] == nil {
				out[k][res] = map[string]string{}
			}
			at := ""
			if target != nil {
				at = fmt.Sprintf(" (target %d%%)", *target)
			}
			scope := "its " + strings.ToUpper(string(res))
			if res == corev1.ResourceMemory {
				scope = "its memory"
			}
			if container != "" {
				scope += " in container " + container
			}
			out[k][res][container] = fmt.Sprintf("HorizontalPodAutoscaler %s/%s scales this %s on %s utilization%s; a lower request "+
				"raises that utilization and the autoscaler adds replicas to bring it back, so the same capacity stays reserved "+
				"and the change saves nothing", h.Namespace, h.Name, k.kind, scope, at)
		}
		if len(h.Spec.Metrics) == 0 {
			eighty := int32(80)
			add(corev1.ResourceCPU, "", &eighty)
			continue
		}
		for _, m := range h.Spec.Metrics {
			switch {
			case m.Resource != nil && m.Resource.Target.Type == autoscalingv2.UtilizationMetricType:
				add(m.Resource.Name, "", m.Resource.Target.AverageUtilization)
			case m.ContainerResource != nil && m.ContainerResource.Target.Type == autoscalingv2.UtilizationMetricType:
				add(m.ContainerResource.Name, m.ContainerResource.Container, m.ContainerResource.Target.AverageUtilization)
			}
		}
	}
	return out
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

// replicaPricer prices a replica on the node it runs on (ENG-02): reclaim × that node's monthly price ÷ its
// allocatable. The dominant node type used to stand in for every node, so in a mixed cluster a replica on a cheap
// pool was priced at the expensive one's rate and the "upper bound" held in neither direction.
type replicaPricer struct {
	nodes map[string]nodePrice
}

// nodePrice is one node's price and allocatable; priced is false for a node the price table does not know.
type nodePrice struct {
	itype      string
	allocCPUm  int64
	allocMemB  int64
	monthlyUSD float64
	priced     bool
}

func newReplicaPricer(inv *collect.Inventory, opts Options) replicaPricer {
	provider := providerFromNodes(inv.Nodes) // one cloud per cluster
	p := replicaPricer{nodes: make(map[string]nodePrice, len(inv.Nodes))}
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		itype := n.Labels[labelInstanceType]
		// SHARED classifier — identical to the collect seam so both seams agree on whether a node is spot.
		monthly, ok := opts.nodeMonthly(provider, collect.RegionOf(*n), itype, collect.ClassifyCapacityType(provider, *n))
		np := nodePrice{itype: itype, allocCPUm: n.Status.Allocatable.Cpu().MilliValue(),
			allocMemB: n.Status.Allocatable.Memory().Value(), monthlyUSD: monthly}
		np.priced = ok && np.allocCPUm > 0 && np.allocMemB > 0
		p.nodes[n.Name] = np
	}
	return p
}

// price is the monthly upper bound for reclaiming cpuM millicores and memB bytes on each of replicas replicas, and
// the sentence that shows the sum. Each live pod is priced on its own node, up to the declared count (a pod beyond
// it is a surge, not a replica); a declared replica with no live pod, or a pod on a node the table does not price,
// contributes $0 and is counted: "priced 5 of 6 replicas". The two dimensions are summed separately and the larger
// taken: freeing CPU and memory on the same replica reclaims overlapping node capacity.
func (p replicaPricer) price(w workload, live []corev1.Pod, replicas int, cpuM, memB int64) (float64, string, []types.SpendShare, []types.Fact) {
	sorted := append([]corev1.Pod(nil), live...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	if len(sorted) > replicas {
		sorted = sorted[:replicas]
	}
	var cpuUSD, memUSD float64
	priced := 0
	byType := map[string]int{}
	cpuBy, memBy := map[string]float64{}, map[string]float64{}
	for _, pod := range sorted {
		n, ok := p.nodes[pod.Spec.NodeName]
		if !ok || !n.priced {
			continue
		}
		priced++
		byType[n.itype]++
		c := float64(cpuM) / float64(n.allocCPUm) * n.monthlyUSD
		m := float64(memB) / float64(n.allocMemB) * n.monthlyUSD
		cpuUSD += c
		memUSD += m
		cpuBy[pod.Spec.NodeName] += c
		memBy[pod.Spec.NodeName] += m
	}
	if priced == 0 {
		return 0, fmt.Sprintf("no replica of %s %s/%s runs on a node the price table knows — dollar impact left at $0 (price unknown)",
			w.Kind, w.Namespace, w.Name), nil, []types.Fact{types.NewFact("rightsizing.replicas", replicas), types.NewFact("rightsizing.replicas.priced", 0)}
	}
	dollar, dim, by := cpuUSD, "CPU", cpuBy
	if memUSD > dollar {
		dollar, dim, by = memUSD, "memory", memBy
	}
	shares := make([]types.SpendShare, 0, len(by))
	for n, usd := range by {
		if usd > 0 {
			shares = append(shares, types.SpendShare{Node: n, USD: usd})
		}
	}
	sort.Slice(shares, func(i, j int) bool { return shares[i].Node < shares[j].Node })
	var on []string
	for t, c := range byType {
		on = append(on, fmt.Sprintf("%s ×%d", t, c))
	}
	sort.Strings(on)
	facts := []types.Fact{
		types.NewFact("rightsizing.replicas", replicas), types.NewFact("rightsizing.replicas.priced", priced),
		types.NewFact("rightsizing.reclaim.cpu", cpuM), types.NewFact("rightsizing.reclaim.memory", memB),
		types.NewFact("rightsizing.usd.cpu", cpuUSD), types.NewFact("rightsizing.usd.memory", memUSD),
		types.NewFact("rightsizing.bound", dim),
	}
	return dollar, priceLine(facts, strings.Join(on, ", ")), shares, facts
}

// priceLine is the dollar's sentence, rendered from the facts (M-172): every figure in it is a fact's value. Both
// dimensions are stated only when both reclaim something — a "$0.00" reads as a price that could not be computed.
func priceLine(fs []types.Fact, on string) string {
	cpuUSD, memUSD := types.FactNum(fs, "rightsizing.usd.cpu"), types.FactNum(fs, "rightsizing.usd.memory")
	dim := types.FactStr(fs, "rightsizing.bound")
	dollar := cpuUSD
	if dim == "memory" {
		dollar = memUSD
	}
	both := ""
	if cpuUSD > 0 && memUSD > 0 {
		both = fmt.Sprintf("CPU $%.2f/mo, memory $%.2f/mo, ", cpuUSD, memUSD)
	}
	return fmt.Sprintf(
		"$ model (UPPER BOUND, if consolidated): reclaim %s per replica, each replica priced on its own node's "+
			"price divided by its allocatable (%s); priced %d of %d replicas (a replica with no live pod or on an unpriced "+
			"node adds nothing) -> %s%s-bound up to $%.2f/mo",
		reclaimSaid(int64(types.FactNum(fs, "rightsizing.reclaim.cpu")), int64(types.FactNum(fs, "rightsizing.reclaim.memory"))),
		on, int(types.FactNum(fs, "rightsizing.replicas.priced")), int(types.FactNum(fs, "rightsizing.replicas")), both, dim, dollar)
}

// reclaimSaid names what one replica gives back, leaving out a dimension with nothing to give.
func reclaimSaid(cpuM, memB int64) string {
	switch {
	case cpuM > 0 && memB > 0:
		return millis(cpuM) + " CPU / " + humanMi(memB) + " mem"
	case memB > 0:
		return humanMi(memB) + " mem"
	}
	return millis(cpuM) + " CPU"
}

// podIndex attributes every pod to exactly one workload, once per evaluation (ENG-09). Attribution was a walk of
// every pod per workload, resolving each pod's owner chain by a walk of every Deployment: measured quadratic, 2.6 s
// at 2,000 nodes. The owner index resolves a chain by lookup, and the pods are bucketed by their outermost owner.
type podIndex struct {
	byOwner map[workloadKey][]corev1.Pod
	orphans map[string][]corev1.Pod // namespace → pods with no resolvable controller
}

func newPodIndex(inv *collect.Inventory) podIndex { return newPodIndexWith(inv, newOwnerIndex(inv)) }

func newPodIndexWith(inv *collect.Inventory, idx *ownerIndex) podIndex {
	x := podIndex{byOwner: map[workloadKey][]corev1.Pod{}, orphans: map[string][]corev1.Pod{}}
	for i := range inv.Pods {
		p := inv.Pods[i]
		if chain := idx.chain(p); len(chain) > 0 {
			k := workloadKey{chain[0].Kind, p.Namespace, chain[0].Name}
			x.byOwner[k] = append(x.byOwner[k], p)
			continue
		}
		x.orphans[p.Namespace] = append(x.orphans[p.Namespace], p)
	}
	return x
}

// podsFor returns the pods belonging to w, attributing each pod to EXACTLY ONE workload so usage (and therefore $)
// is never double-counted across two findings.
//
// Primary attribution is by owner reference: the pod's OUTERMOST controller (pod → ReplicaSet → Deployment, or
// pod → StatefulSet/DaemonSet directly) must be this workload. This is exact, and it fixes the label-superset false
// positive where a canary's pod-template labels {app:api} are a subset of a sibling's pod labels
// {app:api,track:stable}. Label-superset matching (pod labels ⊇ the workload's pod-template labels, equality-AND,
// Service selector semantics) is the FALLBACK, only for pods with no resolvable controller owner. An empty
// PodLabels set matches nothing.
func (x podIndex) podsFor(w workload) []corev1.Pod {
	out := append([]corev1.Pod(nil), x.byOwner[workloadKey{w.Kind, w.Namespace, w.Name}]...)
	if len(w.PodLabels) == 0 {
		return out
	}
	sel := labels.SelectorFromSet(labels.Set(w.PodLabels))
	for _, p := range x.orphans[w.Namespace] {
		if sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// podsForWorkload is podsFor over a fresh index, for a caller with one workload to resolve.
func podsForWorkload(inv *collect.Inventory, w workload) []corev1.Pod {
	return newPodIndex(inv).podsFor(w)
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
func maxP95(usage map[string]prom.ContainerUsage, namespace string, pods []string, cname string) containerStats {
	var s containerStats
	for _, pod := range pods {
		key := namespace + "/" + pod + "/" + cname
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
// the recommended values for each flagged container; stat names the figure (p95, one-moment sample, VPA target).
func rightsizingPatch(w workload, recos []containerReco, span, stat string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apps/v1\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      containers:\n", w.Kind, w.Name, w.Namespace)
	for _, rc := range recos {
		fmt.Fprintf(&b, "        - name: %s\n          resources:\n            requests:\n", rc.name)
		if rc.hasCPU {
			fmt.Fprintf(&b, "              cpu: %s      # %s %s ×%.1f, right-sized\n", millis(rc.cpuMillis), span, stat, headroomFactor)
		}
		if rc.hasMem && rc.memFromMax {
			fmt.Fprintf(&b, "              memory: %s  # %s max ×%.2f, right-sized\n", humanMi(rc.memBytes), span, memMaxSafetyFactor)
		} else if rc.hasMem {
			fmt.Fprintf(&b, "              memory: %s  # %s %s ×%.1f, right-sized\n", humanMi(rc.memBytes), span, stat, headroomFactor)
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
// "observed", and "rest on observed of history" is not a sentence. A sample and a VPA target are not a window at
// all, and are said as what they are.
func historyBasis(span string, b *types.UsageMethodology) string {
	switch {
	case b != nil && b.Source == "vpa":
		return "data-quality: the figures above are the VerticalPodAutoscaler's own targets — its estimate of what the " +
			"container needs, not measured usage over a window this reading can state"
	case b != nil && b.Window == "instant":
		return "data-quality: the figures above are one moment's usage from metrics.k8s.io — what each container used " +
			"at the instant it was read, not a window; a quiet moment understates a busy day"
	}
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

// RequiredKinds — Requests come from the templates, the ceiling from the nodes, the observed figures are keyed by pod,
// and the autoscalers say which dimensions are governed (ENG-01).
// See deps.go for what belongs in this list.
func (r Rightsizing) RequiredKinds() []string {
	return withWorkloads("horizontalpodautoscalers", "nodes", "pods")
}

// RequiresUsage — this rule compares declared requests against OBSERVED consumption. With no usage
// source it emits nothing, so a comparison between a run with Prometheus and one without must not read
// the silence as the cluster having been rightsized.
func (r Rightsizing) RequiresUsage() bool { return true }

// NodeMonthlyPrices is every priced node's monthly list price (the ceiling every rule prices at), by name — what
// the pipeline holds the findings' spend shares to (ENG-08). A node the table does not price is absent.
func NodeMonthlyPrices(inv *collect.Inventory, opts Options) map[string]float64 {
	p := newReplicaPricer(inv, opts)
	out := make(map[string]float64, len(p.nodes))
	for name, n := range p.nodes {
		if n.priced {
			out[name] = n.monthlyUSD
		}
	}
	return out
}

// shardSpan is the shorter of the run's span and the window the workload's usage was read over. A namespace is
// never split across shards, so every container of one workload carries one window.
func shardSpan(run string, usage map[string]prom.ContainerUsage, pods []corev1.Pod) string {
	runH, ok := windowHours(run)
	if !ok {
		return run
	}
	for i := range pods {
		for _, c := range pods[i].Spec.Containers {
			u, found := usage[pods[i].Namespace+"/"+pods[i].Name+"/"+c.Name]
			if !found || u.Window == "" {
				continue
			}
			if h, ok := windowHours(u.Window); ok && h < runH {
				return u.Window
			}
			return run
		}
	}
	return run
}

// usageHistory indexes the usage's pod names per namespace, sorted, so a workload's earlier pods are found by prefix.
type usageHistory map[string][]string

func newUsageHistory(usage map[string]prom.ContainerUsage) usageHistory {
	seen := map[string]map[string]bool{}
	for key := range usage {
		// From the key, which every provider writes as namespace/pod/container: the struct's own fields are not
		// filled by every provider.
		parts := strings.SplitN(key, "/", 3)
		if len(parts) != 3 {
			continue
		}
		if seen[parts[0]] == nil {
			seen[parts[0]] = map[string]bool{}
		}
		seen[parts[0]][parts[1]] = true
	}
	h := usageHistory{}
	for ns, pods := range seen {
		names := make([]string, 0, len(pods))
		for p := range pods {
			names = append(names, p)
		}
		sort.Strings(names)
		h[ns] = names
	}
	return h
}

// The names a controller gives its pods, from the alphabet Kubernetes uses for generated names
// (k8s.io/apimachinery/pkg/util/rand.SafeEncodeString: no vowels, no 0, 1 or 3, so no word is ever spelled).
var (
	// A Deployment's pod: <deployment>-<pod-template-hash>-<5>.
	deploymentPodName = regexp.MustCompile(`^[bcdfghjklmnpqrstvwxz2456789]{6,10}-[bcdfghjklmnpqrstvwxz2456789]{5}$`)
	// A DaemonSet's pod: <daemonset>-<5>.
	daemonSetPodName = regexp.MustCompile(`^[bcdfghjklmnpqrstvwxz2456789]{5}$`)
)

// seriesOf is the pod names whose usage belongs to the workload: its live pods, and the earlier pods its controller
// named the same way (a rollout's predecessors), with how many of those there are. A StatefulSet's pods keep their
// names across a rollout, so its live names already carry the history.
func (h usageHistory) seriesOf(w workload, live []corev1.Pod) (names []string, past int) {
	isLive := map[string]bool{}
	for i := range live {
		isLive[live[i].Name] = true
		names = append(names, live[i].Name)
	}
	var shape *regexp.Regexp
	switch w.Kind {
	case "Deployment", "Rollout": // a Rollout names its pods as a Deployment does: <name>-<template hash>-<5>
		shape = deploymentPodName
	case "DaemonSet":
		shape = daemonSetPodName
	default:
		return names, 0
	}
	all := h[w.Namespace]
	prefix := w.Name + "-"
	for i := sort.SearchStrings(all, prefix); i < len(all) && strings.HasPrefix(all[i], prefix); i++ {
		if !isLive[all[i]] && shape.MatchString(all[i][len(prefix):]) {
			names = append(names, all[i])
			past++
		}
	}
	return names, past
}

// youngestSpan is how long before the reading the OLDEST live pod was created: the longest any live series can
// reach back. ok is false when no pod carries a creation time.
func youngestSpan(live []corev1.Pod, reading time.Time) (time.Duration, bool) {
	var oldest time.Time
	for i := range live {
		if t := live[i].CreationTimestamp.Time; !t.IsZero() && (oldest.IsZero() || t.Before(oldest)) {
			oldest = t
		}
	}
	if oldest.IsZero() || reading.IsZero() {
		return 0, false
	}
	return reading.Sub(oldest), true
}

// humanAge is an age in the unit a reader thinks in.
func humanAge(d time.Duration) string {
	if d < time.Hour {
		return nWord(int(d/time.Minute), "minute", "minutes")
	}
	return nWord(int(d/time.Hour), "hour", "hours")
}
