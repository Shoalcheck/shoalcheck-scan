package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The under-provisioned half (ENG-52). Rightsizing finds requests above what a workload uses; this finds the other
// side, where the usage source shows a container above what it reserved:
//   - CPU p95 above the request: the scheduler placed the pod by its request, so at its peak it runs on room the node
//     promised to other pods, and is throttled first when the node is full;
//   - memory max near the limit: the kernel kills the container when it reaches the limit;
//   - memory p95 above the request: the node can be overcommitted on memory, and a pod above its request is among
//     the first the kubelet evicts under pressure.
//
// NO DOLLARS. Raising a request costs money, but whether the cluster has the room already is the capacity table's
// question, and a cost stated for fixing a risk would read as a saving. A dimension an autoscaler governs is left
// out: running above the request is what its target is for.
type UnderProvisioned struct{}

func (UnderProvisioned) ID() string      { return "k8s.reliability.under-provisioned-requests" }
func (UnderProvisioned) Version() string { return "1.0.0" }

func (UnderProvisioned) RequiredKinds() []string {
	return withWorkloads("pods", "horizontalpodautoscalers")
}

const (
	underCPUFactor   = 1.2  // p95 at least 20% over the request …
	underCPUFloorM   = 50.0 // … and at least 50 millicores over it
	underMemFactor   = 1.2
	underMemLimitPct = 0.9 // a memory max at 90% of the limit or more
)

func (r UnderProvisioned) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if opts.Usage == nil || !observed(inv, "pods") {
		return nil
	}
	pods := derived(inv, opts).podIndex()
	hpas := autoscaled(inv)
	history := newUsageHistory(opts.Usage)
	runSpan := usageSpan(opts)
	stat := usageStat(opts)
	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		live := pods.podsFor(w)
		if len(live) == 0 {
			continue
		}
		names, _ := history.seriesOf(w, live)
		span := shardSpan(runSpan, opts.Usage, live)
		governed := hpas[workloadKey{w.Kind, w.Namespace, w.Name}]
		var lines []string
		var facts []types.Fact
		worst := types.SeverityLow
		for _, c := range w.PodSpec.Containers {
			st := maxP95(opts.Usage, w.Namespace, names, c.Name)
			if !st.found {
				continue
			}
			subj := &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
			if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok && q.MilliValue() > 0 {
				req, used := float64(q.MilliValue()), st.cpuP95Cores*1000
				if _, gov := governed.governs(corev1.ResourceCPU, c.Name); !gov && used >= req*underCPUFactor && used-req >= underCPUFloorM {
					fs := []types.Fact{withSubject(types.NewFact("underprov.cpu.used", used), subj), withSubject(types.NewFact("underprov.cpu.request", req), subj)}
					facts = append(facts, fs...)
					lines = append(lines, underCPULine(c.Name, span, stat, fs))
				}
			}
			if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok && q.Value() > 0 && st.memMaxBytes > 0 {
				lim := float64(q.Value())
				if st.memMaxBytes >= lim*underMemLimitPct {
					fs := []types.Fact{withSubject(types.NewFact("underprov.memory.max", st.memMaxBytes), subj), withSubject(types.NewFact("underprov.memory.limit", lim), subj)}
					facts = append(facts, fs...)
					lines = append(lines, underLimitLine(c.Name, span, fs))
					worst = types.SeverityMedium
				}
			}
			if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok && q.Value() > 0 {
				req := float64(q.Value())
				if _, gov := governed.governs(corev1.ResourceMemory, c.Name); !gov && st.memP95Bytes >= req*underMemFactor {
					fs := []types.Fact{withSubject(types.NewFact("underprov.memory.used", st.memP95Bytes), subj), withSubject(types.NewFact("underprov.memory.request", req), subj)}
					facts = append(facts, fs...)
					lines = append(lines, underMemLine(c.Name, span, stat, fs))
				}
			}
		}
		if len(lines) == 0 {
			continue
		}
		sort.Strings(lines)
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("%s %s/%s uses more than it reserved", w.Kind, w.Namespace, w.Name),
			Description: fmt.Sprintf("The usage source shows %s %s/%s above what its containers request or near what they "+
				"may use at most. The scheduler places a pod by its request, so the cluster's free room is counted as if this "+
				"workload used less than it does.", w.Kind, w.Namespace, w.Name),
			WhyItMatters: "A container above its CPU request is throttled first when its node is full; one above its memory " +
				"request is among the first evicted under memory pressure; one at its memory limit is killed by the kernel.",
			Evidence: append(append([]string{snapshotNote(inv)}, lines...),
				"no dollar is stated: raising a request costs money only if the cluster lacks the room, which the capacity table shows"),
			Facts:             facts,
			Severity:          worst,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        underConfidence(opts),
			Provenance:        provenance(),
		})
	}
	return out
}

// underConfidence is the rule's confidence by its usage source: a measured window is a fact; one moment or a VPA's
// estimate is a lead.
func underConfidence(opts Options) float64 {
	if ok, _ := usageBanks(opts); ok {
		return 0.9
	}
	return 0.5
}

// The rule's sentences, each rendered from its facts (M-172).
func underCPULine(container, span, stat string, fs []types.Fact) string {
	return fmt.Sprintf("container %s: CPU %s %s is %s against a request of %s — at its peak it runs on room the node promised to other pods",
		container, spanWord(span, stat), stat, millis(int64(types.FactNum(fs, "underprov.cpu.used"))), millis(int64(types.FactNum(fs, "underprov.cpu.request"))))
}

func underMemLine(container, span, stat string, fs []types.Fact) string {
	return fmt.Sprintf("container %s: memory %s %s is %s against a request of %s — under memory pressure it is among the first evicted",
		container, spanWord(span, stat), stat, humanMi(int64(types.FactNum(fs, "underprov.memory.used"))), humanMi(int64(types.FactNum(fs, "underprov.memory.request"))))
}

func underLimitLine(container, span string, fs []types.Fact) string {
	max, lim := types.FactNum(fs, "underprov.memory.max"), types.FactNum(fs, "underprov.memory.limit")
	return fmt.Sprintf("container %s: memory max over %s is %s, %.0f%% of its %s limit — the kernel kills the container at the limit",
		container, span, humanMi(int64(max)), 100*max/lim, humanMi(int64(lim)))
}

// spanWord is the span said before a statistic: "7d" before "p95", nothing before "one-moment sample".
func spanWord(span, stat string) string {
	if stat != "p95" || strings.TrimSpace(span) == "" {
		return "(" + stat + ")"
	}
	return span
}
