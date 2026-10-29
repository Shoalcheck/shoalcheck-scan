package rules

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// temporal.go — the rules that read the second data source's time axis.
//
// Spec: `docs/superpowers/specs/2026-08-29-engine-ceiling-design.md` §6b.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE OBJECTION, AND WHY IT DOES NOT HOLD
//
// Addendum A demotes findings a monitoring stack already shows, and these come FROM that stack. The
// objection is obvious and it fails for a specific reason: WE DO NOT SHOW THEM THE METRIC, WE SHOW THEM THE
// QUESTION HAVING BEEN ASKED. Nobody has a dashboard panel per container for CFS throttling. The value is
// not the series; it is that all of them were checked and only the ones that matter are named.
//
// Every finding here says so in its own evidence: this came from your Prometheus, over this window.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS FAMILY REFUSES
//
//	NEVER A CAUSE. Throttling is a fact. That it caused a user-visible slowdown is not, and the gap
//	between them is the same gap as between "published in an EndpointSlice" and "served a request".
//
//	NEVER "YOUR ALERT IS RIGHT". A firing alert means the EXPRESSION EVALUATES TRUE — not that the
//	situation it names is real. Alerts are the most miscalibrated artifact in most clusters: thresholds
//	set for a cluster three sizes ago, and firing because an exporter broke rather than the thing it
//	watches. The supportable claim is "an alerting rule named X is currently firing".
//
//	NEVER A CUSTOMER-AUTHORED STRING INSIDE A GENERATED SENTENCE. Alert names, severities and job labels
//	are written by the cluster's operators. They reach the report as evidence lines that are plainly
//	quoted data, never interpolated into a Title or a WhyItMatters.
//
//	NIL Temporal IS SILENCE. Not assessed is not clean, and the methodology carries the reason.

// ── Rule: the cluster's own operators declared something wrong, and it is firing ─────────────────

// AlertsFiring reports the alerting rules the cluster's own monitoring says are currently firing.
type AlertsFiring struct{}

func (AlertsFiring) ID() string      { return "k8s.observed.alerts-firing" }
func (AlertsFiring) Version() string { return "1.0.0" }

// RequiredKinds is EMPTY and RequiresUsage is TRUE, which together are the honest declaration.
//
// This claim rests on the metrics source and on NO collector step — naming a kind it does not read would
// make the comparison withhold whenever an unrelated list was denied, and would be false besides. The
// dependency system already has the right vocabulary for this: Dependencies.Usage, which the comparison
// reads through RunBasis.UsageSource. A source that resolved last time and did not resolve this time makes
// this finding vanish, and Usage:true is what stops that vanishing being reported as a fix.
func (AlertsFiring) RequiredKinds() []string { return nil }

// RequiresUsage — the metrics source IS this rule's input.
func (AlertsFiring) RequiresUsage() bool { return true }

func (r AlertsFiring) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	if t == nil || len(t.Alerts) == 0 {
		return nil
	}
	total := 0
	var lines []string
	for _, a := range t.Alerts {
		total += a.Count
		// THE ALERT'S OWN STRINGS, QUOTED AS DATA. Name and severity are written by the cluster's
		// operators; they are shown, and they are visibly theirs.
		scope := "cluster-wide"
		if a.Namespace != "" {
			scope = "namespace " + a.Namespace
		}
		sev := a.Severity
		if sev == "" {
			sev = "no severity label"
		}
		lines = append(lines, fmt.Sprintf("alertname=%q severity=%q — %s, %d series firing",
			a.Name, sev, scope, a.Count))
	}
	sort.Strings(lines)

	evidence := append([]string{
		snapshotNote(inv),
		fmt.Sprintf("read from this cluster's own Prometheus, %s", t.WindowText()),
	}, lines...)
	evidence = append(evidence,
		"A FIRING ALERT MEANS THE EXPRESSION EVALUATES TRUE. It does not mean the situation the rule "+
			"names is real: alert thresholds are the most miscalibrated artifact in most clusters, and a "+
			"rule fires just as loudly when its exporter breaks as when its subject does.",
		"the rule names and severities above are written by this cluster's operators and are shown as "+
			"they were read; this reading neither validates nor ranks them",
		"whether anyone is reached when these fire is not visible from here — a route to a dead channel "+
			"and a route to a working one look identical from the series")

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "alerts-firing"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "alerts-firing"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s in this cluster %s firing right now",
			nWord(len(t.Alerts), "alerting rule", "alerting rules"), pick(len(t.Alerts), "is", "are")),
		Description: fmt.Sprintf("This cluster's own monitoring reports %s in a "+
			"firing state, across %d series. These are the operators' own declared thresholds, read from "+
			"their Prometheus rather than judged by this reading.", nWord(len(t.Alerts), "distinct alerting rule", "distinct alerting rules"), total),
		WhyItMatters: "An alert is a rule plus a time window, and neither is an object — so nothing in a " +
			"snapshot of this cluster can see it. What is listed here is what the people who run this " +
			"cluster already decided was worth waking someone for.",
		Evidence:        evidence,
		Severity:        types.SeverityMedium,
		Category:        types.CategoryReliability,
		EstimatedEffort: types.EffortMedium,
		Confidence:      1.0,
		Provenance:      provenance(),
	}}
}

// ── Rule: throttled against its own limit ────────────────────────────────────────────────────────

// throttleFloor is the ratio at which throttling stops being ordinary. A container at its limit is
// throttled a little essentially always; the number that means something is sustained.
const throttleFloor = 0.25

// minThrottlePeriods is the denominator below which a ratio is noise. 100% of three periods is not a fact
// about a workload, and a reader cannot tell that from a percentage alone.
const minThrottlePeriods = 1000

// ContainerThrottled reports containers that spent a large share of their CPU periods throttled.
type ContainerThrottled struct{}

func (ContainerThrottled) ID() string      { return "k8s.observed.cpu-throttled" }
func (ContainerThrottled) Version() string { return "1.0.0" }

// RequiredKinds names pods because the finding NAMES pods — and because the CPU limit that does the
// throttling is a spec field this rule reads to avoid reporting a container that has no limit at all.
func (ContainerThrottled) RequiredKinds() []string { return sortedKinds([]string{"pods"}) }

// RequiresUsage — the throttling ratio comes from the metrics source; the pods only say which containers
// have a limit for it to be measured against.
func (ContainerThrottled) RequiresUsage() bool { return true }

func (r ContainerThrottled) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	if t == nil || len(t.Throttling) == 0 || !observed(inv, "pods") {
		return nil
	}
	type hit struct {
		key   string
		ratio float64
		ctr   string
		ns    string
		pod   string
		limit string
	}
	var hits []hit
	noLimit := 0
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		for j := range p.Spec.Containers {
			c := &p.Spec.Containers[j]
			key := p.Namespace + "/" + p.Name + "/" + c.Name
			th, ok := t.Throttling[key]
			// A CONTAINER ABSENT FROM THE MAP IS UNKNOWN, NEVER UNTHROTTLED. cAdvisor does not export the
			// CFS series when a container has no CPU limit, and a scrape gap looks identical from here.
			if !ok || th.Periods < minThrottlePeriods || th.Ratio < throttleFloor {
				continue
			}
			lim, has := c.Resources.Limits[corev1.ResourceCPU]
			if !has {
				// THROTTLING WITHOUT A LIMIT IS A CONTRADICTION IN OUR OWN READING, not a finding. The CFS
				// quota is what throttles, so a container with no limit cannot be throttled by one — and a
				// series saying otherwise means the pod was recreated with different spec inside the
				// window, or the series belongs to a different container of the same name. Counted and
				// disclosed rather than reported as a fact.
				noLimit++
				continue
			}
			hits = append(hits, hit{key: key, ratio: th.Ratio, ctr: c.Name,
				ns: p.Namespace, pod: p.Name, limit: lim.String()})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].ratio != hits[j].ratio {
			return hits[i].ratio > hits[j].ratio
		}
		return hits[i].key < hits[j].key
	})

	var lines []string
	var refs []types.ResourceRef
	for _, h := range hits {
		lines = append(lines, fmt.Sprintf("%s/%s container %s: throttled in %.0f%% of its CPU periods, "+
			"against its own limit of %s", h.ns, h.pod, h.ctr, h.ratio*100, h.limit))
		refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: h.ns, Name: h.pod})
	}
	evidence := append([]string{
		snapshotNote(inv),
		fmt.Sprintf("read from this cluster's own Prometheus, %s, from the CFS period counters cAdvisor "+
			"exports", t.WindowText()),
	}, lines...)
	if noLimit > 0 {
		evidence = append(evidence, fmt.Sprintf("%s had throttling series but declare no CPU "+
			"limit in this reading and are NOT reported: the CFS quota is what throttles, so either the pod "+
			"was recreated with a different spec inside the window or the series belongs to a different "+
			"container of the same name", nWord(noLimit, "container", "containers")))
	}
	evidence = append(evidence,
		"a container at its limit is throttled a little essentially always; what is listed here is "+
			fmt.Sprintf("sustained — at or above %.0f%% of periods, over at least %d periods",
				throttleFloor*100, minThrottlePeriods),
		"THROTTLING IS A FACT AND ITS CONSEQUENCE IS NOT. Whether any of this reached a user, a timeout "+
			"or a queue is not visible from these series and is not claimed",
		"a container absent from these series is UNKNOWN rather than unthrottled: cAdvisor exports the "+
			"CFS counters only for containers with a CPU limit, and a scrape gap is indistinguishable "+
			"from that here")

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "cpu-throttled"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "cpu-throttled"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s spent a quarter or more of %s CPU periods throttled",
			nWord(len(hits), "container", "containers"), pick(len(hits), "its", "their")),
		Description: fmt.Sprintf("Over the %s, %s were held at their own CPU limit for at "+
			"least %.0f%% of the scheduler periods they ran in. Throttling leaves no trace on any "+
			"Kubernetes object — it is visible only in the counters the kubelet's cAdvisor exports.",
			t.WindowText(), nWord(len(hits), "container", "containers"), throttleFloor*100),
		WhyItMatters: "A CPU limit does not slow a container down gradually; it stops it for the rest of " +
			"each 100ms period once the quota is spent. Nobody has a dashboard panel per container for " +
			"this, so it is usually discovered by someone chasing a latency graph that has no cause in it.",
		Evidence: evidence,
		Severity: types.SeverityMedium,
		// RELIABILITY, not a new category. types.Category is a CLOSED vocabulary of five, read by the
		// renderer, the filters and the compliance mapping; widening it for one rule would ripple through
		// all three to gain a label. Throttling is a reliability fact under any of the five.
		Category:          types.CategoryReliability,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

// ── Rule: the monitoring stack cannot reach its own targets ──────────────────────────────────────

// ScrapeTargetsDown reports targets this cluster's own Prometheus reports as unreachable.
//
// THE COMPANION TO internal/analyzers/monitoring.go, FROM THE OTHER SIDE. That file reads what is
// CONFIGURED — a ServiceMonitor selecting nothing, a conversion webhook with no endpoint. This one reads
// what the stack itself reports about what it can REACH. Neither can substitute for the other: a perfectly
// configured ServiceMonitor whose target is down looks correct from the objects, and a target that is up
// says nothing about whether anything selected it.
type ScrapeTargetsDown struct{}

func (ScrapeTargetsDown) ID() string      { return "k8s.observed.scrape-targets-down" }
func (ScrapeTargetsDown) Version() string { return "1.0.0" }

// No collector step: scrape health is not an object, which is the whole reason this rule exists. The
// declaration is RequiresUsage instead — see AlertsFiring.RequiredKinds for why that is complete.
func (ScrapeTargetsDown) RequiredKinds() []string { return nil }
func (ScrapeTargetsDown) RequiresUsage() bool     { return true }

func (r ScrapeTargetsDown) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	// SeriesExists separates "no target is down" from "up{} is not exported here". Without it an
	// unexported series would render as a clean scrape surface, which is the absence-as-fact defect.
	if t == nil || !t.Scrape.SeriesExists || t.Scrape.Down == 0 {
		return nil
	}
	jobs := make([]string, 0, len(t.Scrape.DownJobs))
	for j := range t.Scrape.DownJobs {
		jobs = append(jobs, j)
	}
	sort.Strings(jobs)
	var lines []string
	for _, j := range jobs {
		lines = append(lines, fmt.Sprintf("job=%q — %s reporting up=0", j, nWord(t.Scrape.DownJobs[j], "target", "targets")))
	}
	total := t.Scrape.Up + t.Scrape.Down

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "scrape-targets-down"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "scrape-targets-down"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("This cluster's monitoring cannot reach %d of its %d scrape targets",
			t.Scrape.Down, total),
		Description: fmt.Sprintf("The metrics source reports up=0 for %d of the %d targets it is "+
			"configured to scrape. A target that cannot be scraped produces no series, and a rule or "+
			"dashboard built on those series shows a gap rather than an error.",
			t.Scrape.Down, total),
		WhyItMatters: "Scrape health is not an object, so nothing in a snapshot of this cluster reveals " +
			"it. A monitoring stack is the one component that cannot report its own gaps — the thing that " +
			"would tell you a series is missing is the thing that is missing it.",
		Evidence: append(append([]string{
			snapshotNote(inv),
			fmt.Sprintf("read from this cluster's own Prometheus at the moment of this reading; %s "+
				"up, %d down", nWord(t.Scrape.Up, "target", "targets"), t.Scrape.Down)},
			lines...),
			"the job names above are written by whoever configured this stack and are shown as they were read",
			"THIS IS A FACT ABOUT THE MONITORING STACK, NOT ABOUT THE WORKLOADS BEHIND IT. A failed scrape "+
				"and an unhealthy service are opposite conclusions when an exporter dies beside a working "+
				"process, and this reading cannot tell them apart",
			"a target down at this instant may have been up for the rest of the window; up{} is read as an "+
				"instant, not as a duration"),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryReliability,
		EstimatedEffort: types.EffortLow,
		Confidence:      1.0,
		Provenance:      provenance(),
	}}
}

// temporalRuleIDs is every rule in this file, for the tests that assert family-wide properties.
func temporalRuleIDs() []string {
	return []string{
		(AlertsFiring{}).ID(), (ContainerThrottled{}).ID(), (ScrapeTargetsDown{}).ID(),
	}
}
