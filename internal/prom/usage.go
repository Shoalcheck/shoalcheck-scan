package prom

import (
	"context"
	"fmt"
	"time"
)

// windowDays is the fixed lookback window for Usage7d, in days.
//
// It is intentionally hard-coded to 7. If a cluster's Prometheus retention is
// shorter than 7d the queries below silently observe whatever range is
// available — Prometheus does not error, it just returns fewer points.
//
// That silence used to reach the screen as a false claim: a Prometheus twenty minutes
// old still produced "7d · p95 · HIGH". Detection now exists — HistoryCoverage probes how
// far the series actually reach and Methodology reports the real span — so this constant
// remains the window the QUERIES span, never the window the report claims.
const windowDays = 7

// WindowDays returns the lookback window, in days, that the Usage7d queries span.
//
// This is always 7, and it is NOT the window to display: what the data supports may be
// shorter. Methodology() reconciles the two via HistoryCoverage and reports the honest
// span, downgrading the confidence grade when less than a day of history exists.
func (c *Client) WindowDays() int { return windowDays }

// ContainerUsage is the 7d p95 and max CPU and memory for one container of one
// pod.
//
// A field left at 0 means the corresponding series was genuinely absent from
// Prometheus (e.g. the mem series is missing for a CPU-only sidecar), NOT that
// the observed usage was zero. Callers must treat a container missing from the
// Usage7d map as "no data" rather than substituting 0, and should treat a zero
// field on a present container as "this dimension unobserved".
type ContainerUsage struct {
	Namespace, Pod, Container string
	CPUCoresP95, CPUCoresMax  float64
	MemBytesP95, MemBytesMax  float64
}

// PromQL expressions over a 7d window using standard kube-prometheus-stack
// (cAdvisor) series names. The {container!="",container!="POD"} matcher drops
// the per-pod infra "pause" container and unlabeled cgroup roll-ups.
const (
	queryCPUP95 = `quantile_over_time(0.95, rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[5m])[7d:5m])`
	queryCPUMax = `max_over_time(rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[5m])[7d:5m])`
	queryMemP95 = `quantile_over_time(0.95, container_memory_working_set_bytes{container!="",container!="POD"}[7d])`
	queryMemMax = `max_over_time(container_memory_working_set_bytes{container!="",container!="POD"}[7d])`
)

// Usage7d queries p95 and max CPU (cores) and memory (bytes) per container over
// a 7-day window and joins the four result vectors by (namespace, pod,
// container).
//
// The returned map is keyed by "namespace/pod/container". A container is
// included if it appears in at least one of the four vectors; dimensions whose
// series are absent are left at 0 (see ContainerUsage — 0 means "series
// absent", never observed-zero). Any underlying query error is propagated.
func (c *Client) Usage7d(ctx context.Context) (map[string]ContainerUsage, error) {
	cpuP95, err := c.Query(ctx, queryCPUP95)
	if err != nil {
		return nil, fmt.Errorf("prom: cpu p95: %w", err)
	}
	cpuMax, err := c.Query(ctx, queryCPUMax)
	if err != nil {
		return nil, fmt.Errorf("prom: cpu max: %w", err)
	}
	memP95, err := c.Query(ctx, queryMemP95)
	if err != nil {
		return nil, fmt.Errorf("prom: mem p95: %w", err)
	}
	memMax, err := c.Query(ctx, queryMemMax)
	if err != nil {
		return nil, fmt.Errorf("prom: mem max: %w", err)
	}

	// Merge into a pointer map so the four vectors accumulate into one entry
	// per container (Go map values are not addressable).
	merged := make(map[string]*ContainerUsage)

	// touch returns the entry for a sample's labels, creating it on first use.
	// It returns nil if the label set lacks the (namespace, pod, container)
	// triple required to key it.
	touch := func(m map[string]string) *ContainerUsage {
		ns, pod, container := containerKey(m)
		if ns == "" || pod == "" || container == "" {
			return nil
		}
		key := ns + "/" + pod + "/" + container
		u := merged[key]
		if u == nil {
			u = &ContainerUsage{Namespace: ns, Pod: pod, Container: container}
			merged[key] = u
		}
		return u
	}

	for _, s := range cpuP95 {
		if u := touch(s.Metric); u != nil {
			u.CPUCoresP95 = s.Value
		}
	}
	for _, s := range cpuMax {
		if u := touch(s.Metric); u != nil {
			u.CPUCoresMax = s.Value
		}
	}
	for _, s := range memP95 {
		if u := touch(s.Metric); u != nil {
			u.MemBytesP95 = s.Value
		}
	}
	for _, s := range memMax {
		if u := touch(s.Metric); u != nil {
			u.MemBytesMax = s.Value
		}
	}

	out := make(map[string]ContainerUsage, len(merged))
	for k, u := range merged {
		out[k] = *u
	}
	return out, nil
}

// containerKey extracts (namespace, pod, container) from a metric label set,
// tolerating older kube-state-metrics label names (pod_name / container_name).
func containerKey(m map[string]string) (namespace, pod, container string) {
	namespace = m["namespace"]
	if namespace == "" {
		namespace = m["exported_namespace"]
	}
	pod = m["pod"]
	if pod == "" {
		pod = m["pod_name"]
	}
	if pod == "" {
		pod = m["exported_pod"]
	}
	container = m["container"]
	if container == "" {
		container = m["container_name"]
	}
	if container == "" {
		container = m["exported_container"]
	}
	return namespace, pod, container
}

// promProvider is the Tier-1 UsageProvider: a *Client plus the resolved backend
// flavour and any unmet-auth caveat. Usage delegates to Usage7d (the four 7d
// cAdvisor queries) so the absent-vs-zero contract is preserved unchanged.
type promProvider struct {
	c       *Client
	backend string   // "prometheus" | "thanos" | "mimir" | "amp" | "gmp" | "victoria-metrics"
	caveats []string // unmet-auth / backend-specific notes (e.g. VictoriaMetrics rate() semantics)

	// coverage is how far back the container series actually reach, probed once at
	// resolution, and coverageKnown says whether the probe could tell. See Methodology
	// and HistoryCoverage — the pair exists because "probe failed" and "no data at all"
	// demand opposite behaviour.
	coverage      time.Duration
	coverageKnown bool
}

// newPromProvider wraps a client with its resolved backend flavour, caveats, and the
// probed history coverage.
func newPromProvider(c *Client, backend string, caveats []string, coverage time.Duration, coverageKnown bool) *promProvider {
	return &promProvider{c: c, backend: backend, caveats: caveats, coverage: coverage, coverageKnown: coverageKnown}
}

// coverageLadder is probed from oldest to newest, stopping at the first offset that
// still has data. On a mature cluster that is one query; on a young Prometheus it is a
// handful of cheap instant queries.
var coverageLadder = []struct {
	offset string
	age    time.Duration
}{
	{"6d", 7 * 24 * time.Hour}, // data 6d back ⇒ treat the nominal 7d window as backed
	{"3d", 3 * 24 * time.Hour},
	{"1d", 24 * time.Hour},
	{"6h", 6 * time.Hour},
	{"1h", time.Hour},
	{"15m", 15 * time.Minute},
}

// HistoryCoverage reports how far back the cAdvisor container series actually reach, by
// asking for the metric at decreasing offsets and stopping at the first offset that still
// returns samples.
//
// The second return value is what separates two states that must never be conflated:
//
//	known=false — a probe ERRORED. Genuinely unknown; the caller makes no claim.
//	known=true, d>0 — history reaches at least d back.
//	known=true, d==0 — every probe answered and every one was empty, so history is
//	                   shorter than the smallest rung. This is the WORST case, not an
//	                   unknown one, and it is exactly what a Prometheus installed for the
//	                   audit looks like.
//
// Collapsing that last case into the same zero as a failed probe is how the first version
// of this fix let a thirty-minute-old Prometheus keep its "7d · p95 · HIGH" label — the
// unit tests passed and the live testbed caught it.
//
// This exists because the usage queries span a fixed 7d window and Prometheus evaluates
// them over whatever history it holds, without complaint. The NUMBER is then real while
// the WINDOW is a false claim about how much evidence backs it.
func (c *Client) HistoryCoverage(ctx context.Context) (time.Duration, bool) {
	for _, step := range coverageLadder {
		samples, err := c.Query(ctx, "count("+cAdvisorCPUMetric+" offset "+step.offset+")")
		if err != nil {
			return 0, false
		}
		if len(samples) > 0 {
			return step.age, true
		}
	}
	return 0, true
}

// Usage runs the 7d p95/max queries — the absent-vs-zero map of Usage7d.
func (p *promProvider) Usage(ctx context.Context) (map[string]ContainerUsage, error) {
	return p.c.Usage7d(ctx)
}

// cAdvisorCPUMetric is the series HistoryCoverage probes — the same one the CPU
// queries above read, so coverage describes the data the rightsizing actually uses.
const cAdvisorCPUMetric = "container_cpu_usage_seconds_total"

// Methodology grades Tier 1 as a windowed p95, but it reports the window the data can
// actually support rather than the window the queries ask for.
//
// The queries span a fixed 7d and Prometheus evaluates them over whatever history it
// holds, so a Prometheus started this morning yields a perfectly real number under a
// false label. Where the probed coverage falls short of the nominal window, the reported
// Window becomes the real span, a caveat names the shortfall, and anything under a day is
// downgraded out of "high" — a sub-day sample cannot represent a weekly peak, which is
// the whole point of taking a p95 over a week.
func (p *promProvider) Methodology() UsageMethodology {
	nominalDays := p.c.WindowDays()
	window := fmt.Sprintf("%dd", nominalDays)
	confidence := UsageConfidenceHigh
	caveats := p.caveats

	nominal := time.Duration(nominalDays) * 24 * time.Hour
	if p.coverageKnown && p.coverage < nominal {
		shortest := coverageLadder[len(coverageLadder)-1].age
		span := humanizeSpan(p.coverage)
		if p.coverage == 0 {
			// Every rung answered and every rung was empty: shorter than the smallest one.
			span = "under " + humanizeSpan(shortest)
		}
		window = span
		caveats = append(append([]string{}, caveats...), fmt.Sprintf(
			"Prometheus holds %s of history, not the %dd the queries span — the p95 is computed over that shorter period.",
			span, nominalDays))
		if p.coverage < 24*time.Hour {
			confidence = UsageConfidenceLow
		}
	}

	return UsageMethodology{
		Source:     "prometheus",
		Backend:    p.backend,
		Confidence: confidence,
		Window:     window,
		Caveats:    caveats,
	}
}

// humanizeSpan renders a probed coverage span the way the report speaks about windows.
func humanizeSpan(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
}

// presence-probe queries. A reachable endpoint that returns an EMPTY vector here
// (GMP curated subset) has no usable container/KSM series — the resolver then
// falls through to Tier 2/3 rather than producing a fake near-zero rightsizing.
const (
	probeContainerCPU = `count(container_cpu_usage_seconds_total)`
	probeKSMRequests  = `count(kube_pod_container_resource_requests)`
)

// hasContainerMetrics returns true only when BOTH the cAdvisor container CPU
// series and the kube-state-metrics requests series are present (non-empty).
func hasContainerMetrics(ctx context.Context, c *Client) (bool, error) {
	cpu, err := c.Query(ctx, probeContainerCPU)
	if err != nil {
		return false, err
	}
	ksm, err := c.Query(ctx, probeKSMRequests)
	if err != nil {
		return false, err
	}
	return len(cpu) > 0 && len(ksm) > 0, nil
}
