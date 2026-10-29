package prom

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// temporal.go — THE AXIS A SNAPSHOT STRUCTURALLY CANNOT SEE.
//
// Spec: `docs/superpowers/specs/2026-08-29-engine-ceiling-design.md` §6b, added after that spec was
// reviewed against its own §1 test and failed it. The engine is not a snapshot reader — it is a read-only
// client with a SECOND data source — and until this file it issued exactly two queries against that source,
// both for rightsizing. The temporal axis was exploited at roughly five percent.
//
// What lives here is the part of the second source the first one cannot reach at all:
//
//	ALERTS      an alert is a rule plus a time window. Neither is an object.
//	throttling  a container throttled against its own limit leaves no trace on any object.
//	up{}        scrape health is not an object.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// FOUR BOUNDARIES, AND EVERY ONE OF THEM IS LOAD-BEARING
//
//	TIER 1a OR NOTHING. Every signal here is conditional on a source PROVEN to be this cluster's — see
//	provenance.go and B-145, where a query with no cluster selector against a Thanos holding twelve
//	clusters computed a StatefulSet's rightsizing dollars from a different cluster's usage, silently. A
//	temporal claim carries the same defect and reads more confidently, so the gate is the same gate.
//
//	A GAP IN THE SERIES IS NOT A ZERO. Prometheus restarts, retention expires, scrapes fail. A query that
//	returns nothing for a container means UNKNOWN, and the difference has to survive into the finding —
//	which is why every result type here distinguishes "absent from the result" from "present and zero".
//
//	A WINDOW IS PART OF THE CLAIM. "Throttled 43%" without "over 7 days" is not a claim. Every result
//	carries the window it was measured over, as data rather than as prose.
//
//	CUSTOMER-AUTHORED STRINGS GO IN TYPED FIELDS, NEVER INTO GENERATED PROSE. An alert's name, its
//	labels and its annotations are written by the cluster's operators, and interpolating them into a
//	sentence we generate is the injection surface every cluster-controlled string has. They are carried
//	as fields and rendered as data.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// AND THE ONE THE REVIEW ADDED (F-4)
//
// The first draft of §6b called ALERTS "their own declared opinion, currently true". That is one step past
// what it supports — the same shape as reading a published EndpointSlice entry as "receives traffic". A
// firing alert means THE EXPRESSION EVALUATES TRUE, not that the situation it names is real. Alerts are the
// most miscalibrated artifact in most clusters: thresholds set for a cluster three sizes ago, routes into
// dead channels, and firing because an exporter broke rather than the thing it watches.
//
// The supportable claim is "an alerting rule named X is currently firing", and the reader judges calibration.

// TemporalWindow is the lookback these queries span. Shared with usage.go's windowDays deliberately: two
// windows in one document would need reconciling in every sentence that mentions both.
const TemporalWindow = windowDays * 24 * time.Hour

// ── ALERTS ───────────────────────────────────────────────────────────────────────────────────────

// FiringAlert is one alerting rule the source reports as currently firing.
//
// EVERY STRING HERE IS CUSTOMER-AUTHORED except State. They are fields, and a renderer prints them as
// data — never interpolated into a sentence this product generates.
type FiringAlert struct {
	// Name is the `alertname` label. Written by the cluster's operators.
	Name string
	// Severity is the `severity` label if present. A convention, not a guarantee: the label is whatever
	// the rule author typed, and this product neither validates nor ranks it.
	Severity string
	// Namespace is the `namespace` label if the rule carries one. Many cluster-level rules do not.
	Namespace string
	// State is "firing" or "pending" — the ONE field here Prometheus owns rather than the operator.
	State string
	// Count is how many series carry this alertname. A single rule matching forty pods fires forty
	// times, and the count is the honest way to say so without listing forty customer-authored labels.
	Count int
}

// queryAlerts reads the ALERTS series. Instant, not ranged: "currently firing" is a statement about now,
// and a range query would let an alert that resolved six days ago read as active.
const queryAlerts = `ALERTS{alertstate="firing"}`

// Alerts returns the alerting rules currently firing, grouped by name.
//
// AN EMPTY RESULT IS AMBIGUOUS AND IS RETURNED AS SUCH. A cluster with no firing alerts and a cluster whose
// Prometheus has no alerting rules loaded at all produce the identical empty vector, and "nothing is firing"
// would be an absence rendered as reassurance. The bool reports whether the ALERTS series exists at all,
// which is the only thing that separates the two.
func (c *Client) Alerts(ctx context.Context) (alerts []FiringAlert, seriesExists bool, err error) {
	firing, err := c.Query(ctx, queryAlerts)
	if err != nil {
		return nil, false, fmt.Errorf("prom: alerts: %w", err)
	}
	// The probe asks whether the series exists in ANY state. A cluster with rules loaded and nothing
	// firing answers this and not the query above; a cluster with no rules answers neither.
	any, err := c.Query(ctx, `ALERTS`)
	if err != nil {
		return nil, false, fmt.Errorf("prom: alerts probe: %w", err)
	}
	seriesExists = len(any) > 0

	byName := map[string]*FiringAlert{}
	for _, s := range firing {
		name := s.Metric["alertname"]
		if name == "" {
			continue
		}
		key := name + "|" + s.Metric["namespace"]
		a := byName[key]
		if a == nil {
			a = &FiringAlert{
				Name:      name,
				Severity:  s.Metric["severity"],
				Namespace: s.Metric["namespace"],
				State:     "firing",
			}
			byName[key] = a
		}
		a.Count++
	}
	for _, a := range byName {
		alerts = append(alerts, *a)
	}
	sortAlerts(alerts)
	return alerts, seriesExists, nil
}

func sortAlerts(a []FiringAlert) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && less(a[j], a[j-1]); j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func less(x, y FiringAlert) bool {
	if x.Name != y.Name {
		return x.Name < y.Name
	}
	return x.Namespace < y.Namespace
}

// ── CPU THROTTLING ───────────────────────────────────────────────────────────────────────────────

// Throttling is one container's CFS throttling over the window.
type Throttling struct {
	Namespace, Pod, Container string
	// Ratio is throttled periods over total periods, in [0,1]. Present only when BOTH series were
	// returned for this container — a throttled count with no period count is not a ratio.
	Ratio float64
	// Periods is the denominator, carried because a ratio over a handful of periods is noise. A reader
	// cannot judge 100% throttled without knowing whether that was three periods or three million.
	Periods float64
}

// The two halves of the ratio. Throttling is only meaningful for a container that HAS a CPU limit: the CFS
// quota is what does the throttling, and a container without one is never throttled by definition. That
// filter is applied by the caller against the object graph rather than here, because the limit is a spec
// field and this package does not read objects.
const (
	queryThrottledPeriods = `sum by (namespace, pod, container) (increase(container_cpu_cfs_throttled_periods_total{container!="",container!="POD"}[7d]))`
	queryTotalPeriods     = `sum by (namespace, pod, container) (increase(container_cpu_cfs_periods_total{container!="",container!="POD"}[7d]))`
)

// Throttling7d returns per-container CFS throttling over the window, keyed "namespace/pod/container".
//
// A CONTAINER ABSENT FROM THE MAP IS UNKNOWN, NEVER UNTHROTTLED. cAdvisor does not export the CFS series
// at all when the container has no CPU limit, and a missing series is indistinguishable from a scrape gap
// from here — so both are absence, and the caller must not read absence as zero.
func (c *Client) Throttling7d(ctx context.Context) (map[string]Throttling, error) {
	throttled, err := c.Query(ctx, queryThrottledPeriods)
	if err != nil {
		return nil, fmt.Errorf("prom: throttled periods: %w", err)
	}
	total, err := c.Query(ctx, queryTotalPeriods)
	if err != nil {
		return nil, fmt.Errorf("prom: total periods: %w", err)
	}
	totals := map[string]float64{}
	for _, s := range total {
		if k, _, _, _ := containerKeyOf(s.Metric); k != "" {
			totals[k] = s.Value
		}
	}
	out := map[string]Throttling{}
	for _, s := range throttled {
		k, ns, pod, ctr := containerKeyOf(s.Metric)
		if k == "" {
			continue
		}
		den, ok := totals[k]
		// BOTH HALVES OR NOTHING. A throttled count without its denominator is not a ratio, and
		// inventing one — or defaulting the denominator — would produce a percentage nothing measured.
		if !ok || den <= 0 {
			continue
		}
		r := s.Value / den
		if r > 1 {
			// Two `increase()` results over the same window can disagree slightly at the edges. A ratio
			// above 1 is that artifact, not 140% throttling, and clamping is honest where reporting it
			// would not be.
			r = 1
		}
		out[k] = Throttling{
			Namespace: ns, Pod: pod, Container: ctr,
			Ratio: r, Periods: den,
		}
	}
	return out, nil
}

// containerKeyOf is usage.go's containerKey, joined. DELEGATING RATHER THAN RE-EXTRACTING: the version in
// usage.go tolerates older kube-state-metrics label names (pod_name / container_name) and the `exported_`
// prefix a federated or Thanos-fronted source adds, and a second extractor written here would have been
// silently blind to both — on exactly the topologies B-145 was about.
func containerKeyOf(m map[string]string) (string, string, string, string) {
	ns, pod, ctr := containerKey(m)
	if ns == "" || pod == "" || ctr == "" {
		return "", "", "", ""
	}
	return ns + "/" + pod + "/" + ctr, ns, pod, ctr
}

// ── SCRAPE HEALTH ────────────────────────────────────────────────────────────────────────────────

// ScrapeHealth is what the monitoring stack can and cannot reach.
//
// THIS IS A FACT ABOUT THE MONITORING STACK, NOT ABOUT THE WORKLOADS. A target that is down means the
// scrape failed; whether the thing behind it is healthy is a different question this cannot answer, and
// the two are opposite conclusions when an exporter dies beside a working service.
type ScrapeHealth struct {
	// Up and Down are target counts. Both zero with SeriesExists true means the source scrapes nothing.
	Up, Down int
	// DownJobs names the `job` label of failing targets, with a count each. Customer-authored strings,
	// carried as data.
	DownJobs map[string]int
	// SeriesExists separates "no targets are down" from "up{} is not exported here", which produce the
	// identical empty result.
	SeriesExists bool
}

const queryUp = `up`

// Scrape returns target health as the source itself reports it.
func (c *Client) Scrape(ctx context.Context) (ScrapeHealth, error) {
	rows, err := c.Query(ctx, queryUp)
	if err != nil {
		return ScrapeHealth{}, fmt.Errorf("prom: up: %w", err)
	}
	h := ScrapeHealth{DownJobs: map[string]int{}, SeriesExists: len(rows) > 0}
	for _, s := range rows {
		if s.Value >= 1 {
			h.Up++
			continue
		}
		h.Down++
		job := s.Metric["job"]
		if job == "" {
			job = "(no job label)"
		}
		h.DownJobs[job]++
	}
	return h, nil
}

// ── the bundle the pipeline threads to the rules ─────────────────────────────────────────────────

// Temporal is every signal from the second source that a snapshot cannot produce.
//
// A NIL *Temporal MEANS NOT ASSESSED, and that is a third state distinct from "assessed and clean". The
// rules that read it are silent on nil, and Methodology names the reason — no source, or a source that
// could not be proven to be this cluster's.
type Temporal struct {
	// Window is what every measurement here spans. Carried so a finding states it rather than assuming it.
	Window time.Duration

	// Covered is how much history Prometheus actually holds, when HistoryCoverage managed to probe it, and
	// CoverageKnown says whether it did. Window is what the QUERIES ask for; Prometheus answers them over
	// whatever it has, so on a six-hour-old Prometheus every temporal claim said "7-day window ending at
	// this reading" — a quiet afternoon described as a quiet week (M-127). WindowText names the shorter.
	Covered       time.Duration
	CoverageKnown bool

	Alerts       []FiringAlert
	AlertsSeries bool

	Throttling map[string]Throttling
	Scrape     ScrapeHealth
}

// FetchTemporal runs the temporal queries against a proven source.
//
// IT REFUSES AN UNPROVEN ONE RATHER THAN DEGRADING. Tier 1b is the B-145 state: a source answered and
// nothing establishes it is this cluster's. Rightsizing withholds its figures there; a temporal claim reads
// more confidently than a dollar figure and would be wrong the same way, so it refuses on the same test.
func FetchTemporal(ctx context.Context, c *Client, p Provenance) (*Temporal, error) {
	if c == nil || !p.Proven() {
		return nil, nil
	}
	t := &Temporal{Window: TemporalWindow}
	// The same probe the usage path uses, for the same reason: these queries ask for a week and Prometheus
	// answers over whatever history it holds. WindowText names the shorter of the two (M-127).
	if cov, known := c.HistoryCoverage(ctx); known {
		t.Covered, t.CoverageKnown = cov, true
	}
	alerts, exists, err := c.Alerts(ctx)
	if err != nil {
		return nil, err
	}
	t.Alerts, t.AlertsSeries = alerts, exists

	th, err := c.Throttling7d(ctx)
	if err != nil {
		return nil, err
	}
	t.Throttling = th

	sh, err := c.Scrape(ctx)
	if err != nil {
		return nil, err
	}
	t.Scrape = sh
	return t, nil
}

// WindowText renders the window for a finding's evidence. One spelling, so two findings never describe the
// same window two ways.
func (t *Temporal) WindowText() string {
	if t == nil {
		return ""
	}
	span := t.Window
	if t.CoverageKnown && t.Covered < span {
		span = t.Covered
	}
	d := int(span.Hours() / 24)
	if d >= 1 {
		return strconv.Itoa(d) + "-day window ending at this reading"
	}
	// "6h0m0s" reads as a machine's answer; trim the empty tail units so the sentence says 6h.
	txt := strings.TrimSuffix(span.String(), "0s")
	txt = strings.TrimSuffix(txt, "0m")
	return txt + " window ending at this reading"
}
