// servicemap.go is the mesh/CNI telemetry detector + observed-graph builder. It
// lives in package prom (not collect) because it owns the PromQL and emits plain
// types.ObservedEdge structs, keeping collect cycle-free. Every number it
// produces is a SERVER-SIDE aggregate of a real series, read from ONE pinned
// reporter (reporter="destination") so the rate is never double-counted and the
// mTLS posture is never fabricated from the source side's "unknown".
package prom

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// TelemetrySource is the detected mesh/CNI telemetry backend, in priority order.
type TelemetrySource string

const (
	SourceNone     TelemetrySource = ""
	SourceIstio    TelemetrySource = "istio"
	SourceLinkerd  TelemetrySource = "linkerd"
	SourceHubbleL7 TelemetrySource = "hubble-l7"
	SourceHubbleL4 TelemetrySource = "hubble-l4"
	SourceIngress  TelemetrySource = "ingress" // nginx/envoy ingress only
)

// detectProbes is each backend's signature query, in priority order. A non-empty
// result vector means the backend is present. Absent series ⇒ empty vector (not
// error) per Query's contract (TestQuery_EmptyVector), so a missing backend is a
// clean skip, never a failure.
var detectProbes = []struct {
	src   TelemetrySource
	query string
}{
	{SourceIstio, "count(istio_requests_total)"},
	{SourceLinkerd, `count(response_total{direction="outbound"})`},
	{SourceHubbleL7, "count(hubble_http_requests_total)"},
	{SourceHubbleL4, "count(hubble_flows_processed_total)"},
	{SourceIngress, "count(nginx_ingress_controller_requests)"},
}

// DetectTelemetry probes count()>0 of each backend's signature series in
// priority order and returns the FIRST present source. An all-empty cluster
// returns (SourceNone, nil) — absence is a clean, non-error skip so the caller
// falls back to the declared graph. A transport/query error bubbles up so the
// caller leaves the report on Tier-3 declared (degrade-gracefully).
func DetectTelemetry(ctx context.Context, c *Client) (TelemetrySource, error) {
	for _, p := range detectProbes {
		samples, err := c.Query(ctx, p.query)
		if err != nil {
			return SourceNone, err
		}
		if len(samples) > 0 && samples[0].Value > 0 {
			return p.src, nil
		}
	}
	return SourceNone, nil
}

// maxObservedEdges caps the graph to the top-N talkers by req/s after
// aggregation, so a large mesh stays renderable. A Kiali-style rpm floor drops
// noise below ~0.01 rpm (= ~0.000167 rps).
const (
	maxObservedEdges = 60
	minObservedRPS   = 0.01 / 60.0
)

// ObservedGraph is one cluster's server-aggregated traffic graph for a window.
type ObservedGraph struct {
	Source   TelemetrySource
	Window   string    // "5m"
	AsOf     time.Time // query wall-clock — feeds the as-of stamp
	Edges    []types.ObservedEdge
	Reporter string // "destination" — the pinned reporter (trust note)
	Note     string // "" | "mesh present, no traffic in window"

	// NamespacesObserved is how many distinct namespaces actually appeared in the
	// telemetry, source or destination side, excluding endpoints with no namespace
	// (external / unknown clients).
	//
	// It is computed here rather than downstream because types.ObservedEdge carries only
	// "Kind/Name" workload IDs — the namespace labels exist at this layer and nowhere
	// after it. The progress contract's MapBuilt.NamespacesObserved is fed from this.
	NamespacesObserved int
}

// edgeAccum aggregates the per-(response_code) rate rows into one logical edge.
type edgeAccum struct {
	from, to     string
	protocol     string
	totalRPS     float64
	errorRPS     float64
	csp          string // connection_security_policy (mTLS) from destination reporter
	cspMixed     bool   // true once a non-mutual_tls sample is seen ⇒ mTLS=partial
	srcWorkload  string // for the p99 source+dest join key
	dstWorkload  string // for the p99 source+dest join key
	dstNamespace string
}

// BuildObservedGraph runs the server-aggregated PromQL for src and returns the
// edge list, normalized to topology WorkloadNode IDs via resolve. resolve maps a
// (namespace, meshWorkloadName) to a "Kind/Name" WorkloadNode ID, or "" when
// unmapped (then the edge endpoint becomes an explicit external/ node, never
// dropped). window must be >=5m (>=2x the 30s scrape); the caller passes "5m".
//
// Correctness invariants: ONE reporter pinned (reporter="destination"); error %
// is the 5xx slice over total computed in Go from the response_code buckets (one
// round-trip, one denominator); detected-but-empty sets Note and keeps the graph
// observed rather than silently downgrading.
func BuildObservedGraph(ctx context.Context, c *Client, src TelemetrySource,
	window string, resolve func(ns, workload string) string) (*ObservedGraph, error) {

	g := &ObservedGraph{Source: src, Window: window, AsOf: time.Now().UTC(), Reporter: "destination"}

	switch src {
	case SourceIstio:
		if err := buildIstio(ctx, c, window, resolve, g); err != nil {
			return nil, err
		}
	case SourceLinkerd:
		if err := buildLinkerd(ctx, c, window, resolve, g); err != nil {
			return nil, err
		}
	case SourceHubbleL4, SourceHubbleL7:
		if err := buildHubble(ctx, c, src, window, resolve, g); err != nil {
			return nil, err
		}
	default:
		// ingress-only / none: no observed edges built here.
	}

	finalizeGraph(g)
	return g, nil
}

// finalizeGraph applies the rpm floor, sorts by req/s desc, caps to top-N, and
// records the detected-but-empty state honestly.
func finalizeGraph(g *ObservedGraph) {
	kept := g.Edges[:0]
	for _, e := range g.Edges {
		if e.RequestsPerSec >= minObservedRPS {
			kept = append(kept, e)
		}
	}
	g.Edges = kept
	sort.SliceStable(g.Edges, func(i, j int) bool {
		if g.Edges[i].RequestsPerSec != g.Edges[j].RequestsPerSec {
			return g.Edges[i].RequestsPerSec > g.Edges[j].RequestsPerSec
		}
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	if len(g.Edges) > maxObservedEdges {
		g.Edges = g.Edges[:maxObservedEdges]
	}
	if len(g.Edges) == 0 {
		g.Note = "mesh present, no traffic in window"
	}
}

// resolveEndpoint maps a (ns, workload) to a topology ID, or an explicit
// external/ node when unmapped — never dropped, never force-fit (mirrors
// CapacityUnknown / UnpricedNodeTypes honesty).
func resolveEndpoint(resolve func(ns, wl string) string, ns, wl string) string {
	if id := resolve(ns, wl); id != "" {
		return id
	}
	if wl == "" {
		return "unknown/"
	}
	return "external/" + wl
}

// labelOr returns the first non-empty label among keys (canonical-then-fallback,
// to tolerate cross-version label drift).
func labelOr(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func buildIstio(ctx context.Context, c *Client, window string,
	resolve func(ns, wl string) string, g *ObservedGraph) error {

	rateQ := `sum(rate(istio_requests_total{reporter="destination"}[` + window +
		`])) by (source_workload, source_workload_namespace, destination_workload, ` +
		`destination_workload_namespace, destination_service, response_code, connection_security_policy)`
	samples, err := c.Query(ctx, rateQ)
	if err != nil {
		return err
	}

	acc := map[string]*edgeAccum{}
	// Distinct namespaces that actually appeared in the telemetry. Endpoints with no
	// namespace (external or unknown clients) are deliberately not counted, and must not
	// be counted as an empty-string namespace either.
	seenNs := map[string]bool{}
	for _, s := range samples {
		m := s.Metric
		srcWl := labelOr(m, "source_workload", "source_app")
		srcNs := labelOr(m, "source_workload_namespace", "source_namespace")
		dstWl := labelOr(m, "destination_workload", "destination_app")
		dstNs := labelOr(m, "destination_workload_namespace", "destination_namespace")
		if srcNs != "" {
			seenNs[srcNs] = true
		}
		if dstNs != "" {
			seenNs[dstNs] = true
		}
		from := resolveEndpoint(resolve, srcNs, srcWl)
		to := resolveEndpoint(resolve, dstNs, dstWl)
		key := from + "\x00" + to
		a := acc[key]
		if a == nil {
			a = &edgeAccum{from: from, to: to, protocol: "http", srcWorkload: srcWl, dstWorkload: dstWl, dstNamespace: dstNs}
			acc[key] = a
		}
		a.totalRPS += s.Value
		if code := m["response_code"]; len(code) == 3 && code[0] == '5' {
			a.errorRPS += s.Value
		}
		// mTLS from the DESTINATION reporter only. Track whether ANY sample on the
		// edge was non-mutual_tls: a mixed edge (some plaintext rows) must round
		// DOWN to partial, never up to strict (honesty — don't over-claim mTLS).
		if csp := m["connection_security_policy"]; csp != "" {
			if csp == "mutual_tls" {
				if a.csp == "" {
					a.csp = csp
				}
			} else {
				a.cspMixed = true
				if a.csp == "" {
					a.csp = csp
				}
			}
		}
	}

	// p99/p50 join: histogram_quantile over the destination-reporter buckets, le in by().
	p99 := istioQuantile(ctx, c, window, 0.99)
	p50 := istioQuantile(ctx, c, window, 0.50)

	for _, a := range acc {
		e := types.ObservedEdge{
			From: a.from, To: a.to, Protocol: a.protocol,
			RequestsPerSec: a.totalRPS,
			MTLS:           istioMTLS(a.csp, a.cspMixed),
			Source:         string(SourceIstio),
			Window:         window,
			Confidence:     "high",
		}
		if a.totalRPS > 0 {
			e.ErrorRatePct = a.errorRPS / a.totalRPS * 100
		}
		qk := quantileKey(a.srcWorkload, a.dstNamespace, a.dstWorkload)
		e.P99Ms = p99[qk]
		e.P50Ms = p50[qk]
		g.Edges = append(g.Edges, e)
	}
	g.NamespacesObserved = len(seenNs)
	return nil
}

// istioMTLS maps connection_security_policy to the schema's mtls value. A mixed
// edge (mutual_tls seen alongside any non-mutual_tls sample) is "partial", never
// up-rounded to "strict" — encryption was not evidenced for all of the traffic.
func istioMTLS(csp string, mixed bool) string {
	switch csp {
	case "mutual_tls":
		if mixed {
			return "partial"
		}
		return "strict"
	case "none", "":
		return "none"
	default:
		return "partial"
	}
}

// istioQuantile runs a histogram_quantile and returns ms per join key. The
// by() clause and the map key MUST AGREE: both include source_workload so two
// sources to ONE dest do not collapse (last-wins) and misattribute one source's
// latency to another's edge. Key = "srcWl\x00dstNs\x00dstWl". le MUST be inside
// by(). buildIstio looks up with the identical source+dest key.
func istioQuantile(ctx context.Context, c *Client, window string, q float64) map[string]float64 {
	query := "histogram_quantile(" + strconv.FormatFloat(q, 'f', -1, 64) +
		`, sum(rate(istio_request_duration_milliseconds_bucket{reporter="destination"}[` + window +
		`])) by (le, source_workload, destination_workload, destination_workload_namespace))`
	out := map[string]float64{}
	samples, err := c.Query(ctx, query)
	if err != nil {
		return out // missing latency is not fatal — edge keeps zero p99
	}
	for _, s := range samples {
		k := quantileKey(s.Metric["source_workload"],
			s.Metric["destination_workload_namespace"], s.Metric["destination_workload"])
		out[k] = s.Value
	}
	return out
}

// quantileKey is the shared source+dest join key for the latency maps, used by
// BOTH istioQuantile (when building the map) and buildIstio (when looking up),
// so they can never drift.
func quantileKey(srcWl, dstNs, dstWl string) string {
	return srcWl + "\x00" + dstNs + "\x00" + dstWl
}

// buildLinkerd reads response_total{direction="outbound"} keyed by dst workload
// + classification (success|failure) for error %. Destination-reporter trust
// comes from direction="outbound".
//
// HONESTY (mTLS): Linkerd is mTLS-by-default BETWEEN MESHED PODS, but an edge to
// an unmeshed or external endpoint is NOT encrypted, so we must never assert a
// blanket "strict" from the source proxy. We read Linkerd's per-sample tls
// signal (label `tls`, e.g. "true" when the proxy encrypted the connection) and
// require BOTH endpoints to resolve to in-mesh WorkloadNode IDs. mTLS is
// reported "strict" only when every sample for the edge was tls="true" AND both
// ends are in-mesh; otherwise it stays "none" (unknown/unencrypted), never up-
// rounded.
func buildLinkerd(ctx context.Context, c *Client, window string,
	resolve func(ns, wl string) string, g *ObservedGraph) error {

	rateQ := `sum(rate(response_total{direction="outbound"}[` + window +
		`])) by (namespace, dst_deployment, dst_statefulset, dst_namespace, classification, deployment, statefulset, tls)`
	samples, err := c.Query(ctx, rateQ)
	if err != nil {
		return err
	}
	// lAcc carries the same fields as edgeAccum plus the per-edge mTLS evidence:
	// bothMeshed (both endpoints resolved to in-mesh IDs) and allEncrypted (every
	// sample reported tls="true"). A single non-tls sample flips allEncrypted off.
	type lAcc struct {
		from, to           string
		totalRPS, errorRPS float64
		bothMeshed         bool
		allEncrypted       bool
	}
	acc := map[string]*lAcc{}
	// See ObservedGraph.NamespacesObserved — counted in every builder, not just Istio,
	// otherwise a Linkerd cluster reports zero observed namespaces alongside real edges.
	seenNs := map[string]bool{}
	for _, s := range samples {
		m := s.Metric
		srcWl := labelOr(m, "deployment", "statefulset")
		srcNs := m["namespace"]
		dstWl := labelOr(m, "dst_deployment", "dst_statefulset")
		dstNs := labelOr(m, "dst_namespace", "namespace")
		if srcNs != "" {
			seenNs[srcNs] = true
		}
		if dstNs != "" {
			seenNs[dstNs] = true
		}
		// in-mesh iff resolve() returns a topology ID for BOTH endpoints (an
		// unmapped endpoint is external/unknown — its traffic isn't mesh-mTLS).
		bothMeshed := resolve(srcNs, srcWl) != "" && resolve(dstNs, dstWl) != ""
		from := resolveEndpoint(resolve, srcNs, srcWl)
		to := resolveEndpoint(resolve, dstNs, dstWl)
		key := from + "\x00" + to
		a := acc[key]
		if a == nil {
			a = &lAcc{from: from, to: to, bothMeshed: bothMeshed, allEncrypted: true}
			acc[key] = a
		}
		a.bothMeshed = a.bothMeshed && bothMeshed
		// tls="true" is the proxy's "this connection was mTLS-encrypted" signal.
		// Any other value (or absent label) means we cannot claim encryption.
		if m["tls"] != "true" {
			a.allEncrypted = false
		}
		a.totalRPS += s.Value
		if m["classification"] == "failure" {
			a.errorRPS += s.Value
		}
	}
	for _, a := range acc {
		mtls := "none" // default: unknown / not evidenced — never a blanket strict
		if a.bothMeshed && a.allEncrypted {
			mtls = "strict"
		}
		e := types.ObservedEdge{
			From: a.from, To: a.to, Protocol: "http",
			RequestsPerSec: a.totalRPS,
			MTLS:           mtls,
			Source:         string(SourceLinkerd),
			Window:         window,
			Confidence:     "high",
		}
		if a.totalRPS > 0 {
			e.ErrorRatePct = a.errorRPS / a.totalRPS * 100
		}
		g.Edges = append(g.Edges, e)
	}
	g.NamespacesObserved = len(seenNs)
	return nil
}

// buildHubble reads hubble_flows_processed_total by (src, dst, verdict) for the
// common L4 case: forwarded vs dropped %. L7 latency is gated on SourceHubbleL7
// so an L4-only cluster never shows a fabricated "0ms p99". L4-only edges are
// Confidence="partial" (no latency observed).
func buildHubble(ctx context.Context, c *Client, src TelemetrySource, window string,
	resolve func(ns, wl string) string, g *ObservedGraph) error {

	rateQ := `sum(rate(hubble_flows_processed_total[` + window +
		`])) by (source_workload, source_namespace, destination_workload, destination_namespace, verdict)`
	samples, err := c.Query(ctx, rateQ)
	if err != nil {
		return err
	}
	type hAcc struct {
		from, to       string
		total, dropped float64
	}
	acc := map[string]*hAcc{}
	// See ObservedGraph.NamespacesObserved.
	seenNs := map[string]bool{}
	for _, s := range samples {
		m := s.Metric
		if ns := m["source_namespace"]; ns != "" {
			seenNs[ns] = true
		}
		if ns := m["destination_namespace"]; ns != "" {
			seenNs[ns] = true
		}
		from := resolveEndpoint(resolve, m["source_namespace"], m["source_workload"])
		to := resolveEndpoint(resolve, m["destination_namespace"], m["destination_workload"])
		key := from + "\x00" + to
		a := acc[key]
		if a == nil {
			a = &hAcc{from: from, to: to}
			acc[key] = a
		}
		a.total += s.Value
		if m["verdict"] == "DROPPED" {
			a.dropped += s.Value
		}
	}
	for _, a := range acc {
		e := types.ObservedEdge{
			From: a.from, To: a.to, Protocol: "tcp",
			RequestsPerSec: a.total,
			MTLS:           "none",
			Source:         "hubble",
			Window:         window,
			Confidence:     "partial",
		}
		if a.total > 0 {
			e.VerdictDroppedPct = a.dropped / a.total * 100
		}
		g.Edges = append(g.Edges, e)
	}
	g.NamespacesObserved = len(seenNs)
	return nil
}
