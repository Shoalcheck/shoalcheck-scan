package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// vectorN returns an n-sample vector; n=0 is an empty vector. Used to simulate
// "series present" vs "series absent" per DetectTelemetry's contract.
func vectorN(n int) map[string]any {
	results := make([]any, 0, n)
	for i := 0; i < n; i++ {
		results = append(results, map[string]any{
			"metric": map[string]string{},
			"value":  []any{1718000000, "1"},
		})
	}
	return map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": results},
	}
}

// detectServer answers count() probes: a query containing one of `present`'s
// substrings returns a 1-sample vector; everything else returns empty.
func detectServer(t *testing.T, present ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		for _, p := range present {
			if strings.Contains(q, p) {
				json.NewEncoder(w).Encode(vectorN(1))
				return
			}
		}
		json.NewEncoder(w).Encode(vectorN(0))
	}))
}

func testClient(url string) *Client { return NewClient(url, PromAuth{Mode: AuthNone}) }

func TestDetectTelemetry(t *testing.T) {
	cases := []struct {
		name    string
		present []string
		want    TelemetrySource
	}{
		{"istio", []string{"istio_requests_total"}, SourceIstio},
		{"linkerd", []string{"response_total"}, SourceLinkerd},
		{"hubble-l7", []string{"hubble_http_requests_total"}, SourceHubbleL7},
		{"hubble-l4", []string{"hubble_flows_processed_total"}, SourceHubbleL4},
		{"ingress", []string{"nginx_ingress_controller_requests"}, SourceIngress},
		{"none", nil, SourceNone},
		// priority: istio wins even when linkerd series also present.
		{"priority-istio-over-linkerd", []string{"istio_requests_total", "response_total"}, SourceIstio},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := detectServer(t, c.present...)
			defer srv.Close()
			got, err := DetectTelemetry(context.Background(), testClient(srv.URL))
			if err != nil {
				t.Fatalf("DetectTelemetry: %v", err)
			}
			if got != c.want {
				t.Errorf("source = %q, want %q", got, c.want)
			}
		})
	}
}

// istioEdgeSample is one server-aggregated istio_requests_total row.
func istioEdgeSample(srcWl, srcNs, dstWl, dstNs, dstSvc, code, csp string, rps float64) map[string]any {
	return map[string]any{
		"metric": map[string]string{
			"source_workload":                srcWl,
			"source_workload_namespace":      srcNs,
			"destination_workload":           dstWl,
			"destination_workload_namespace": dstNs,
			"destination_service":            dstSvc,
			"response_code":                  code,
			"connection_security_policy":     csp,
			"reporter":                       "destination",
		},
		"value": []any{1718000000, formatFloat(rps)},
	}
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// idResolve maps every (ns, workload) to "Deployment/<workload>" so the test
// edges land on known IDs; "ext" resolves to "" (unmapped → external).
func idResolve(ns, wl string) string {
	if wl == "ext" {
		return ""
	}
	return "Deployment/" + wl
}

func TestBuildObservedGraph_Istio(t *testing.T) {
	// web→api: 90 rps 200 + 10 rps 503 ⇒ 100 rps total, 10% error, mTLS strict.
	rate := []any{
		istioEdgeSample("web", "shop", "api", "shop", "api.shop.svc", "200", "mutual_tls", 90),
		istioEdgeSample("web", "shop", "api", "shop", "api.shop.svc", "503", "mutual_tls", 10),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "istio_requests_total"):
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": rate},
			})
		case strings.Contains(q, "histogram_quantile(0.99"):
			json.NewEncoder(w).Encode(quantileVector("web", "api", "shop", 120))
		default: // p50 + any other ⇒ empty
			json.NewEncoder(w).Encode(vectorN(0))
		}
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("BuildObservedGraph: %v", err)
	}
	if g.Reporter != "destination" {
		t.Errorf("Reporter = %q, want destination", g.Reporter)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 aggregated edge, got %d", len(g.Edges))
	}
	e := g.Edges[0]
	if e.From != "Deployment/web" || e.To != "Deployment/api" {
		t.Errorf("edge = %s→%s, want Deployment/web→Deployment/api", e.From, e.To)
	}
	if e.RequestsPerSec != 100 {
		t.Errorf("rps = %v, want 100", e.RequestsPerSec)
	}
	if e.ErrorRatePct != 10 {
		t.Errorf("err%% = %v, want 10", e.ErrorRatePct)
	}
	if e.P99Ms != 120 {
		t.Errorf("p99 = %v, want 120", e.P99Ms)
	}
	if e.MTLS != "strict" {
		t.Errorf("mtls = %q, want strict", e.MTLS)
	}
	if e.Confidence != "high" {
		t.Errorf("confidence = %q, want high", e.Confidence)
	}
}

// quantileVector is one histogram_quantile result row keyed by the by() labels.
func quantileVector(srcWl, dstWl, dstNs string, ms float64) map[string]any {
	return quantileVectorN(quantileRow(srcWl, dstWl, dstNs, ms))
}

// quantileRow is one histogram_quantile sample carrying the source+dest labels.
func quantileRow(srcWl, dstWl, dstNs string, ms float64) map[string]any {
	return map[string]any{
		"metric": map[string]string{
			"source_workload":                srcWl,
			"destination_workload":           dstWl,
			"destination_workload_namespace": dstNs,
		},
		"value": []any{1718000000, formatFloat(ms)},
	}
}

// quantileVectorN wraps N quantile rows in a success vector envelope.
func quantileVectorN(rows ...map[string]any) map[string]any {
	result := make([]any, len(rows))
	for i, r := range rows {
		result[i] = r
	}
	return map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": result},
	}
}

// TestBuildObservedGraph_Istio_TwoSourcesDistinctLatency pins fix #5: TWO sources
// to the SAME dest must each get their OWN p50/p99. The latency map is keyed by
// source+dest, so frontend→api (p99=120) and worker→api (p99=900) do not collapse
// (last-wins) and misattribute one source's latency to the other's edge.
func TestBuildObservedGraph_Istio_TwoSourcesDistinctLatency(t *testing.T) {
	rate := []any{
		istioEdgeSample("frontend", "shop", "api", "shop", "api.svc", "200", "mutual_tls", 50),
		istioEdgeSample("worker", "shop", "api", "shop", "api.svc", "200", "mutual_tls", 20),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "istio_requests_total"):
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": rate},
			})
		case strings.Contains(q, "histogram_quantile(0.99"):
			json.NewEncoder(w).Encode(quantileVectorN(
				quantileRow("frontend", "api", "shop", 120),
				quantileRow("worker", "api", "shop", 900),
			))
		default:
			json.NewEncoder(w).Encode(vectorN(0))
		}
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("want 2 distinct edges (two sources to one dest), got %d: %+v", len(g.Edges), g.Edges)
	}
	got := map[string]float64{}
	for _, e := range g.Edges {
		got[e.From] = e.P99Ms
	}
	if got["Deployment/frontend"] != 120 {
		t.Errorf("frontend→api p99 = %v, want 120 (own latency)", got["Deployment/frontend"])
	}
	if got["Deployment/worker"] != 900 {
		t.Errorf("worker→api p99 = %v, want 900 (own latency, not collapsed to frontend's)", got["Deployment/worker"])
	}
}

// TestBuildObservedGraph_Istio_MixedMTLSIsPartial pins fix #8: an edge with both
// mutual_tls and plaintext (none) samples must report partial, never round up to
// strict. mTLS strict is a security claim — it must be evidenced for ALL traffic.
func TestBuildObservedGraph_Istio_MixedMTLSIsPartial(t *testing.T) {
	rate := []any{
		istioEdgeSample("web", "shop", "api", "shop", "api.svc", "200", "mutual_tls", 80),
		istioEdgeSample("web", "shop", "api", "shop", "api.svc", "200", "none", 20),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "istio_requests_total") {
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": rate},
			})
			return
		}
		json.NewEncoder(w).Encode(vectorN(0))
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 aggregated edge, got %d", len(g.Edges))
	}
	if g.Edges[0].MTLS != "partial" {
		t.Errorf("mixed mutual_tls+plaintext edge must be partial, got %q (must NOT round up to strict)", g.Edges[0].MTLS)
	}
}

func TestBuildObservedGraph_HubbleL4_DroppedAndPartial(t *testing.T) {
	// web→db: 95 forwarded + 5 dropped ⇒ 100 rps, 5% dropped, partial confidence.
	rows := []any{
		hubbleSample("web", "db", "FORWARDED", 95),
		hubbleSample("web", "db", "DROPPED", 5),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": rows},
		})
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceHubbleL4, "5m", idResolve)
	if err != nil {
		t.Fatalf("BuildObservedGraph hubble: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(g.Edges))
	}
	e := g.Edges[0]
	if e.RequestsPerSec != 100 {
		t.Errorf("rps = %v, want 100", e.RequestsPerSec)
	}
	if e.VerdictDroppedPct != 5 {
		t.Errorf("dropped%% = %v, want 5", e.VerdictDroppedPct)
	}
	if e.Confidence != "partial" {
		t.Errorf("L4-only confidence = %q, want partial", e.Confidence)
	}
}

func hubbleSample(srcWl, dstWl, verdict string, rps float64) map[string]any {
	return map[string]any{
		"metric": map[string]string{
			"source_workload":      srcWl,
			"destination_workload": dstWl,
			"verdict":              verdict,
		},
		"value": []any{1718000000, formatFloat(rps)},
	}
}

// TestBuildObservedGraph_DoubleCountGuard proves the destination-reporter pin:
// the rate query the builder issues includes reporter="destination", so a server
// that keys on that never returns source rows — the rate is not doubled and mTLS
// is not fabricated as a gap. We assert the builder's query carries the pin.
func TestBuildObservedGraph_DoubleCountGuard(t *testing.T) {
	var sawDestPin bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "istio_requests_total") && strings.Contains(q, `reporter="destination"`) {
			sawDestPin = true
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "istio_requests_total") {
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data": map[string]any{"resultType": "vector", "result": []any{
					istioEdgeSample("web", "shop", "api", "shop", "api.svc", "200", "mutual_tls", 50),
				}},
			})
			return
		}
		json.NewEncoder(w).Encode(vectorN(0))
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !sawDestPin {
		t.Fatal("rate query must pin reporter=destination (double-count guard)")
	}
	if len(g.Edges) != 1 || g.Edges[0].RequestsPerSec != 50 {
		t.Fatalf("want single 50rps edge, got %+v", g.Edges)
	}
	if g.Edges[0].MTLS != "strict" {
		t.Errorf("mtls = %q, want strict (destination reporter)", g.Edges[0].MTLS)
	}
}

func TestBuildObservedGraph_DetectedButEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vectorN(0)) // every query empty
	}))
	defer srv.Close()
	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("want 0 edges, got %d", len(g.Edges))
	}
	if g.Note != "mesh present, no traffic in window" {
		t.Errorf("Note = %q, want detected-but-empty note", g.Note)
	}
	if g.Source != SourceIstio {
		t.Errorf("Source must stay %q (no silent downgrade)", SourceIstio)
	}
}

// linkerdSample is one server-aggregated response_total{direction="outbound"}
// row. tls is the proxy's per-connection encryption signal ("true" ⇒ encrypted).
func linkerdSample(srcWl, srcNs, dstWl, dstNs, classification, tls string, rps float64) map[string]any {
	return map[string]any{
		"metric": map[string]string{
			"deployment":     srcWl,
			"namespace":      srcNs,
			"dst_deployment": dstWl,
			"dst_namespace":  dstNs,
			"classification": classification,
			"tls":            tls,
			"direction":      "outbound",
		},
		"value": []any{1718000000, formatFloat(rps)},
	}
}

func linkerdServer(t *testing.T, rows []any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": rows},
		})
	}))
}

// TestBuildObservedGraph_LinkerdInMeshEncryptedIsStrict: when BOTH endpoints
// resolve to in-mesh WorkloadNode IDs AND every sample reports tls="true", the
// edge is honestly mTLS=strict.
func TestBuildObservedGraph_LinkerdInMeshEncryptedIsStrict(t *testing.T) {
	srv := linkerdServer(t, []any{
		linkerdSample("web", "shop", "api", "shop", "success", "true", 40),
	})
	defer srv.Close()
	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceLinkerd, "5m", idResolve)
	if err != nil {
		t.Fatalf("build linkerd: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(g.Edges))
	}
	if g.Edges[0].MTLS != "strict" {
		t.Errorf("in-mesh + tls=true must be strict, got %q", g.Edges[0].MTLS)
	}
}

// TestBuildObservedGraph_LinkerdExternalNotStrict is the honesty guard: an edge
// to an UNMAPPED (external) endpoint must NEVER be labelled strict, even though
// the source proxy is in the mesh — the old code hardcoded strict on every edge,
// fabricating an encryption claim about traffic leaving the mesh.
func TestBuildObservedGraph_LinkerdExternalNotStrict(t *testing.T) {
	srv := linkerdServer(t, []any{
		// dst "ext" resolves to "" (idResolve) ⇒ external/unmapped endpoint.
		linkerdSample("web", "shop", "ext", "shop", "success", "true", 7),
	})
	defer srv.Close()
	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceLinkerd, "5m", idResolve)
	if err != nil {
		t.Fatalf("build linkerd: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 retained edge, got %d", len(g.Edges))
	}
	if g.Edges[0].To != "external/ext" {
		t.Errorf("unmapped dst To = %q, want external/ext", g.Edges[0].To)
	}
	if g.Edges[0].MTLS == "strict" {
		t.Errorf("edge to an external/unmapped endpoint must NOT be strict (fabricated), got %q", g.Edges[0].MTLS)
	}
}

// TestBuildObservedGraph_LinkerdUnencryptedNotStrict: both endpoints in-mesh but
// a sample reports tls!="true" (e.g. an unmeshed leg). The edge must not round
// up to strict — encryption was not evidenced for all of its traffic.
func TestBuildObservedGraph_LinkerdUnencryptedNotStrict(t *testing.T) {
	srv := linkerdServer(t, []any{
		linkerdSample("web", "shop", "api", "shop", "success", "true", 30),
		linkerdSample("web", "shop", "api", "shop", "success", "disabled", 10),
	})
	defer srv.Close()
	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceLinkerd, "5m", idResolve)
	if err != nil {
		t.Fatalf("build linkerd: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(g.Edges))
	}
	if g.Edges[0].MTLS == "strict" {
		t.Errorf("a mixed/unencrypted edge must not be strict, got %q", g.Edges[0].MTLS)
	}
}

func TestBuildObservedGraph_UnmappedToExternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "istio_requests_total") {
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data": map[string]any{"resultType": "vector", "result": []any{
					istioEdgeSample("web", "shop", "ext", "shop", "ext.svc", "200", "none", 7),
				}},
			})
			return
		}
		json.NewEncoder(w).Encode(vectorN(0))
	}))
	defer srv.Close()
	g, _ := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if len(g.Edges) != 1 {
		t.Fatalf("want 1 retained edge, got %d", len(g.Edges))
	}
	if g.Edges[0].To != "external/ext" {
		t.Errorf("unmapped dst To = %q, want external/ext (never dropped)", g.Edges[0].To)
	}
}

// TestBuildObservedGraph_CountsObservedNamespaces is the B-007 regression.
//
// The frozen progress contract carries MapBuilt.NamespacesObserved so the UI can state
// observation coverage, and nothing ever assigned it — the first live OBSERVED run emitted
// {"namespacesObserved":0,...,"edges":7}. Rendered, that reads "0 of 9 namespaces observed"
// beside "7 measured edges": self-contradictory, and understating what was actually
// measured. The count cannot be recovered downstream because ObservedEdge carries only
// "Kind/Name" workload IDs, so it has to be computed here, where the raw
// source/destination namespace labels still exist.
func TestBuildObservedGraph_CountsObservedNamespaces(t *testing.T) {
	rate := []any{
		istioEdgeSample("web", "shop", "api", "shop", "api.shop.svc", "200", "mutual_tls", 10),
		istioEdgeSample("api", "shop", "db", "data", "db.data.svc", "200", "mutual_tls", 5),
		// An external client has no source namespace — it must not be counted, and must not
		// be counted as an empty-string namespace either.
		istioEdgeSample("", "", "web", "shop", "web.shop.svc", "200", "none", 2),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "istio_requests_total") {
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": rate},
			})
			return
		}
		json.NewEncoder(w).Encode(vectorN(0))
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("BuildObservedGraph: %v", err)
	}
	// shop and data — the empty external namespace is excluded.
	if g.NamespacesObserved != 2 {
		t.Errorf("NamespacesObserved = %d, want 2 (shop, data); edges=%d",
			g.NamespacesObserved, len(g.Edges))
	}
}

// TestBuildObservedGraph_NoTrafficObservesNoNamespaces keeps the honest empty state honest:
// a mesh with no traffic in the window has observed nothing, and must not borrow a count.
func TestBuildObservedGraph_NoTrafficObservesNoNamespaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vectorN(0))
	}))
	defer srv.Close()

	g, err := BuildObservedGraph(context.Background(), testClient(srv.URL), SourceIstio, "5m", idResolve)
	if err != nil {
		t.Fatalf("BuildObservedGraph: %v", err)
	}
	if g.NamespacesObserved != 0 {
		t.Errorf("NamespacesObserved = %d, want 0 when no traffic was observed", g.NamespacesObserved)
	}
}
