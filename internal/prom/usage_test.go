package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// usageVector builds a /api/v1/query vector envelope from (metric, value) pairs.
func usageVector(series ...struct {
	metric map[string]string
	value  string
}) map[string]any {
	result := make([]any, 0, len(series))
	for _, s := range series {
		result = append(result, map[string]any{
			"metric": s.metric,
			"value":  []any{1718000000, s.value},
		})
	}
	return map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "vector",
			"result":     result,
		},
	}
}

type ser = struct {
	metric map[string]string
	value  string
}

// usageServer returns an httptest server that dispatches the four Usage7d
// queries by inspecting the `query` param, returning each canned vector.
func usageServer(t *testing.T, cpuP95, cpuMax, memP95, memMax map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		var payload map[string]any
		switch {
		case strings.Contains(q, "container_cpu_usage") && strings.Contains(q, "quantile_over_time"):
			payload = cpuP95
		case strings.Contains(q, "container_cpu_usage") && strings.Contains(q, "max_over_time"):
			payload = cpuMax
		case strings.Contains(q, "container_memory_working_set_bytes") && strings.Contains(q, "quantile_over_time"):
			payload = memP95
		case strings.Contains(q, "container_memory_working_set_bytes") && strings.Contains(q, "max_over_time"):
			payload = memMax
		default:
			http.Error(w, "unexpected query: "+q, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(payload)
	}))
}

// lbl is a convenience for the standard kube-state-metrics label set.
func lbl(ns, pod, container string) map[string]string {
	return map[string]string{"namespace": ns, "pod": pod, "container": container}
}

func TestUsage7d_JoinsTwoContainers(t *testing.T) {
	// Two containers across two pods, present in all four vectors.
	cpuP95 := usageVector(
		ser{lbl("api", "api-1", "app"), "0.5"},
		ser{lbl("web", "web-1", "nginx"), "0.1"},
	)
	cpuMax := usageVector(
		ser{lbl("api", "api-1", "app"), "0.9"},
		ser{lbl("web", "web-1", "nginx"), "0.2"},
	)
	memP95 := usageVector(
		ser{lbl("api", "api-1", "app"), "104857600"},  // 100Mi
		ser{lbl("web", "web-1", "nginx"), "52428800"}, // 50Mi
	)
	memMax := usageVector(
		ser{lbl("api", "api-1", "app"), "209715200"},  // 200Mi
		ser{lbl("web", "web-1", "nginx"), "62914560"}, // 60Mi
	)

	srv := usageServer(t, cpuP95, cpuMax, memP95, memMax)
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	got, err := c.Usage7d(context.Background())
	if err != nil {
		t.Fatalf("Usage7d: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 containers, got %d: %+v", len(got), got)
	}

	api := got["api/api-1/app"]
	if api.Namespace != "api" || api.Pod != "api-1" || api.Container != "app" {
		t.Errorf("api key fields wrong: %+v", api)
	}
	if api.CPUCoresP95 != 0.5 || api.CPUCoresMax != 0.9 {
		t.Errorf("api cpu = (%v,%v), want (0.5,0.9)", api.CPUCoresP95, api.CPUCoresMax)
	}
	if api.MemBytesP95 != 104857600 || api.MemBytesMax != 209715200 {
		t.Errorf("api mem = (%v,%v), want (104857600,209715200)", api.MemBytesP95, api.MemBytesMax)
	}

	web := got["web/web-1/nginx"]
	if web.CPUCoresP95 != 0.1 || web.CPUCoresMax != 0.2 {
		t.Errorf("web cpu = (%v,%v), want (0.1,0.2)", web.CPUCoresP95, web.CPUCoresMax)
	}
	if web.MemBytesP95 != 52428800 || web.MemBytesMax != 62914560 {
		t.Errorf("web mem = (%v,%v), want (52428800,62914560)", web.MemBytesP95, web.MemBytesMax)
	}
}

func TestUsage7d_CPUOnlyContainerHasZeroMem(t *testing.T) {
	// "cron" container appears only in CPU vectors; its mem stays 0
	// (0 == "series absent", documented in usage.go).
	cpuP95 := usageVector(
		ser{lbl("api", "api-1", "app"), "0.5"},
		ser{lbl("batch", "cron-1", "cron"), "0.3"},
	)
	cpuMax := usageVector(
		ser{lbl("api", "api-1", "app"), "0.9"},
		ser{lbl("batch", "cron-1", "cron"), "0.4"},
	)
	memP95 := usageVector(
		ser{lbl("api", "api-1", "app"), "104857600"},
	)
	memMax := usageVector(
		ser{lbl("api", "api-1", "app"), "209715200"},
	)

	srv := usageServer(t, cpuP95, cpuMax, memP95, memMax)
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	got, err := c.Usage7d(context.Background())
	if err != nil {
		t.Fatalf("Usage7d: %v", err)
	}

	cron, ok := got["batch/cron-1/cron"]
	if !ok {
		t.Fatalf("cron container must be present (CPU-only), got keys: %v", keys(got))
	}
	if cron.CPUCoresP95 != 0.3 || cron.CPUCoresMax != 0.4 {
		t.Errorf("cron cpu = (%v,%v), want (0.3,0.4)", cron.CPUCoresP95, cron.CPUCoresMax)
	}
	if cron.MemBytesP95 != 0 || cron.MemBytesMax != 0 {
		t.Errorf("cron mem = (%v,%v), want (0,0) since mem series absent", cron.MemBytesP95, cron.MemBytesMax)
	}
}

func TestUsage7d_LabelFallback(t *testing.T) {
	// Older kube-state-metrics uses pod_name / container_name.
	old := func(ns, pod, container string) map[string]string {
		return map[string]string{"namespace": ns, "pod_name": pod, "container_name": container}
	}
	cpuP95 := usageVector(ser{old("api", "api-1", "app"), "0.5"})
	cpuMax := usageVector(ser{old("api", "api-1", "app"), "0.9"})
	memP95 := usageVector(ser{old("api", "api-1", "app"), "104857600"})
	memMax := usageVector(ser{old("api", "api-1", "app"), "209715200"})

	srv := usageServer(t, cpuP95, cpuMax, memP95, memMax)
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	got, err := c.Usage7d(context.Background())
	if err != nil {
		t.Fatalf("Usage7d: %v", err)
	}
	u, ok := got["api/api-1/app"]
	if !ok {
		t.Fatalf("fallback labels must resolve to api/api-1/app, got keys: %v", keys(got))
	}
	if u.Pod != "api-1" || u.Container != "app" {
		t.Errorf("fallback fields wrong: pod=%q container=%q", u.Pod, u.Container)
	}
	if u.CPUCoresP95 != 0.5 || u.MemBytesMax != 209715200 {
		t.Errorf("fallback values wrong: %+v", u)
	}
}

func TestUsage7d_QueryErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":    "error",
			"errorType": "bad_data",
			"error":     "boom",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if _, err := c.Usage7d(context.Background()); err == nil {
		t.Fatal("query error must propagate from Usage7d")
	}
}

func TestWindowDays(t *testing.T) {
	if got := NewClient("http://x", PromAuth{Mode: AuthNone}).WindowDays(); got != 7 {
		t.Errorf("WindowDays() = %d, want 7", got)
	}
}

func TestContainerKeyExportedPrefix(t *testing.T) {
	// Federated/remote-write setups prefix collided labels with exported_.
	m := map[string]string{"exported_namespace": "api", "exported_pod": "api-1", "exported_container": "app"}
	ns, pod, container := containerKey(m)
	if ns != "api" || pod != "api-1" || container != "app" {
		t.Errorf("containerKey(exported_*) = (%q,%q,%q), want (api,api-1,app)", ns, pod, container)
	}
}

func TestPromProviderMethodology(t *testing.T) {
	srv := usageServer(t, usageVector(), usageVector(), usageVector(), usageVector())
	defer srv.Close()
	p := newPromProvider(NewClient(srv.URL, PromAuth{Mode: AuthNone}), "prometheus", nil, 0, false)
	m := p.Methodology()
	if m.Source != "prometheus" || m.Window != "7d" || m.Confidence != UsageConfidenceHigh {
		t.Errorf("promProvider methodology = %+v, want source=prometheus window=7d confidence=high", m)
	}
	if m.Backend != "prometheus" {
		t.Errorf("backend = %q, want prometheus", m.Backend)
	}
}

func TestPresenceProbe(t *testing.T) {
	// count() of both signature series returns >0 → present.
	present := usageVector(ser{map[string]string{}, "42"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(present)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if ok, err := hasContainerMetrics(context.Background(), c); err != nil || !ok {
		t.Fatalf("hasContainerMetrics = (%v,%v), want (true,nil)", ok, err)
	}

	// Empty vector (GMP curated subset) → absent.
	empty := usageVector()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(empty)
	}))
	defer srv2.Close()
	c2 := NewClient(srv2.URL, PromAuth{Mode: AuthNone})
	if ok, _ := hasContainerMetrics(context.Background(), c2); ok {
		t.Error("hasContainerMetrics on empty vector must be false (GMP curated subset)")
	}
}

func keys(m map[string]ContainerUsage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- B-001 regression: never present a 7d p95 over history that does not exist -------
//
// Confirmed live on the mesh testbed: a Prometheus roughly twenty minutes old produced
// the on-screen line "usage: prometheus · 7d · p95 · 37 series" with quality HIGH. The
// queries do span [7d:5m], and Prometheus evaluates them happily over whatever it holds,
// so the number is real — but the WINDOW is a claim about evidence, and that claim was
// false. The realistic shape of this is a client who installs Prometheus for the audit,
// or one with short retention, whose rightsizing headline then rests on hours of data.

// coverageServer answers the history-coverage probes: non-empty only for offsets at or
// below maxAge, empty beyond it, mimicking a Prometheus with a short retention.
func coverageServer(t *testing.T, hasDataAtOffsets map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		hit := false
		for off, ok := range hasDataAtOffsets {
			if strings.Contains(q, "offset "+off) {
				hit = ok
				break
			}
		}
		result := []any{}
		if hit {
			result = []any{map[string]any{"metric": map[string]string{}, "value": []any{1.0, "42"}}}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": result},
		})
	}))
}

func TestMethodology_ReportsTheRealWindowWhenHistoryIsShort(t *testing.T) {
	// Data exists an hour ago, but nothing older — a Prometheus started this morning.
	srv := coverageServer(t, map[string]bool{"6d": false, "3d": false, "1d": false, "6h": false, "1h": true})
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	cov, covKnown := c.HistoryCoverage(context.Background())
	if !covKnown {
		t.Fatal("probes answered, so coverage must be known")
	}
	if cov <= 0 {
		t.Fatalf("HistoryCoverage = %v, want a positive short span", cov)
	}
	if cov >= 24*time.Hour {
		t.Errorf("HistoryCoverage = %v, want well under a day", cov)
	}

	p := newPromProvider(c, "prometheus", nil, cov, covKnown)
	m := p.Methodology()
	if strings.Contains(m.Window, "7d") {
		t.Errorf("Window = %q — must not claim 7d when only %v of history exists", m.Window, cov)
	}
	if m.Confidence == UsageConfidenceHigh {
		t.Errorf("Confidence = %q — a sub-day span cannot back a weekly p95", m.Confidence)
	}
	if len(m.Caveats) == 0 {
		t.Error("expected a caveat naming the history shortfall")
	}
}

func TestMethodology_FullHistoryKeepsTheNominalWindowAndHighGrade(t *testing.T) {
	srv := coverageServer(t, map[string]bool{"6d": true})
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	cov, covKnown := c.HistoryCoverage(context.Background())
	p := newPromProvider(c, "prometheus", nil, cov, covKnown)

	m := p.Methodology()
	if m.Window != "7d" {
		t.Errorf("Window = %q, want 7d when a full week of history exists", m.Window)
	}
	if m.Confidence != UsageConfidenceHigh {
		t.Errorf("Confidence = %q, want high for a full windowed p95", m.Confidence)
	}
}

// TestMethodology_VeryYoungPrometheusStillLosesTheSevenDayClaim covers the case that
// escaped the first fix and was caught only by re-running against the live testbed: a
// Prometheus younger than the shortest probe rung.
//
// The first implementation returned a single zero for two different states — "the probe
// failed, so make no claim" and "the probe worked and found nothing even an hour back".
// The second is the WORST case, not an unknown one, and collapsing it into the same zero
// meant a thirty-minute-old Prometheus quietly kept its "7d · p95 · HIGH" label. Probed
// emptiness and probe failure must stay distinguishable.
func TestMethodology_VeryYoungPrometheusStillLosesTheSevenDayClaim(t *testing.T) {
	// Every rung answers successfully, and every rung is empty.
	srv := coverageServer(t, map[string]bool{})
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	cov, known := c.HistoryCoverage(context.Background())
	if !known {
		t.Fatal("all probes answered, so coverage must be reported as known")
	}

	p := newPromProvider(c, "prometheus", nil, cov, known)
	m := p.Methodology()
	if strings.Contains(m.Window, "7d") {
		t.Errorf("Window = %q — a Prometheus with no data even an hour back must not claim 7d", m.Window)
	}
	if m.Confidence == UsageConfidenceHigh {
		t.Errorf("Confidence = %q, want a downgrade", m.Confidence)
	}
	if len(m.Caveats) == 0 {
		t.Error("expected a caveat naming the history shortfall")
	}
}

// TestMethodology_UnreachableBackendMakesNoWindowClaim is the other side of that split: a
// probe that ERRORS is genuinely unknown, and unknown must not be dressed up as a finding.
func TestMethodology_UnreachableBackendMakesNoWindowClaim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	_, known := c.HistoryCoverage(context.Background())
	if known {
		t.Error("a failing probe must report coverage as unknown, not as zero history")
	}
}
