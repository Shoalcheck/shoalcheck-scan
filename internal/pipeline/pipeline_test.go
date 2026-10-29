package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"

	"reflect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/progress"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/ruledeps"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
	"sort"
)

// provenInventory is a cluster with pods carrying UIDs, which is what B-145's provenance check needs to
// prove a metrics source is this cluster's. An empty inventory is not a degenerate case here — it is the
// "nothing to prove with" state, and usage is correctly withheld for it.
func provenInventory(n int) *collect.Inventory {
	inv := &collect.Inventory{Services: promSvc()}
	for i := 0; i < n; i++ {
		inv.Pods = append(inv.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop", Name: fmt.Sprintf("api-%03d", i),
			UID: k8stypes.UID(fmt.Sprintf("11111111-2222-3333-4444-%012d", i)),
		}})
	}
	return inv
}

// promProvenServer answers the usage queries with `samples` AND answers B-145's two identity queries as a
// single-cluster source would: every sampled UID present, and a live-pod count matching the reading. A
// stub that answered the identity queries the same way it answers the usage ones would fail the proof and
// the test would be measuring the stub rather than the product.
func promProvenServer(t *testing.T, samples []map[string]any, pods int) *httptest.Server {
	return promProvenServerFor(t, samples, pods, nil)
}

// promProvenServerFor is promProvenServer with a KNOWN UID SET, so the containment query is answered by
// actually intersecting rather than by always saying yes.
//
// The first version always answered 40 to the uid matcher, and the fleet test then passed for cluster B —
// whose pods the source has never seen — because the stub said yes to everyone. That is the failure this
// stub's own comment warns about, committed while writing it: the test was measuring the stub. knownUIDs
// nil means "this source knows every UID asked about", which is the single-cluster case.
func promProvenServerFor(t *testing.T, samples []map[string]any, pods int, knownUIDs map[string]bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		q := r.URL.Query().Get("query")
		if q == "" {
			q = r.Form.Get("query")
		}
		w.Header().Set("Content-Type", "application/json")
		scalar := func(v float64) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data": map[string]any{"resultType": "vector", "result": []any{map[string]any{
					"metric": map[string]string{}, "value": []any{1.0, fmt.Sprintf("%g", v)}}}},
			})
		}
		switch {
		case r.URL.Path == "/api/v1/status/buildinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success", "data": map[string]any{"version": "2.45.0"}})
		case strings.HasPrefix(q, "count(kube_pod_info{uid=~"):
			if knownUIDs == nil {
				scalar(40)
				return
			}
			inner := q[strings.Index(q, `uid=~"`)+len(`uid=~"`):]
			inner = inner[:strings.Index(inner, `"`)]
			n := 0
			for _, u := range strings.Split(inner, "|") {
				if knownUIDs[u] {
					n++
				}
			}
			scalar(float64(n))
		case strings.HasPrefix(q, "count(kube_pod_info)"):
			scalar(float64(pods))
		case r.URL.Path == "/api/v1/query":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": samples}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchUsage_URLSuccess verifies a reachable URL fetches usage and returns
// a Methodology.DataSources note.
func TestFetchUsage_URLSuccess(t *testing.T) {
	srv := promProvenServer(t, []map[string]any{
		{
			"metric": map[string]string{"namespace": "shop", "pod": "api-aaa", "container": "api"},
			"value":  []any{1.0, "0.18"},
		},
	}, 12)

	res, err := fetchUsage(context.Background(), Options{PrometheusURL: srv.URL}, provenInventory(12), io.Discard)
	if err != nil {
		t.Fatalf("fetchUsage with reachable URL: %v", err)
	}
	if len(res.usage) != 1 {
		t.Fatalf("want 1 usage series, got %d: %v", len(res.usage), res.usage)
	}
	if !strings.Contains(res.dataSrc, "Usage: prometheus") {
		t.Errorf("unexpected DataSources note: %q", res.dataSrc)
	}
	if res.methodology == nil || res.methodology.Source != "prometheus" {
		t.Errorf("usage methodology = %+v, want source=prometheus", res.methodology)
	}
}

// TestFetchUsage_URLFailure verifies an unreachable URL returns a hard error.
func TestFetchUsage_URLFailure(t *testing.T) {
	res, err := fetchUsage(context.Background(), Options{PrometheusURL: "http://127.0.0.1:1"}, &collect.Inventory{}, io.Discard)
	if err == nil {
		t.Fatal("unreachable prometheus URL must return an error")
	}
	if res.usage != nil {
		t.Errorf("usage must be nil on failure, got %v", res.usage)
	}
	if !strings.Contains(err.Error(), "--prometheus-url") {
		t.Errorf("error must mention the flag name, got: %v", err)
	}
}

// TestFetchUsage_QueryFailureIsNonFatal verifies a reachable endpoint whose
// presence-probe query errors degrades to usage=nil WITHOUT failing the audit.
// With the tiered resolver, a probe-failing endpoint and no lower tier fall
// THROUGH to the none tier rather than emitting a fake near-zero rightsizing.
func TestFetchUsage_QueryFailureIsNonFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/status/buildinfo" {
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45.0"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "error", "errorType": "bad_data", "error": "boom"})
	}))
	defer srv.Close()

	res, err := fetchUsage(context.Background(), Options{PrometheusURL: srv.URL}, &collect.Inventory{}, io.Discard)
	if err != nil {
		t.Fatalf("query failure must NOT be fatal, got err: %v", err)
	}
	if res.usage != nil {
		t.Errorf("usage must be nil when probe fails, got %v", res.usage)
	}
	if res.methodology == nil || res.methodology.Source != "none" {
		t.Errorf("probe-failing endpoint with no lower tier must resolve to none, got %+v", res.methodology)
	}
	if !strings.Contains(res.dataSrc, "no usage source available") {
		t.Errorf("dataSrc must note no usage source, got %q", res.dataSrc)
	}
}

// TestFetchUsage_AutoDetect verifies that when no URL is given and a
// Prometheus-compatible service is present, the function succeeds with no usage
// and no DataSources note (the hint is written to the log).
func TestFetchUsage_AutoDetect(t *testing.T) {
	services := []corev1.Service{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-prometheus-stack-prometheus", Namespace: "monitoring"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Name: "http-web", Port: 9090, TargetPort: intstr.FromInt(9090)}},
			},
		},
	}
	res, err := fetchUsage(context.Background(), Options{}, &collect.Inventory{Services: services}, io.Discard)
	if err != nil {
		t.Fatalf("auto-detect path must not error: %v", err)
	}
	if res.usage != nil {
		t.Errorf("auto-detect must not produce usage, got usage=%v", res.usage)
	}
	// The none tier now carries an honest "no usage source" note + stamp.
	if res.methodology == nil || res.methodology.Source != "none" {
		t.Errorf("auto-detect (no URL) must resolve to none, got %+v", res.methodology)
	}
	if !strings.Contains(res.dataSrc, "no usage source available") {
		t.Errorf("none tier must note no usage source, got %q", res.dataSrc)
	}
}

// TestFetchUsage_NoPrometheus verifies the no-op path returns nil usage and the
// honest none-tier methodology stamp + note (never a fake zero rightsizing).
func TestFetchUsage_NoPrometheus(t *testing.T) {
	res, err := fetchUsage(context.Background(), Options{}, &collect.Inventory{}, io.Discard)
	if err != nil {
		t.Fatalf("no-op path must not error: %v", err)
	}
	if res.usage != nil {
		t.Errorf("no-op path must produce nil usage, got usage=%v", res.usage)
	}
	if res.methodology == nil || res.methodology.Source != "none" {
		t.Errorf("no-op path must resolve to none, got %+v", res.methodology)
	}
	if !strings.Contains(res.dataSrc, "no usage source available") {
		t.Errorf("none tier must note no usage source, got %q", res.dataSrc)
	}
}

// proxyServer answers Ping (buildinfo) and /api/v1/query under the SERVICE-PROXY
// path prefix, simulating an in-cluster Prometheus reached through the API
// server. usable=false makes /api/v1/query 403, simulating a blocked proxy.
func proxyServer(t *testing.T, usable bool, samples []map[string]any) (*httptest.Server, string) {
	t.Helper()
	const prefix = "/api/v1/namespaces/monitoring/services/http:prometheus-server:9090/proxy"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case prefix + "/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45.0"}})
		case prefix + "/api/v1/query":
			if !usable {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// B-145's identity queries answer as a single-cluster source would. Without this the proxy
			// stub would answer them with the USAGE vector, the containment check would read 0.2 as
			// "zero UIDs matched", and the test would be measuring the stub rather than the product.
			_ = r.ParseForm()
			q := r.URL.Query().Get("query")
			if q == "" {
				q = r.Form.Get("query")
			}
			if strings.HasPrefix(q, "count(kube_pod_info") {
				n := 40.0
				if !strings.Contains(q, "uid=~") {
					n = float64(len(samples))
				}
				json.NewEncoder(w).Encode(map[string]any{
					"status": "success",
					"data": map[string]any{"resultType": "vector", "result": []any{map[string]any{
						"metric": map[string]string{}, "value": []any{1.0, fmt.Sprintf("%g", n)}}}},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": samples},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, srv.URL
}

func promSvc() []corev1.Service {
	return []corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Name: "prometheus-server", Namespace: "monitoring"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 9090, TargetPort: intstr.FromInt(9090)}},
		},
	}}
}

// TestFetchUsage_AutoConnectSuccess: detected + reachable proxy ⇒ usage non-nil,
// dataSrc names the service-proxy connect mode.
func TestFetchUsage_AutoConnectSuccess(t *testing.T) {
	srv, host := proxyServer(t, true, []map[string]any{
		{"metric": map[string]string{"namespace": "shop", "pod": "api-1", "container": "api"}, "value": []any{1.0, "0.2"}},
	})
	defer srv.Close()

	res, err := fetchUsage(context.Background(), Options{
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: host},
	}, provenInventory(1), io.Discard)
	if err != nil {
		t.Fatalf("auto-connect success must not error: %v", err)
	}
	if len(res.usage) == 0 {
		t.Fatal("auto-connect must yield usage")
	}
	if !strings.Contains(res.dataSrc, "service-proxy") && !strings.Contains(res.dataSrc, "api-server-proxy") {
		t.Errorf("dataSrc must name the connect mode, got %q", res.dataSrc)
	}
	// The auto-connected client is surfaced for the map block to reuse.
	if res.mapClient == nil {
		t.Error("auto-connect success must surface mapClient for the service-map block")
	}
	if res.connectMode != string(prom.ModeServiceProxy) {
		t.Errorf("connectMode = %q, want %q", res.connectMode, prom.ModeServiceProxy)
	}
}

// TestFetchUsage_AutoConnectNoSeriesStillDisclosesConnectMode pins fix #7: when
// an opt-in auto-connect succeeds (proxy reachable, mapClient set) but the usage
// queries return NOTHING usable (Source resolves to "none"), the dataSrc note
// must STILL disclose the connect mode — the RBAC the path exercised was real,
// so dropping the disclosure would under-state the access used.
func TestFetchUsage_AutoConnectNoSeriesStillDisclosesConnectMode(t *testing.T) {
	// usable=true (proxy answers /query) but with NO samples ⇒ usage resolver
	// finds no series and falls through to Source="none".
	srv, host := proxyServer(t, true, nil)
	defer srv.Close()

	res, err := fetchUsage(context.Background(), Options{
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: host},
	}, &collect.Inventory{Services: promSvc()}, io.Discard)
	if err != nil {
		t.Fatalf("auto-connect no-series must not error: %v", err)
	}
	if res.methodology == nil || res.methodology.Source != "none" {
		t.Fatalf("no usable series must resolve to none, got %+v", res.methodology)
	}
	if res.mapClient == nil {
		t.Error("a reachable auto-connect endpoint must still surface mapClient (may carry mesh telemetry)")
	}
	if !strings.Contains(res.dataSrc, "no usage source available") {
		t.Errorf("dataSrc must note no usage source, got %q", res.dataSrc)
	}
	// The connect-mode disclosure must survive into the RBAC note.
	if !strings.Contains(res.dataSrc, string(prom.ModeServiceProxy)) {
		t.Errorf("dataSrc must disclose the connect mode %q even with no series, got %q", prom.ModeServiceProxy, res.dataSrc)
	}
}

// TestFetchUsage_AutoConnectProxyBlocked: proxy 403 + AllowPortForward=false ⇒
// usage nil, NO error, log mentions blocked.
func TestFetchUsage_AutoConnectProxyBlocked(t *testing.T) {
	srv, host := proxyServer(t, false, nil)
	defer srv.Close()

	var log bytes.Buffer
	res, err := fetchUsage(context.Background(), Options{
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: host},
	}, &collect.Inventory{Services: promSvc()}, &log)
	if err != nil {
		t.Fatalf("blocked proxy must NOT be fatal: %v", err)
	}
	if res.usage != nil {
		t.Errorf("usage must be nil when proxy blocked, got %v", res.usage)
	}
	if !strings.Contains(log.String(), "blocked") {
		t.Errorf("log must explain the proxy was blocked, got:\n%s", log.String())
	}
}

// TestFetchUsage_AutoConnectNoService: auto-connect on but no Prometheus Service
// ⇒ usage nil, no error.
func TestFetchUsage_AutoConnectNoService(t *testing.T) {
	res, err := fetchUsage(context.Background(), Options{
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: "http://127.0.0.1:1"},
	}, nil, io.Discard)
	if err != nil {
		t.Fatalf("no-service auto-connect must not error: %v", err)
	}
	if res.usage != nil {
		t.Errorf("usage must be nil when no service found, got %v", res.usage)
	}
	if res.mapClient != nil {
		t.Errorf("no service found must leave mapClient nil, got %v", res.mapClient)
	}
}

// fakeClientsetWithWorkloads seeds Deployments web+api in namespace shop so the
// observed-map resolver can land istio edges on real "Deployment/<name>" IDs.
func fakeClientsetWithWorkloads(t *testing.T) *fake.Clientset {
	t.Helper()
	return fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"}},
	)
}

// fakeClientsetWithWorkloadsAndProm is fakeClientsetWithWorkloads plus the
// in-cluster prometheus-server/monitoring:9090 Service auto-connect discovers
// (matching istioProxyServer's service-proxy path prefix), so the auto-connect
// path resolves an Endpoint and reaches the stub via service-proxy.
func fakeClientsetWithWorkloadsAndProm(t *testing.T) *fake.Clientset {
	t.Helper()
	return fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"}},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "prometheus-server", Namespace: "monitoring"},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Name: "http", Port: 9090, TargetPort: intstr.FromInt(9090)}},
			},
		},
	)
}

// emptyVec / oneSampleVec are query-response envelopes for the service-map tests.
func emptyVec() map[string]any {
	return map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": []any{}}}
}

func oneSampleVec() map[string]any {
	return map[string]any{"status": "success", "data": map[string]any{"resultType": "vector",
		"result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1718000000, "1"}}}}}
}

// istioRateVec is one server-aggregated istio_requests_total row, 200s only.
func istioRateVec(srcWl, srcNs, dstWl, dstNs string, rps float64) map[string]any {
	return map[string]any{"status": "success", "data": map[string]any{"resultType": "vector",
		"result": []any{map[string]any{
			"metric": map[string]string{
				"source_workload":                srcWl,
				"source_workload_namespace":      srcNs,
				"destination_workload":           dstWl,
				"destination_workload_namespace": dstNs,
				"response_code":                  "200",
				"connection_security_policy":     "mutual_tls",
				"reporter":                       "destination",
			},
			"value": []any{1718000000, "12"},
		}}}}
}

func TestRun_UnreachablePrometheus_TierStaysDeclared_NoError(t *testing.T) {
	col := collect.NewWithClient(fakeClientsetWithWorkloads(t))
	ar, err := Run(context.Background(), Options{
		Collector:     col,
		PrometheusURL: "", // no URL ⇒ no telemetry attempt
		Log:           io.Discard,
	})
	if err != nil {
		t.Fatalf("Run must not error without Prometheus: %v", err)
	}
	if ar.Architecture != nil && ar.Architecture.Tier == types.TierObserved {
		t.Errorf("Tier must stay declared with no telemetry, got observed")
	}
}

func TestRun_ReachableMesh_TierObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45"}})
		case strings.Contains(q, "count(istio_requests_total)"):
			json.NewEncoder(w).Encode(oneSampleVec())
		case strings.Contains(q, "istio_requests_total"):
			json.NewEncoder(w).Encode(istioRateVec("web", "shop", "api", "shop", 12))
		default:
			json.NewEncoder(w).Encode(emptyVec())
		}
	}))
	defer srv.Close()

	col := collect.NewWithClient(fakeClientsetWithWorkloads(t)) // seeds Deployment web+api in ns shop
	ar, err := Run(context.Background(), Options{Collector: col, PrometheusURL: srv.URL, Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Architecture == nil || ar.Architecture.Tier != types.TierObserved {
		t.Fatalf("Tier = %v, want observed", ar.Architecture)
	}
	if len(ar.Architecture.ObservedEdges) == 0 {
		t.Errorf("want observed edges, got none")
	}
}

// TestRun_ObservedGraph_IsAsOfTheReading pins that an observed map is dated by the reading's own clock. It was
// stamped with the wall clock inside prom.BuildObservedGraph, so the sample — a reading of 15 September — said its
// traffic was observed "as of" the afternoon it was regenerated, and the committed golden changed on every run.
// One reading, one clock: the collector's, which is the GeneratedAt every other dated field is read against.
func TestRun_ObservedGraph_IsAsOfTheReading(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45"}})
		case strings.Contains(q, "count(istio_requests_total)"):
			json.NewEncoder(w).Encode(oneSampleVec())
		case strings.Contains(q, "istio_requests_total"):
			json.NewEncoder(w).Encode(istioRateVec("web", "shop", "api", "shop", 12))
		default:
			json.NewEncoder(w).Encode(emptyVec())
		}
	}))
	defer srv.Close()

	at := time.Date(2026, 9, 15, 6, 28, 50, 0, time.UTC)
	cs := fakeClientsetWithWorkloads(t)
	col := collect.NewWithClients(cs, nil, cs.Discovery(), collect.WithClock(func() time.Time { return at }))
	ar, err := Run(context.Background(), Options{Collector: col, PrometheusURL: srv.URL, Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Architecture == nil || ar.Architecture.Tier != types.TierObserved {
		t.Fatalf("Tier = %v, want observed", ar.Architecture)
	}
	if ar.Architecture.ObservedAsOf == nil {
		t.Fatal("an observed map carries no as-of time")
	}
	if got := *ar.Architecture.ObservedAsOf; !got.Equal(ar.GeneratedAt) {
		t.Errorf("the map is observed as of %s, the reading was taken at %s — two clocks in one reading",
			got.Format(time.RFC3339Nano), ar.GeneratedAt.Format(time.RFC3339Nano))
	}
}

// TestRun_IngressOnlyTelemetry_TierStaysDeclared pins fix #4: an nginx ingress
// controller exposes ingress metrics but is NOT a service mesh — it has no
// service-to-service edge telemetry. DetectTelemetry returns SourceIngress, but
// Run must NOT promote Architecture to observed or report "mesh present". The
// cluster stays honestly on TierDeclared.
func TestRun_IngressOnlyTelemetry_TierStaysDeclared(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45"}})
		case strings.Contains(q, "nginx_ingress_controller_requests"):
			json.NewEncoder(w).Encode(oneSampleVec()) // ingress present
		default:
			json.NewEncoder(w).Encode(emptyVec()) // no mesh series
		}
	}))
	defer srv.Close()

	col := collect.NewWithClient(fakeClientsetWithWorkloads(t))
	var log bytes.Buffer
	ar, err := Run(context.Background(), Options{Collector: col, PrometheusURL: srv.URL, Log: &log})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Architecture != nil && ar.Architecture.Tier == types.TierObserved {
		t.Errorf("ingress-only telemetry must stay declared, got observed with note %q", ar.Architecture.ObservedNote)
	}
	if ar.Architecture != nil && strings.Contains(strings.ToLower(ar.Architecture.ObservedNote), "mesh present") {
		t.Errorf("an ingress controller must NOT be reported as 'mesh present', got note %q", ar.Architecture.ObservedNote)
	}
}

// istioProxyServer is proxyServer's mesh-aware sibling: it answers buildinfo,
// the usage presence-probe, AND the istio detect/build queries UNDER the
// service-proxy path prefix, so Run's auto-connect path reaches a mesh-bearing
// Prometheus terminal-free. withMesh=false returns empty vectors for the istio
// detect probe (no telemetry), so the map must stay declared.
func istioProxyServer(t *testing.T, withMesh bool) (*httptest.Server, string) {
	t.Helper()
	const prefix = "/api/v1/namespaces/monitoring/services/http:prometheus-server:9090/proxy"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("query")
		switch {
		case r.URL.Path == prefix+"/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45.0"}})
		case r.URL.Path != prefix+"/api/v1/query":
			http.NotFound(w, r)
		case strings.Contains(q, "count(istio_requests_total)"):
			if withMesh {
				json.NewEncoder(w).Encode(oneSampleVec())
			} else {
				json.NewEncoder(w).Encode(emptyVec())
			}
		case strings.Contains(q, "istio_requests_total"):
			json.NewEncoder(w).Encode(istioRateVec("web", "shop", "api", "shop", 12))
		default:
			// usage presence-probe and every other detect probe: empty.
			json.NewEncoder(w).Encode(emptyVec())
		}
	}))
	return srv, srv.URL
}

// TestRun_AutoConnectMesh_TierObserved is the double-unlock: with NO explicit
// --prometheus-url, the app's auto-connect (service-proxy) path reaches an
// in-cluster Prometheus carrying istio telemetry, and Run REUSES that one
// connection to upgrade Architecture from declared to observed with real edges.
func TestRun_AutoConnectMesh_TierObserved(t *testing.T) {
	srv, host := istioProxyServer(t, true)
	defer srv.Close()

	col := collect.NewWithClient(fakeClientsetWithWorkloadsAndProm(t)) // workloads + prom Service
	var log bytes.Buffer
	ar, err := Run(context.Background(), Options{
		Collector:   col,
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: host},
		Log:         &log,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Architecture == nil || ar.Architecture.Tier != types.TierObserved {
		t.Fatalf("Tier = %v, want observed (auto-connected mesh)", ar.Architecture)
	}
	if len(ar.Architecture.ObservedEdges) == 0 {
		t.Errorf("want observed edges over auto-connect, got none")
	}
	// The connect mode must be disclosed honestly in the service-map log line.
	if !strings.Contains(log.String(), "service-map:") || !strings.Contains(log.String(), string(prom.ModeServiceProxy)) {
		t.Errorf("service-map log must disclose the api-server-proxy connect mode, got:\n%s", log.String())
	}
}

// TestRun_AutoConnectNoTelemetry_TierStaysDeclared: auto-connect reaches a
// Prometheus with NO mesh series. The usage layer still connects, but the map
// must stay Tier-3 declared — never a fabricated edge.
func TestRun_AutoConnectNoTelemetry_TierStaysDeclared(t *testing.T) {
	srv, host := istioProxyServer(t, false)
	defer srv.Close()

	col := collect.NewWithClient(fakeClientsetWithWorkloadsAndProm(t))
	ar, err := Run(context.Background(), Options{
		Collector:   col,
		AutoConnect: true,
		RESTConfig:  &rest.Config{Host: host},
		Log:         io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Architecture != nil && ar.Architecture.Tier == types.TierObserved {
		t.Errorf("Tier must stay declared with no telemetry over auto-connect, got observed with %d edges",
			len(ar.Architecture.ObservedEdges))
	}
}

// TestUsageAggregation_ComesFromTheSourceNotTheWindowString guards a coupling that broke
// the moment the usage window became honest.
//
// usageAggregation used to read `window == "7d"` as a proxy for "this is the Tier-1
// Prometheus path", which held only while the window was a hard-coded constant. Once
// Methodology started reporting the span the data actually supports, a young Prometheus
// reported "15m" and the p95 label silently vanished from the chip — the aggregation had
// not changed at all, only the string it was being inferred from. The tier is the real
// signal: Tier 1 is a windowed p95 whatever its span; Tier 2/3 are instantaneous.
func TestUsageAggregation_ComesFromTheSourceNotTheWindowString(t *testing.T) {
	cases := []struct {
		source, window, want string
	}{
		{"prometheus", "7d", "p95"},
		{"prometheus", "15m", "p95"},
		{"prometheus", "under 15m", "p95"},
		{"vpa", "", ""},
		{"metrics.k8s.io", "instant", ""},
		{"none", "", ""},
	}
	for _, tc := range cases {
		if got := usageAggregation(tc.source); got != tc.want {
			t.Errorf("usageAggregation(source=%q, window was %q) = %q, want %q",
				tc.source, tc.window, got, tc.want)
		}
	}
}

// TestEmitVerdict_ReconcilesWithTheFindingsItRanks is the pipeline half of the judgment
// layer's headline invariant. The podium and the report read the SAME ar.Findings slice that
// validate.go reconciles against, so a Verdict event whose totals disagree with the findings
// it was built from would mean the two halves of the screen are describing different clusters.
func TestEmitVerdict_ReconcilesWithTheFindingsItRanks(t *testing.T) {
	ar := &types.AuditReport{Findings: []types.Finding{
		// A LimitRange is used rather than a resources block on purpose: a resources change
		// edits the pod template and rolls the workload, so it is NeedsReview, not SafeNow
		// (B-008). This fixture needs something genuinely safe for StartHere to point at.
		{ID: "f-1", RuleID: "cfg.limitrange", Title: "Add a LimitRange to waste", Severity: types.SeverityMedium,
			DollarImpactMonthly: 30, EstimatedEffort: types.EffortLow,
			RemediationYAML: "apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: defaults\n"},
		{ID: "f-2", RuleID: "sec.root", Title: "Runs as root", Severity: types.SeverityHigh},
		{ID: "f-3", RuleID: "cfg.limits", Title: "No limits", Severity: types.SeverityLow,
			DollarImpactMonthly: 12},
		{ID: "f-4", RuleID: "cfg.limits", Title: "No limits again", Severity: types.SeverityLow,
			DollarImpactMonthly: 8},
	}}

	var evts []progress.Event
	emitVerdict(progress.Func(func(e progress.Event) { evts = append(evts, e) }), ar, "kind-assay-mesh")

	if len(evts) != 1 {
		t.Fatalf("emitted %d events, want exactly one verdict", len(evts))
	}
	v := evts[0].Verdict
	if v == nil {
		t.Fatal("verdict payload is nil")
	}
	if got, want := v.TotalDollars, 50.0; got != want {
		t.Errorf("TotalDollars = %.2f, want %.2f (every finding, uncollapsed)", got, want)
	}
	var shown float64
	for _, l := range v.Leaders {
		shown += l.DollarMonthly
	}
	if sum := shown + v.RestDollars; sum != v.TotalDollars {
		t.Errorf("leaders %.2f + rest %.2f = %.2f, want %.2f — every dollar must be accounted for",
			shown, v.RestDollars, sum, v.TotalDollars)
	}
	// The two cfg.limits findings are one observation, so the podium must show three rules for
	// four findings.
	if len(v.Leaders) != 3 {
		t.Errorf("Leaders = %d, want 3", len(v.Leaders))
	}
	for _, l := range v.Leaders {
		if l.RuleID == "cfg.limits" && l.CollapsedFrom != 2 {
			t.Errorf("cfg.limits CollapsedFrom = %d, want 2", l.CollapsedFrom)
		}
	}
	// StartHere may only ever point at something actually safe.
	if v.StartHere == nil {
		t.Error("StartHere is nil although a resources/requests remediation exists")
	} else if v.StartHere.Safety != "safe-now" {
		t.Errorf("StartHere.Safety = %q, want safe-now", v.StartHere.Safety)
	}
}

// TestEmitVerdict_NoFindingsEmitsNothing — a clean cluster gets no podium at all, rather than
// an empty one asserting that three things matter.
// THE PODIUM IS RANKED IN BANDS, AND A READER IS TOLD SO. A finding whose own text says it may not apply is
// ranked after everything that certainly does — a hedged critical included — so three cards can be two mediums
// and a high while the reading holds a critical. The adversarial review of 2026-10-18 saw exactly that under a
// footer that said "Ranked by severity". Each card now carries its band, and a podium that leaves out the most
// severe finding names it, so the most serious thing in a reading is never one a reader has to go looking for.
func TestEmitVerdict_NamesTheMostSevereFindingThePodiumLeavesOut(t *testing.T) {
	ar := &types.AuditReport{Findings: []types.Finding{
		{ID: "f-crit", RuleID: "sec.hostpath", Title: "Mounts the host filesystem", Severity: types.SeverityCritical,
			Description: "This may not apply if the node is dedicated."},
		{ID: "f-now", RuleID: "gt.crashloop", Title: "Restarting", Severity: types.SeverityMedium,
			Pillar: types.PillarGroundTruth},
		{ID: "f-next", RuleID: "cp.pdb", Title: "Blocks a drain", Severity: types.SeverityMedium,
			Pillar: types.PillarChangePreflight},
		{ID: "f-high", RuleID: "sec.root", Title: "Runs as root", Severity: types.SeverityHigh},
	}}
	var evts []progress.Event
	emitVerdict(progress.Func(func(e progress.Event) { evts = append(evts, e) }), ar, "ctx")
	if len(evts) != 1 || evts[0].Verdict == nil {
		t.Fatalf("emitted %d events, want one verdict", len(evts))
	}
	v := evts[0].Verdict
	if len(v.Leaders) != 3 {
		t.Fatalf("%d leaders, want 3 — the premise is a podium the critical does not make", len(v.Leaders))
	}
	for _, l := range v.Leaders {
		if l.FindingID == "f-crit" {
			t.Fatalf("the hedged critical leads; this test needs the ranking that ranks it last")
		}
		if l.Band == "" {
			t.Errorf("leader %s carries no band, so a medium above a high reads as a broken sort", l.FindingID)
		}
	}
	if v.Leaders[0].Band != "true now" {
		t.Errorf("first leader's band = %q, want %q", v.Leaders[0].Band, "true now")
	}
	if v.MostSevere == nil {
		t.Fatal("the podium leaves out the reading's only critical and the verdict does not name it")
	}
	if v.MostSevere.FindingID != "f-crit" || v.MostSevere.Severity != "critical" || v.MostSevere.Band != "conditional" {
		t.Errorf("MostSevere = %s %s %q, want f-crit critical \"conditional\"", v.MostSevere.FindingID,
			v.MostSevere.Severity, v.MostSevere.Band)
	}

	// And a podium that already holds the most severe finding names nothing extra.
	ar.Findings[0].Description = "Mounts the host filesystem."
	evts = nil
	emitVerdict(progress.Func(func(e progress.Event) { evts = append(evts, e) }), ar, "ctx")
	if v := evts[0].Verdict; v.MostSevere != nil {
		t.Errorf("MostSevere = %s while the critical leads the podium", v.MostSevere.FindingID)
	}
}

func TestEmitVerdict_NoFindingsEmitsNothing(t *testing.T) {
	var evts []progress.Event
	emitVerdict(progress.Func(func(e progress.Event) { evts = append(evts, e) }), &types.AuditReport{}, "ctx")
	if len(evts) != 0 {
		t.Errorf("emitted %d events for a findings-free report, want 0", len(evts))
	}
	// And a nil report must not panic.
	emitVerdict(progress.Func(func(e progress.Event) {}), nil, "ctx")
}

// The opt-in port-forward fallback issues `create pods/portforward` — the one non-read verb this process
// can send to a cluster. The read path bounds itself at prom.MaxProbeCandidates precisely so a large
// monitoring stack cannot turn pre-flight into a long wait; the fallback loop had no bound at all, so on a
// stock kube-prometheus-stack (internal/prom/discover_test.go documents ELEVEN Services matching
// "prometheus") an opt-in run could issue eleven create calls against pods that were never Prometheus.
//
// The number of non-read verbs a run issues must not scale with how many unrelated Services happen to be
// named like Prometheus. Asserted as one shared constant rather than two matching literals, because two
// literals drift and the drift is invisible.
func TestPortForwardFallback_IsBoundedByTheSameCapAsTheReadPath(t *testing.T) {
	if got := prom.MaxProbeCandidates; got < 1 || got > 6 {
		t.Fatalf("prom.MaxProbeCandidates = %d — the bound is meant to be small; check this test's premise", got)
	}
	src, err := os.ReadFile("pipeline.go")
	if err != nil {
		t.Fatalf("read pipeline.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, "for _, cand := range eps {") {
		t.Error("the port-forward fallback still iterates every candidate — a cluster with N Prometheus-like " +
			"Services would receive N create pods/portforward calls")
	}
	if !strings.Contains(s, "prom.MaxProbeCandidates") {
		t.Error("the fallback does not reference prom.MaxProbeCandidates, so its bound can drift from the read path's")
	}
}

// TestFetchUsage_B145_AMultiClusterSourceYieldsNoUsage is the test that would have caught B-145.
//
// The source answers every usage query perfectly and it genuinely contains this cluster — the containment
// check passes. What separates it from a correct single-cluster Prometheus is one measurement: it reports
// far more live pods than this reading collected, which is what a Thanos holding a dozen clusters looks
// like. Every topology the founder named — central observability cluster, tunnel, Thanos, Mimir, Grafana
// Cloud, AMP, GMP, federation — lands here.
//
// The assertion is that USAGE IS DROPPED, not that a warning is logged. A rightsizing dollar computed from
// another cluster's consumption is worse than no dollar: absence is honest and a wrong number is not.
func TestFetchUsage_B145_AMultiClusterSourceYieldsNoUsage(t *testing.T) {
	srv := promProvenServer(t, []map[string]any{
		{"metric": map[string]string{"namespace": "shop", "pod": "api-000", "container": "api"},
			"value": []any{1.0, "0.18"}},
	}, 4900) // ~12 clusters' worth of live pods against the 12 this reading collected

	res, err := fetchUsage(context.Background(), Options{PrometheusURL: srv.URL}, provenInventory(12), io.Discard)
	if err != nil {
		t.Fatalf("an unproven source must not be fatal — the audit proceeds without usage: %v", err)
	}
	if len(res.usage) != 0 {
		t.Fatalf("usage from a source holding twelve clusters was kept (%d series) — this is B-145",
			len(res.usage))
	}
	if res.provenance.Proven() {
		t.Error("the source was marked proven")
	}
	// The reason must reach the methodology note, or the reader sees an absence with no explanation and
	// cannot tell a withheld figure from a cluster that had nothing to say.
	if !strings.Contains(res.dataSrc, "NOT PROVEN") {
		t.Errorf("the withholding is not disclosed in the data-source note: %q", res.dataSrc)
	}
	if !strings.Contains(res.dataSrc, "4900") {
		t.Errorf("the note does not carry the measurement it was decided on: %q", res.dataSrc)
	}
}

// The counterpart, and it is the one that stops the fix from being a regression: a correct single-cluster
// source must still produce usage. A check that withholds on the commonest topology in the world would be
// a worse defect than B-145.
func TestFetchUsage_B145_ASingleClusterSourceStillProducesUsage(t *testing.T) {
	srv := promProvenServer(t, []map[string]any{
		{"metric": map[string]string{"namespace": "shop", "pod": "api-000", "container": "api"},
			"value": []any{1.0, "0.18"}},
	}, 12)

	res, err := fetchUsage(context.Background(), Options{PrometheusURL: srv.URL}, provenInventory(12), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.usage) == 0 {
		t.Fatal("a proven single-cluster source produced no usage — the fix has become the defect")
	}
	if !res.provenance.Proven() {
		t.Errorf("a single-cluster source was not proven: %s", res.provenance.Detail)
	}
}

// TestFetchUsage_B145_FleetIsTheSameDefectAtScale.
//
// One --prometheus-url across N clusters is definitionally unproven for at least N-1 of them, and RunFleet
// passes the same URL to every cluster's Run. The proof runs per cluster against THAT cluster's pod UIDs,
// so the cluster the endpoint belongs to keeps its figures and the others have theirs withheld — rather
// than every cluster being billed for one cluster's consumption.
//
// This asserts the second half, which is the one that was silently wrong: a cluster whose pods the source
// has never heard of gets nothing.
func TestFetchUsage_B145_FleetIsTheSameDefectAtScale(t *testing.T) {
	// The source is cluster A's Prometheus: healthy, single-cluster, 12 live pods, and it knows only
	// cluster A's UIDs.
	clusterAUIDs := map[string]bool{}
	for i := 0; i < 12; i++ {
		clusterAUIDs[fmt.Sprintf("11111111-2222-3333-4444-%012d", i)] = true
	}
	srv := promProvenServerFor(t, []map[string]any{
		{"metric": map[string]string{"namespace": "shop", "pod": "api-000", "container": "api"},
			"value": []any{1.0, "0.18"}},
	}, 12, clusterAUIDs)

	// Cluster B points at it. Its pods carry different UIDs, so nothing of B's is in the source.
	clusterB := &collect.Inventory{Services: promSvc()}
	for i := 0; i < 12; i++ {
		clusterB.Pods = append(clusterB.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop", Name: fmt.Sprintf("api-%03d", i),
			UID: k8stypes.UID(fmt.Sprintf("99999999-8888-7777-6666-%012d", i)),
		}})
	}
	res, err := fetchUsage(context.Background(), Options{PrometheusURL: srv.URL}, clusterB, io.Discard)
	if err != nil {
		t.Fatalf("a fleet member with an unproven source must not fail the run: %v", err)
	}
	if len(res.usage) != 0 {
		t.Fatalf("cluster B kept %d usage series from cluster A's Prometheus", len(res.usage))
	}
	if !strings.Contains(res.dataSrc, "NOT PROVEN") {
		t.Errorf("cluster B's withholding is not disclosed: %q", res.dataSrc)
	}
}

// TestRun_EmitsGlassBoxEvents asserts Run streams the structural Glass-Box
// events at the real seams: the collection ledger (Collected), Act-1 node cards
// (NodeSeen, grouped by instance type, no dollars), the Act-2 pricing summary
// (Pricing), and exactly one map tier event (MapBuilt = declared, since no
// Prometheus). The CLI path (nil Progress) is unaffected — covered elsewhere.
func TestRun_EmitsGlassBoxEvents(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name:   "n1",
			Labels: map[string]string{"node.kubernetes.io/instance-type": "m6i.large"},
		}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name:   "n2",
			Labels: map[string]string{"node.kubernetes.io/instance-type": "m6i.large"},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}},
	)
	col := collect.NewWithClient(cs)

	var events []progress.Event
	_, err := Run(context.Background(), Options{
		Collector:   col,
		ClusterName: "c",
		Log:         io.Discard,
		Progress:    func(e progress.Event) { events = append(events, e) },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var collected, nodeSeen, pricing, mapBuilt int
	var mapTier string
	var nodeSeenHasDollars bool
	for _, e := range events {
		switch e.Kind {
		case progress.KindCollected:
			collected++
		case progress.KindNodeSeen:
			nodeSeen++
			if e.NodeSeen.InstanceType != "m6i.large" || e.NodeSeen.Count != 2 {
				t.Errorf("node_seen group wrong: %+v", e.NodeSeen)
			}
			// Act 1 carries NO dollars — pricing is a separate Act-2 event.
			if strings.Contains(e.NodeSeen.Spec, "$") {
				nodeSeenHasDollars = true
			}
		case progress.KindPricing:
			pricing++
		case progress.KindMapBuilt:
			mapBuilt++
			mapTier = e.MapBuilt.Tier
		}
	}
	if collected == 0 {
		t.Error("expected Collected events (the Act-1 ledger)")
	}
	if nodeSeen != 1 {
		t.Errorf("expected exactly 1 node_seen group (m6i.large ×2), got %d", nodeSeen)
	}
	if nodeSeenHasDollars {
		t.Error("node_seen must not contain dollars — pricing is Act 2 (honesty by sequencing)")
	}
	if pricing != 1 {
		t.Errorf("expected exactly 1 pricing summary, got %d", pricing)
	}
	// Exactly one map tier event, and with no Prometheus it MUST be declared —
	// never a fabricated observed tier (honesty guard 4).
	if mapBuilt != 1 || mapTier != "declared" {
		t.Errorf("expected exactly 1 map_built with tier=declared, got count=%d tier=%q", mapBuilt, mapTier)
	}
}

func (f *fakePreferredDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return f.preferred, nil
}

// TestRun_StackAnalyzerFindingSurvivesPipeline stands up a fake-dynamic
// collector seeded with an expiring cert-manager Certificate and a discovery
// list that serves cert-manager.io/v1, then asserts the analyzer's finding
// survives into ar.Findings (carrying no fabricated dollars) — i.e. Run threads
// the GVR union into Collect and runs analyzers after rules.
func TestRun_StackAnalyzerFindingSurvivesPipeline(t *testing.T) {
	scheme := runtime.NewScheme()
	certGVR := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	scheme.AddKnownTypeWithName(certGVR.GroupVersion().WithKind("CertificateList"), &unstructured.UnstructuredList{})

	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cert := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]interface{}{"namespace": "prod", "name": "api-tls"},
		"spec":     map[string]interface{}{"issuerRef": map[string]interface{}{"name": "le"}},
		"status": map[string]interface{}{
			"notAfter":   soon,
			"conditions": []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}},
		},
	}}
	cert.SetGroupVersionKind(certGVR.GroupVersion().WithKind("Certificate"))
	// THE CRD LIST KIND IS REGISTERED THOUGH THIS TEST IS ABOUT CERTIFICATES, because Collect reads CRDs
	// through the same dynamic client and the FAKE PANICS on an unregistered list kind where the real client
	// would return an error the step handles. That is the safe direction — a harness gap here cannot pass
	// quietly — but it means every fake dynamic client in this repository has to carry this entry.
	crdGVR := schema.GroupVersionResource{
		Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			certGVR: "CertificateList",
			crdGVR:  "CustomResourceDefinitionList",
		},
		cert,
	)
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}})
	// collect.Collect calls ServerPreferredResources(); the plain FakeDiscovery
	// returns nil there, so wrap it to serve cert-manager.io/v1 into PresentGVRs.
	disco := &fakePreferredDiscovery{
		FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}},
		preferred: []*metav1.APIResourceList{{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []metav1.APIResource{{Name: "certificates", Namespaced: true, Kind: "Certificate"}},
		}},
	}

	col := collect.NewWithClients(cs, dyn, disco)
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "test", Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, f := range ar.Findings {
		if strings.HasPrefix(f.RuleID, "stack.certmanager") {
			found = true
			if f.DollarImpactMonthly != 0 {
				t.Errorf("stack finding carried dollars: %v", f.DollarImpactMonthly)
			}
		}
	}
	if !found {
		t.Fatalf("expected a stack.certmanager.* finding in ar.Findings, got %d findings", len(ar.Findings))
	}
	// The stack DataSources note must be stamped honestly.
	joined := strings.Join(ar.Methodology.DataSources, " | ")
	if !strings.Contains(joined, "Stack CRDs: read via dynamic discovery") {
		t.Errorf("stack DataSources note missing: %v", ar.Methodology.DataSources)
	}
}

// TestRun_FakeClientsetProducesValidReport exercises the whole pipeline against
// an empty fake clientset: collect → rules → assemble → compliance → validate.
// An empty cluster yields zero findings but MUST still produce a schema-valid
// report (Run validates before returning), which is the contract cmd/shoalcheck-scan
// relies on when it marshals the result to JSON.
func TestRun_FakeClientsetProducesValidReport(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset())
	ar, err := Run(context.Background(), Options{
		Collector:   col,
		ClusterName: "fake",
		Log:         io.Discard,
	})
	if err != nil {
		t.Fatalf("Run on empty fake clientset: %v", err)
	}
	if ar == nil {
		t.Fatal("Run returned nil report without error")
	}
	if ar.SchemaVersion == "" {
		t.Error("report missing schemaVersion")
	}
	if err := ar.Validate(); err != nil {
		t.Errorf("report returned by Run must already be valid: %v", err)
	}
	// An empty cluster has zero findings, so BuildCompliance returns nil
	// (it only reports controls it observed). The contract that matters here:
	// Run still produced a schema-valid report ready to marshal to JSON.
	if len(ar.Findings) != 0 {
		t.Errorf("empty cluster must yield zero findings, got %d", len(ar.Findings))
	}
}

// TestRun_DerivesComplianceFromFindings proves Run wires
// rules.BuildCompliance onto the report: a cluster-admin ServiceAccount binding
// triggers a finding that maps to compliance controls, so Compliance must be
// non-empty.
func TestRun_DerivesComplianceFromFindings(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "danger"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "app",
				Namespace: "shop",
			}},
		},
	))
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "c", Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(ar.Findings) == 0 {
		t.Fatal("cluster-admin SA binding must produce at least one finding")
	}
	if len(ar.Compliance) == 0 {
		t.Error("Run must derive a non-empty Compliance map when findings map to controls")
	}
}

// TestRun_NilCollectorErrors verifies the required-field guard.
func TestRun_NilCollectorErrors(t *testing.T) {
	_, err := Run(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "Collector is required") {
		t.Fatalf("want Collector-required error, got %v", err)
	}
}

// TestRun_RedactTokenizesClusterName verifies the opt-in redaction path runs
// after validation and changes the cluster identity.
func TestRun_RedactTokenizesClusterName(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "secret-node-name"}},
	))
	ar, err := Run(context.Background(), Options{
		Collector:   col,
		ClusterName: "secret-cluster-name",
		Redact:      true,
		Log:         io.Discard,
	})
	if err != nil {
		t.Fatalf("Run with redact: %v", err)
	}
	if strings.Contains(ar.Cluster.Name, "secret-cluster-name") {
		t.Errorf("redaction must tokenize the cluster name, got %q", ar.Cluster.Name)
	}
}

// "neverlandcentral" IS DELIBERATE AND IS NOT A TYPO.
//
// This case used francecentral until 2026-08-31, when the pricing generator moved from four
// hand-listed Azure regions to all 69 the Retail API sells in — and francecentral became covered, so
// the assertion that an uncovered region suppresses the headline was quietly testing a covered one.
// A well-formed name no catalogue will ever carry keeps the case non-vacuous no matter how far
// coverage grows, which is the point: the suppression guard must go on being proven precisely
// BECAUSE the uncovered set is shrinking.
// TestRun_UncoveredRegionWarnsAndSuppresses is the credibility guard at the run
// boundary: an AKS cluster in a region the pricing tables don't cover
// (neverlandcentral) must (a) emit a prominent WARNING to the log/stderr and (b)
// have its misleading near-zero spend headline suppressed to the honest $0 state.
func TestRun_UncoveredRegionWarnsAndSuppresses(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: "aks-0",
			Labels: map[string]string{
				"topology.kubernetes.io/region":    "neverlandcentral",
				"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
			},
		}, Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"}},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "shop"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		},
	))
	var log bytes.Buffer
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "aks-fr", Log: &log})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := log.String()
	// A prominent, actionable WARNING naming the provider/region must be emitted.
	if !strings.Contains(out, "WARNING") {
		t.Errorf("expected a WARNING in the log, got:\n%s", out)
	}
	if !strings.Contains(out, "neverlandcentral") {
		t.Errorf("warning must name the uncovered region neverlandcentral, got:\n%s", out)
	}
	// The headline must be suppressed, not a fabricated LB/control-plane residue.
	if ar.Cluster.EstimatedMonthlySpend != 0 {
		t.Errorf("EstimatedMonthlySpend = %.2f, want 0 (suppressed)", ar.Cluster.EstimatedMonthlySpend)
	}
}

// TestRun_CoveredRegionNoWarning guards against false alarms: a covered region
// (Azure westus3) must NOT emit the uncovered-region warning.
func TestRun_CoveredRegionNoWarning(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name: "aks-0",
			Labels: map[string]string{
				"topology.kubernetes.io/region":    "westus3",
				"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
			},
		}, Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"}},
	))
	var log bytes.Buffer
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "aks-ok", Log: &log})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(log.String(), "WARNING: no pricing table") {
		t.Errorf("covered region must not warn, got:\n%s", log.String())
	}
	if ar.Cluster.EstimatedMonthlySpend <= 0 {
		t.Errorf("covered region must still price, got spend=%.2f", ar.Cluster.EstimatedMonthlySpend)
	}
}

// fakePreferredDiscovery serves a fixed ServerPreferredResources list (the
// plain FakeDiscovery returns nil there), so collect.Collect populates
// PresentGVRs and the analyzer gate opens for the seeded CRD.
type fakePreferredDiscovery struct {
	*fakediscovery.FakeDiscovery
	preferred []*metav1.APIResourceList
}

// THE LEAF TABLE AND THE REGISTRY ARE ONE TABLE OR THEY ARE A LIE.
//
// internal/ruledeps exists because cmd/shoalcheck-mcp must not import client-go and history.Compute needs the
// dependency map anyway — passing nil made every comparison refuse, with a sentence blaming the readings.
// A copied table is only safe while something fails when it drifts, which is the same contract
// internal/boundaries has with rules.TestEveryRuleCarriesABoundary and types.DataSourceValid has with
// internal/refdata.
//
// Both directions, with denominators: a producer the registry gained and the table has not, a producer the
// table kept after the registry dropped it, and any difference in what a producer rests on.
func TestRuleDeps_TableEqualsTheRegistry(t *testing.T) {
	live, leaf := HistoryDeps(), ruledeps.All()
	if len(live) == 0 {
		t.Fatal("the registry reports no producers at all, so this comparison has no denominator")
	}
	if len(leaf) != len(live) {
		t.Errorf("the leaf table holds %d producer(s) and the registry builds %d — run `make ruledeps`",
			len(leaf), len(live))
	}
	missing, extra, differ := 0, 0, 0
	for id, want := range live {
		got, ok := leaf[id]
		if !ok {
			missing++
			t.Errorf("%s is in the registry and not in the leaf table", id)
			continue
		}
		if !reflect.DeepEqual(normalizeDeps(want), normalizeDeps(got)) {
			differ++
			t.Errorf("%s rests on %+v in the registry and %+v in the leaf table", id,
				normalizeDeps(want), normalizeDeps(got))
		}
	}
	for id := range leaf {
		if _, ok := live[id]; !ok {
			extra++
			t.Errorf("%s is in the leaf table and no longer in the registry", id)
		}
	}
	t.Logf("%d producer(s) compared: %d missing, %d stale, %d differing", len(live), missing, extra, differ)
}

// normalizeDeps sorts what the registry does not promise to order, so a comparison fails on content rather
// than on map iteration.
func normalizeDeps(d history.Deps) history.Deps {
	out := history.Deps{Usage: d.Usage, Producer: d.Producer}
	out.Kinds = append([]string(nil), d.Kinds...)
	sort.Strings(out.Kinds)
	out.Datasets = append([]history.DatasetDep(nil), d.Datasets...)
	sort.Slice(out.Datasets, func(i, j int) bool { return out.Datasets[i].Name < out.Datasets[j].Name })
	return out
}
