package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/rest"
)

// TestNewServiceProxyClient_PathAndVerb points rest.Config.Host at an httptest
// server and asserts (a) the exact service-proxy path is used for both
// /status/buildinfo (Ping) and /api/v1/query, (b) the colons in
// <scheme>:<name>:<port> are NOT percent-encoded, and (c) only GET is ever
// issued.
func TestNewServiceProxyClient_PathAndVerb(t *testing.T) {
	const wantPrefix = "/api/v1/namespaces/monitoring/services/http:prometheus:9090/proxy"
	var sawMethods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethods = append(sawMethods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case wantPrefix + "/api/v1/status/buildinfo":
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45.0"}})
		case wantPrefix + "/api/v1/query":
			json.NewEncoder(w).Encode(map[string]any{
				"status": "success",
				"data":   map[string]any{"resultType": "vector", "result": []any{}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := NewServiceProxyClient(&rest.Config{Host: srv.URL}, Endpoint{
		Namespace: "monitoring", Name: "prometheus", Port: 9090, Scheme: "http",
	})
	if err != nil {
		t.Fatalf("NewServiceProxyClient: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping over proxy: %v", err)
	}
	if _, err := c.Query(context.Background(), "up"); err != nil {
		t.Fatalf("Query over proxy: %v", err)
	}
	if len(sawMethods) == 0 {
		t.Fatal("server saw no requests — proxy path likely wrong")
	}
	for _, m := range sawMethods {
		if m != http.MethodGet {
			t.Errorf("service-proxy must only GET, saw %q", m)
		}
	}
}

// TestNewServiceProxyClient_TrailingSlashHost guards the cfg.Host TrimRight.
func TestNewServiceProxyClient_TrailingSlashHost(t *testing.T) {
	c, err := NewServiceProxyClient(&rest.Config{Host: "https://api.example.com/"}, Endpoint{
		Namespace: "obs", Name: "thanos-query", Port: 10902, Scheme: "http",
	})
	if err != nil {
		t.Fatalf("NewServiceProxyClient: %v", err)
	}
	const want = "https://api.example.com/api/v1/namespaces/obs/services/http:thanos-query:10902/proxy"
	if c.baseURL != want {
		t.Errorf("baseURL = %q, want %q", c.baseURL, want)
	}
}

// TestConnectModeValues locks the disclosed connect-mode labels: the report's
// methodology stamp depends on these exact strings.
func TestConnectModeValues(t *testing.T) {
	if ModeServiceProxy != "api-server-proxy" {
		t.Errorf("ModeServiceProxy = %q, want api-server-proxy", ModeServiceProxy)
	}
	if ModePortForward != "port-forward" {
		t.Errorf("ModePortForward = %q, want port-forward", ModePortForward)
	}
	if ModeDirectURL != "direct-url" {
		t.Errorf("ModeDirectURL = %q, want direct-url", ModeDirectURL)
	}
}

// TestDialFirstServiceProxy_SkipsUnreachableCandidates is the transport half of the
// B-002 regression. Ranking alone cannot be trusted to identify a query API, so the
// caller must confirm by dialling: given the operator's webhook endpoint first and the
// real Prometheus second, the dialer must skip the former and return the latter.
func TestDialFirstServiceProxy_SkipsUnreachableCandidates(t *testing.T) {
	const realPrefix = "/api/v1/namespaces/monitoring/services/http:kps-kube-prometheus-prometheus:9090/proxy"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == realPrefix+"/api/v1/status/buildinfo" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"version": "2.45.0"}})
			return
		}
		// Everything else — notably the operator's 443 webhook — is not Prometheus.
		http.NotFound(w, r)
	}))
	defer srv.Close()

	candidates := []Endpoint{
		{Namespace: "monitoring", Name: "kps-kube-prometheus-operator", Port: 443, Scheme: "https"},
		{Namespace: "monitoring", Name: "kps-kube-prometheus-prometheus", Port: 9090, Scheme: "http"},
	}
	c, ep, err := DialFirstServiceProxy(context.Background(), &rest.Config{Host: srv.URL}, candidates)
	if err != nil {
		t.Fatalf("DialFirstServiceProxy: %v (tried paths: %v)", err, paths)
	}
	if c == nil {
		t.Fatal("returned a nil client with no error")
	}
	if ep.Name != "kps-kube-prometheus-prometheus" || ep.Port != 9090 {
		t.Errorf("landed on %s:%d, want kps-kube-prometheus-prometheus:9090", ep.Name, ep.Port)
	}
	if len(paths) < 2 {
		t.Errorf("expected the unreachable candidate to be tried and skipped; paths = %v", paths)
	}
}

// TestDialFirstServiceProxy_NoneReachable must fail honestly rather than hand back a
// client that cannot answer PromQL.
func TestDialFirstServiceProxy_NoneReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, _, err := DialFirstServiceProxy(context.Background(), &rest.Config{Host: srv.URL}, []Endpoint{
		{Namespace: "monitoring", Name: "nope", Port: 9090, Scheme: "http"},
	})
	if err == nil {
		t.Fatal("want an error when no candidate answers, got nil")
	}
}
