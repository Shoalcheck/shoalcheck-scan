package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"k8s.io/client-go/rest"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

func promServer(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// A direct-URL Prometheus client goes through no client-go transport at all — its nil Transport means
// http.DefaultTransport. Without its own recorder these requests are invisible, and the identical audit
// reports a different total depending only on how it reached Prometheus.
func TestClient_DirectURLRequestsAreCounted(t *testing.T) {
	srv, served := promServer(t)
	defer srv.Close()

	rec := trace.New(nil)
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone}, WithTransportRecorder(rec))
	for i := 0; i < 3; i++ {
		if _, err := c.Query(context.Background(), "up"); err != nil {
			t.Fatalf("Query: %v", err)
		}
	}

	if got, want := rec.Tally().Total, served(); got != want {
		t.Errorf("recorder counted %d, the Prometheus server served %d", got, want)
	}
	rows, _ := rec.Since(0)
	if len(rows) == 0 || rows[0].Target != trace.TargetPrometheus || rows[0].Verb != "" {
		t.Errorf("a direct Prometheus query was not recorded as a Prometheus request: %+v", rows)
	}
}

// THE DRIFT TEST. In service-proxy mode the transport is built from the collector's own rest.Config, so it
// already carries the recorder underneath client-go's auth, user-agent and impersonation wrappers. Wrapping
// again would count every query twice — and describe it wrongly, since the row that matters is the
// Kubernetes-level `get services/proxy` the cluster's audit log will show.
//
// Built against the REAL rest.TransportFor chain, not a stub, because the deduplication walks client-go's
// WrappedRoundTripper contract. If a future client-go release stops implementing it on one of those
// wrappers, the walk stops early, the double count returns silently — and this test is what fails.
func TestClient_ServiceProxyQueriesAreCountedOnceThroughTheRealChain(t *testing.T) {
	srv, served := promServer(t)
	defer srv.Close()

	rec := trace.New(nil)
	// A config with a bearer token and impersonation, so client-go layers its real wrappers OUTSIDE ours.
	cfg := &rest.Config{
		Host:        srv.URL,
		BearerToken: "test-token",
		UserAgent:   "shoalcheck-test",
		Impersonate: rest.ImpersonationConfig{UserName: "someone"},
	}
	cfg.Wrap(rec.Wrap(trace.TargetAPIServer))
	rt, err := rest.TransportFor(cfg)
	if err != nil {
		t.Fatalf("TransportFor: %v", err)
	}
	if _, isOurs := rt.(interface{ WrappedRoundTripper() http.RoundTripper }); !isOurs {
		t.Fatal("the real chain is not walkable at all, so this test would prove nothing")
	}

	c, err := NewServiceProxyClient(cfg, Endpoint{Namespace: "monitoring", Name: "prom", Port: 9090, Scheme: "http"},
		WithTransportRecorder(rec))
	if err != nil {
		t.Fatalf("NewServiceProxyClient: %v", err)
	}
	// The proxy base URL is cfg.Host + the proxy path, which points back at the test server.
	for i := 0; i < 4; i++ {
		if _, err := c.Query(context.Background(), "up"); err != nil {
			t.Fatalf("Query: %v", err)
		}
	}

	got, want := rec.Tally().Total, served()
	if want == 0 {
		t.Fatal("no request reached the server; the fixture is wrong")
	}
	if got != want {
		t.Errorf("recorder counted %d for %d served requests — the service-proxy client is being wrapped "+
			"twice (or not at all)", got, want)
	}
	rows, _ := rec.Since(0)
	for _, q := range rows {
		if q.Target != trace.TargetAPIServer {
			t.Errorf("a service-proxy query was recorded as a Prometheus request rather than the "+
				"Kubernetes-level get services/proxy the audit log will show: %+v", q)
		}
		if q.Tuple() != "core/services/proxy" || q.Verb != "get" {
			t.Errorf("wrong canonical record for a service-proxy query: verb=%q tuple=%q", q.Verb, q.Tuple())
		}
		if q.Class != trace.ClassRead {
			t.Errorf("a GET through the service proxy is a read; got %v", q.Class)
		}
	}
}

// The recorder must not mutate a caller's http.Client. NewServiceProxyClient hands newClient a client it
// built, but a future caller may pass one it still uses.
func TestClient_RecorderDoesNotMutateTheCallersHTTPClient(t *testing.T) {
	rec := trace.New(nil)
	caller := &http.Client{}
	_ = newClient("http://x", caller, PromAuth{Mode: AuthNone}, WithTransportRecorder(rec))
	if caller.Transport != nil {
		t.Error("newClient replaced the transport on the caller's own http.Client")
	}
}
