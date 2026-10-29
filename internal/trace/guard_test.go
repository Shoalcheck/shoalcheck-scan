package trace

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The guard is tested where it would matter: a real HTTP server counts what reached it. A refused
// request must not arrive at all, not arrive and be ignored.
func guardServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestGuard_NeverLetsASecretOrAnExecLeaveTheProcess(t *testing.T) {
	srv, hits := guardServer(t)
	rec := New(nil)
	client := &http.Client{Transport: rec.Wrap(TargetAPIServer)(http.DefaultTransport)}

	for _, path := range []string{
		"/api/v1/secrets",
		"/api/v1/namespaces/prod/secrets",
		"/api/v1/namespaces/prod/secrets/db-password",
		"/api/v1/watch/namespaces/prod/secrets",
		"/api/v1/configmaps",
		"/api/v1/namespaces/prod/configmaps/app-config",
		"/api/v1/namespaces/prod/pods/api-0/log",
		"/api/v1/namespaces/prod/pods/api-0/exec",
		"/api/v1/namespaces/prod/pods/api-0/attach",
		"/api/v1/namespaces/prod/serviceaccounts/default/token",
		"/apis/example.com/v1/namespaces/prod/secrets",
		"/API/V1/SECRETS",
		"/api/v1/namespaces/prod/secrets/",
	} {
		resp, err := client.Get(srv.URL + path)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, ErrNeverRead) {
			t.Errorf("GET %s: err = %v, want ErrNeverRead", path, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d refused request(s) reached the server; the guard must stop them before they are sent", n)
	}
	if got := rec.Tally().Total; got != 0 {
		t.Errorf("tally counts %d request(s); a request that never left the process was not issued and must not be counted against the audit log", got)
	}
}

func TestGuard_LetsTheCollectorsOwnReadsThrough(t *testing.T) {
	srv, hits := guardServer(t)
	rec := New(nil)
	api := &http.Client{Transport: rec.Wrap(TargetAPIServer)(http.DefaultTransport)}
	prom := &http.Client{Transport: rec.Wrap(TargetPrometheus)(http.DefaultTransport)}

	allowed := []struct {
		c    *http.Client
		path string
	}{
		{api, "/api/v1/pods"},
		{api, "/api/v1/namespaces/prod/pods"},
		{api, "/api/v1/namespaces"},
		{api, "/api/v1/namespaces/secrets"}, // a namespace that happens to be named "secrets"
		{api, "/apis/apps/v1/deployments"},
		{api, "/apis/rbac.authorization.k8s.io/v1/clusterroles"},
		{api, "/api/v1/namespaces/monitoring/services/prometheus:9090/proxy/api/v1/query"},
		{api, "/version"},
		{prom, "/api/v1/query"},
	}
	for _, a := range allowed {
		resp, err := a.c.Get(srv.URL + a.path)
		if err != nil {
			t.Errorf("GET %s: %v, want it to reach the server", a.path, err)
			continue
		}
		resp.Body.Close()
	}
	if n := hits.Load(); n != int64(len(allowed)) {
		t.Fatalf("%d of %d allowed reads reached the server", n, len(allowed))
	}
}

// The refusal's OWN text names only the kind. (http.Client and client-go prefix any transport error with
// the request URL; that wrapper is theirs, so the transport is called directly here.)
func TestGuard_RefusalNamesWhatItRefused(t *testing.T) {
	srv, _ := guardServer(t)
	rt := New(nil).Wrap(TargetAPIServer)(http.DefaultTransport)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/namespaces/prod/secrets/db-password", nil)
	_, err := rt.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("err = %v, want a refusal that names the resource", err)
	}
	if strings.Contains(err.Error(), "db-password") || strings.Contains(err.Error(), "prod") {
		t.Errorf("refusal %q carries an object or namespace name; it must name only the kind", err)
	}
}
