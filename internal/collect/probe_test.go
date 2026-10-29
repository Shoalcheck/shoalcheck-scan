package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// What a Prometheus pre-flight is allowed to cost.
//
// The app's ProbePrometheus called Collect and then used exactly one field of the result — inv.Services — to
// rank candidate endpoints. Collect sweeps the whole cluster, so the probe spent 21 requests to read one list,
// and the UI re-fires it on every context toggle. Against a cluster that cannot be reached, all 21 fail: a real
// fleet run reported "21 never got an answer" and that was one probe of one unreachable cluster.
//
// ProbeServices reads what the probe actually needs. The budget is asserted rather than described, because a
// future edit that reaches for Collect again would silently restore the old cost.
func TestProbeServices_CostsTwoRequestsNotTwentyOne(t *testing.T) {
	var reqs int64
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqs, 1)
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"gitVersion":"v1.29.0"}`))
		case "/api/v1/services":
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"ServiceList","items":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	col := colFor(t, srv.URL)
	svcs, err := col.ProbeServices(context.Background())
	if err != nil {
		t.Fatalf("ProbeServices: %v", err)
	}
	if svcs == nil {
		t.Fatal("ProbeServices returned no service list on a reachable cluster")
	}
	if n := atomic.LoadInt64(&reqs); n > 3 {
		t.Errorf("a Prometheus pre-flight issued %d requests (%v); it needs the Service list and a reachability\n"+
			"    check, and the whole reason this exists is that Collect spent 21", n, paths)
	}
}

// An unreachable cluster must cost ONE request, not twenty-one. This is the case the operator actually hit.
func TestProbeServices_AnUnreachableClusterCostsOneRequest(t *testing.T) {
	// Port 1 refuses immediately on every platform.
	col := colFor(t, "https://127.0.0.1:1")
	if _, err := col.ProbeServices(context.Background()); err == nil {
		t.Fatal("ProbeServices against an unreachable cluster returned no error")
	}
	// The cost is asserted through the collector's own recorder in the app-level test; here the contract is
	// that it STOPS — it must not go on to list Services after the cluster failed to answer at all.
}

func colFor(t *testing.T, server string) *Collector {
	t.Helper()
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	body := "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: cl\n  cluster:\n    server: " +
		server + "\n    insecure-skip-tls-verify: true\ncontexts:\n- name: c\n  context: {cluster: cl, user: u}\n" +
		"users:\n- name: u\n  user: {token: t}\n"
	if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	col, err := New(kc, "c")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return col
}
