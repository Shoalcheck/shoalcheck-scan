package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

// fakeAPIServer answers the shapes a collection issues and counts its own requests. It is the independent
// count: a tally we verify with our own bookkeeping proves nothing, so the assertion is against a number
// produced outside the recorder entirely.
func fakeAPIServer(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api":
			json.NewEncoder(w).Encode(map[string]any{"kind": "APIVersions", "versions": []string{"v1"}})
		case "/apis":
			json.NewEncoder(w).Encode(map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{}})
		case "/version":
			json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "31", "gitVersion": "v1.31.0"})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "v1", "kind": "List", "metadata": map[string]any{}, "items": []any{},
			})
		}
	}))
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

func kubeconfigFor(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: k, cluster: {server: %s}}]
users: [{name: u, user: {}}]
contexts: [{name: c, context: {cluster: k, user: u}}]
current-context: c
`, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// The count cannot be an undercount. Every HTTP request a collection sends must appear exactly once —
// asserted against the server's own count, exactly, with no tolerance, because a tolerance is precisely
// where an undercount would hide.
func TestCollect_RecorderCountsEveryRequestExactlyOnce(t *testing.T) {
	srv, served := fakeAPIServer(t)
	defer srv.Close()

	rec := trace.New(nil)
	c, err := New(kubeconfigFor(t, srv.URL), "c", WithTransportRecorder(rec))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.WrapTransport == nil {
		t.Fatal("the recorder was not installed on the rest.Config")
	}
	if _, err := c.Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want, got := served(), rec.Tally().Total
	if want == 0 {
		t.Fatal("the fake API server was never called, so this test would pass without measuring anything")
	}
	if got != want {
		t.Errorf("recorder counted %d requests, the server served %d — the typed, dynamic or discovery "+
			"client is bypassing the recorder", got, want)
	}
	if w := rec.Tally().Write; w != 0 {
		t.Errorf("a collection recorded %d object write(s); a read-only audit must record none", w)
	}
}

// Why the option exists, stated as a test so nobody simplifies it away.
//
// kubernetes.NewForConfig takes a SHALLOW COPY of the config and freezes its http.Client at construction
// (clientset.go: configShallowCopy := *c, then rest.HTTPClientFor). Installing the recorder afterwards —
// the obvious move, since Collector already exposes RESTConfig() and already has a post-construction
// setter in SetOnStep — mutates a config nobody reads again. The result is the worst possible state: a
// recorder that looks installed, reports a plausible number, and has silently missed the entire
// collection.
func TestCollect_ARecorderInstalledAfterConstructionSeesNothing(t *testing.T) {
	srv, served := fakeAPIServer(t)
	defer srv.Close()

	late := trace.New(nil)
	c, err := New(kubeconfigFor(t, srv.URL), "c") // no option: clients are already built
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.RESTConfig().Wrap(late.Wrap(trace.TargetAPIServer)) // too late, by construction
	if _, err := c.Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if served() == 0 {
		t.Fatal("the fake API server was never called; this test cannot demonstrate anything")
	}
	if got := late.Tally().Total; got != 0 {
		t.Fatalf("a late-installed recorder counted %d requests — if this now works, the option in New "+
			"may be unnecessary, but verify against the client-go version before removing it", got)
	}
}

// The recorder must COMPOSE with whatever wrapper the kubeconfig's auth provider already installed.
// Assignment would destroy it, and the failure mode is authentication breaking on exactly the managed
// clusters this tool is for — an EKS or AKS kubeconfig whose exec provider installs a wrapper of its own.
//
// Asserted at the source, because reproducing an auth provider in a test would require a kubeconfig whose
// provider still exists in this client-go version, and the decision being pinned is a one-line one.
func TestCollect_RecorderIsComposedNotAssigned(t *testing.T) {
	src, err := os.ReadFile("collect.go")
	if err != nil {
		t.Fatalf("read collect.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, "cfg.WrapTransport =") {
		t.Error("collect.go ASSIGNS cfg.WrapTransport, which discards any wrapper an auth provider " +
			"already installed; use cfg.Wrap to compose")
	}
	if !strings.Contains(s, "cfg.Wrap(") {
		t.Error("collect.go does not install the recorder with cfg.Wrap")
	}
	// And the install must precede the first client construction, or it is frozen out (see the test above).
	wrapAt := strings.Index(s, "cfg.Wrap(")
	clientAt := strings.Index(s, "kubernetes.NewForConfig(cfg)")
	if wrapAt < 0 || clientAt < 0 || wrapAt > clientAt {
		t.Error("the recorder is installed at or after the first client construction, where it is frozen out")
	}
}

// A sanity floor on the equality assertion above: a collection must issue a substantial number of
// requests, or "counted == served" could hold at one and prove nothing.
func TestCollect_RecorderCountIsNotTrivial(t *testing.T) {
	srv, served := fakeAPIServer(t)
	defer srv.Close()

	rec := trace.New(nil)
	c, err := New(kubeconfigFor(t, srv.URL), "c", WithTransportRecorder(rec))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Collect(context.Background(), nil); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	ta := rec.Tally()
	t.Logf("collection issued %d requests (server served %d); by tuple: %v", ta.Total, served(), ta.ByTuple)
	if ta.Total < 15 {
		t.Errorf("a full collection issued only %d requests — the fixture is not exercising the collector", ta.Total)
	}
}
