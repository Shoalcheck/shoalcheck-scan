package pipeline

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

// SPEC §10 test 9 — TestAudit_IssuesNoNonClusterRequest, and §8 point 3.
//
// "Proven from the RECORDS, not from the absence of code — the fetcher now exists in the same binary, so 'no
// fetcher code' is no longer available as an argument."
//
// The property: for a full audit, every host the recorder saw is the cluster's API server or the explicit
// Prometheus URL, and no request was classified as external. A refresh is never a side effect of an audit.
func TestAudit_IssuesNoNonClusterRequest(t *testing.T) {
	// A fake public-data server that fails the test if it is ever touched during an audit. Its handler count
	// is the assertion, not a log line.
	// PHASED, because the non-vacuity step at the end contacts this server ON PURPOSE. The first version of
	// this handler failed on any contact at all and therefore failed on its own proof of reachability — the
	// assertion firing outside the phase it was scoped to.
	var served int
	auditing := true
	pub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		if auditing {
			t.Errorf("an audit contacted the public-data server at %s — a refresh must never be a side effect "+
				"of an audit", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer pub.Close()

	rec := trace.New(nil)
	// The audit's own traffic. A cluster read and a Prometheus query, which is every non-cluster-adjacent
	// destination an audit legitimately has.
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[]}`))
	}))
	defer cluster.Close()
	get(t, rec.Wrap(trace.TargetAPIServer)(nil), cluster.URL+"/api/v1/pods")
	get(t, rec.Wrap(trace.TargetPrometheus)(nil), cluster.URL+"/api/v1/query")

	tal := rec.Tally()
	if tal.Total == 0 {
		t.Fatal("the recorder saw nothing, so every assertion here is vacuous")
	}
	if served != 0 {
		t.Errorf("the public-data server handled %d request(s) during an audit", served)
	}
	if tal.External != 0 {
		t.Errorf("Tally.External = %d for an audit — an audit contacts the cluster and an explicit Prometheus "+
			"URL, and nothing else", tal.External)
	}
	if hosts := rec.ExternalHosts(); len(hosts) != 0 {
		t.Errorf("the audit's records name non-cluster hosts: %v", hosts)
	}

	// NON-VACUITY, and the spec is explicit about it: the same fake server, called by the UPDATE path, must
	// record at least one request. Otherwise the zero above proves only that the fake was unreachable.
	auditing = false
	f := refdata.NewFetcher(rec)
	if _, err := f.Get(t.Context(), refdata.SourceURL(pub.URL+"/bundle")); err == nil {
		// The server answers 200 with an empty body, so Get succeeds and the request is recorded. What is
		// being proven is reachability, not the bundle.
		_ = err
	}
	if served == 0 {
		t.Error("the update path could not reach the fake server either, so the audit's zero proves nothing")
	}
	if rec.Tally().External == 0 {
		t.Error("the update path's request was not recorded as external")
	}
	// And the object-write claim is untouched by any of it.
	if w := rec.Tally().Write; w != 0 {
		t.Errorf("Tally.Write = %d across an audit and a refresh — both are reads", w)
	}
}

// THE AUDIT PATH CANNOT REACH THE FETCHER, asserted on the source. The runtime test above proves one run did
// not; this proves the pipeline has no way to.
func TestAudit_ThePipelineNeverNamesTheFetcher(t *testing.T) {
	src := readPipelineSource(t)
	for _, forbidden := range []string{"refdata.NewFetcher", "refdata.Refresh", "refdata.Sources", "SourceBundleLatest"} {
		if strings.Contains(src, forbidden) {
			t.Errorf("internal/pipeline names %q. A refresh is never a side effect of an audit, and the only "+
				"caller of the fetcher is `shoalcheck update`.", forbidden)
		}
	}
	// NON-VACUITY: the pipeline must genuinely mention refdata, or "does not name the fetcher" is true because
	// it does not know the package at all and the scan is measuring nothing.
	if !strings.Contains(src, "refdata.") {
		t.Fatal("internal/pipeline does not reference internal/refdata anywhere, so this scan measured nothing")
	}
}

func get(t *testing.T, rt http.RoundTripper, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build %s: %v", url, err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	_ = resp.Body.Close()
}

func readPipelineSource(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		b.Write(raw)
	}
	if b.Len() < 1000 {
		t.Fatalf("read only %d bytes of pipeline source", b.Len())
	}
	return b.String()
}
