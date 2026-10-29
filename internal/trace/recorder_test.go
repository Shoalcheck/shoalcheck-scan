package trace

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

type fnRT func(*http.Request) (*http.Response, error)

func (f fnRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// stubWrapper mimics the client-go wrappers layered OUTSIDE ours (bearer auth, user agent,
// impersonation). They all implement WrappedRoundTripper, which is what makes the chain walkable.
type stubWrapper struct{ base http.RoundTripper }

func (s stubWrapper) RoundTrip(r *http.Request) (*http.Response, error) { return s.base.RoundTrip(r) }
func (s stubWrapper) WrappedRoundTripper() http.RoundTripper            { return s.base }

func get(t *testing.T, rt http.RoundTripper, rawURL string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("bad URL: %v", err)
	}
	resp, err := rt.RoundTrip(&http.Request{Method: "GET", URL: u, Header: http.Header{}})
	if err == nil && resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

func okRT() http.RoundTripper {
	return fnRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
}

// A row must never appear before the request it describes was actually sent. This is the difference
// between a live trace and a scripted animation, and it is the one property a viewer cannot check for
// themselves — so it is pinned rather than asserted in prose.
func TestRecorder_NothingIsRecordedBeforeTheRequestResolves(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	rec := New(nil)
	rt := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))

	done := make(chan struct{})
	go func() { get(t, rt, "https://k/api/v1/pods"); close(done) }()

	<-entered
	if got, _ := rec.Since(0); len(got) != 0 {
		t.Fatalf("recorded %d request(s) while the round trip was still in flight: %+v", len(got), got)
	}
	if rec.Tally().Total != 0 {
		t.Error("the tally counted a request that had not come back yet")
	}
	close(release)
	<-done

	if got, _ := rec.Since(0); len(got) != 1 {
		t.Fatalf("after the round trip resolved, recorded %d, want 1", len(got))
	}
}

// A refused read is a request we issued. Dropping it would make the trace disagree with the audit log the
// reader is invited to check it against, and would quietly turn a coverage gap into a clean bill.
func TestRecorder_DeniedAndUnansweredCallsAppear(t *testing.T) {
	rec := New(nil)
	forbidden := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
	}))
	broken := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}))

	get(t, forbidden, "https://k/apis/rbac.authorization.k8s.io/v1/rolebindings")
	get(t, broken, "https://k/api/v1/pods")

	rows, _ := rec.Since(0)
	if len(rows) != 2 {
		t.Fatalf("recorded %d rows, want 2 (a 403 and a transport error)", len(rows))
	}
	if rows[0].Status != 403 || rows[0].Outcome != "forbidden" {
		t.Errorf("the refused read is not marked forbidden: %+v", rows[0])
	}
	if rows[1].Status != 0 || rows[1].Outcome != "no-response" {
		t.Errorf("the unanswered round trip is not marked no-response: %+v", rows[1])
	}
	ta := rec.Tally()
	if ta.Total != 2 || ta.Denied != 1 || ta.NoResponse != 1 {
		t.Errorf("tally = %+v; want Total 2, Denied 1, NoResponse 1", ta)
	}
}

// The case that would otherwise double every Prometheus query: in service-proxy mode the Prometheus
// client is built from the same rest.Config the collector uses, so its transport already carries this
// recorder from underneath. Counting again would inflate the total AND describe the request wrongly — the
// row that matters is the Kubernetes-level `get services/proxy` the cluster's audit log will show, not a
// second "prometheus" row no audit log contains.
func TestRecorder_WrappingAnAlreadyRecordedTransportCountsOnce(t *testing.T) {
	rec := New(nil)
	inner := rec.Wrap(TargetAPIServer)(okRT())
	// client-go layers its own wrappers outside ours; the chain must remain walkable through them.
	chain := stubWrapper{base: stubWrapper{base: inner}}
	outer := rec.Wrap(TargetPrometheus)(chain)

	if outer != http.RoundTripper(chain) {
		t.Fatal("the outer Wrap added a second recorder to a transport that already routes through this one")
	}
	get(t, outer, "https://k/api/v1/namespaces/monitoring/services/p:9090/proxy/api/v1/query?query=up")

	rows, _ := rec.Since(0)
	if len(rows) != 1 {
		t.Fatalf("one PromQL query produced %d rows", len(rows))
	}
	if rows[0].Target != TargetAPIServer || rows[0].Tuple() != "core/services/proxy" {
		t.Errorf("the surviving row is not the Kubernetes-level one: %+v (%s)", rows[0], rows[0].Tuple())
	}
}

// A Prometheus client that reaches Prometheus directly goes through no recorded transport, so it must get
// its own. Without this the identical audit reports wildly different totals depending only on how it
// happened to reach Prometheus.
func TestRecorder_AnUnrelatedTransportIsWrapped(t *testing.T) {
	rec := New(nil)
	rt := rec.Wrap(TargetPrometheus)(okRT())
	get(t, rt, "http://127.0.0.1:9090/api/v1/query?query=up")

	rows, _ := rec.Since(0)
	if len(rows) != 1 || rows[0].Target != TargetPrometheus || rows[0].Resource != "prometheus" {
		t.Fatalf("a direct Prometheus query was not recorded as one: %+v", rows)
	}
}

// Requests issued before the operator pressed Begin are still requests this session sent. The phase must
// travel on the record, because the alternative — presenting the run's number under a sentence beginning
// "This session" — is an undercount presented as a total.
func TestRecorder_PhaseTravelsOnTheRecord(t *testing.T) {
	rec := New(nil)
	rt := rec.Wrap(TargetAPIServer)(okRT())
	get(t, rt, "https://k/api/v1/nodes")
	rec.SetPhase(PhaseRun)
	get(t, rt, "https://k/api/v1/pods")

	rows, _ := rec.Since(0)
	if len(rows) != 2 || rows[0].Phase != PhasePreflight || rows[1].Phase != PhaseRun {
		t.Fatalf("phases = %v/%v, want pre-flight then run", rows[0].Phase, rows[1].Phase)
	}
	ta := rec.Tally()
	if ta.Preflight != 1 || ta.Run != 1 || ta.Total != 2 {
		t.Errorf("tally = %+v; want 1 pre-flight, 1 run, 2 total", ta)
	}
}

// client-go retries a throttled call above the transport, so each attempt is its own round trip. Counting
// them separately is the honest number — the cluster really was hit twice — but the appendix has to be
// able to say which rows were retries rather than distinct reads.
func TestRecorder_ARetryIsCountedAndLabelled(t *testing.T) {
	rec := New(nil)
	var n int
	rt := rec.Wrap(TargetAPIServer)(fnRT(func(r *http.Request) (*http.Response, error) {
		n++
		if n == 1 {
			return &http.Response{StatusCode: 429, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	get(t, rt, "https://k/api/v1/pods")
	get(t, rt, "https://k/api/v1/pods")

	rows, _ := rec.Since(0)
	if len(rows) != 2 {
		t.Fatalf("recorded %d rows, want 2 — a retry is a second request, not the same one", len(rows))
	}
	if rows[0].Retry {
		t.Error("the first attempt was labelled a retry")
	}
	if !rows[1].Retry {
		t.Error("the attempt following a 429 on the same tuple was not labelled a retry")
	}
	if rec.Tally().Retried != 1 {
		t.Errorf("Retried = %d, want 1", rec.Tally().Retried)
	}
}

// Discovery fans out one goroutine per group-version on servers without aggregated discovery, and Wrap is
// invoked once per client construction — eleven or more times in a single app audit. Every closure must
// share one recorder, or the tally fragments into independent streams each restarting at one.
func TestRecorder_IsSafeUnderConcurrentRoundTrips(t *testing.T) {
	rec := New(func(Request) {})
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rt := rec.Wrap(TargetAPIServer)(okRT()) // a fresh Wrap per goroutine, one shared recorder
			get(t, rt, "https://k/api/v1/pods")
		}(i)
	}
	wg.Wait()

	if got := rec.Tally().Total; got != n {
		t.Errorf("Total = %d, want %d — the tally fragmented across Wrap invocations", got, n)
	}
	rows, next := rec.Since(0)
	if len(rows) != n || next != int64(n) {
		t.Errorf("Since(0) returned %d rows, next=%d; want %d/%d", len(rows), next, n, n)
	}
	seen := map[int64]bool{}
	for _, q := range rows {
		if seen[q.Seq] {
			t.Fatalf("sequence number %d was issued twice", q.Seq)
		}
		seen[q.Seq] = true
	}
}

// The measurement must equal an independent count of the same traffic. Asserted against a real HTTP server
// counting its own requests, exactly — no tolerance, because a tolerance is where an undercount hides.
func TestRecorder_MatchesAnIndependentCountOfTheSameTraffic(t *testing.T) {
	var mu sync.Mutex
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	rec := New(nil)
	hc := &http.Client{Transport: rec.Wrap(TargetAPIServer)(http.DefaultTransport), Timeout: 5 * time.Second}
	for _, p := range []string{"/api/v1/pods", "/api/v1/nodes", "/apis/apps/v1/deployments", "/version"} {
		resp, err := hc.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	want := served
	mu.Unlock()
	if got := rec.Tally().Total; got != want {
		t.Errorf("recorder counted %d, the server served %d", got, want)
	}
}
