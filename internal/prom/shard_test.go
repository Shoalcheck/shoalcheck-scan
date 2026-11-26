package prom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// limitedProm is a Prometheus that enforces what a real one does (ENG-05): a query whose samples exceed maxSamples
// is refused with Prometheus's own 422 and message, and each query costs latency per sample, past which this
// side's timeout fires. Samples are counted as a real engine loads them: containers × points in the window.
type limitedProm struct {
	namespaces map[string]int // namespace → containers
	maxSamples int
	perPoint   time.Duration // latency per loaded sample, 0 for none
	queries    atomic.Int64
}

var (
	nsMatcher  = regexp.MustCompile(`namespace=~"([^"]*)"`)
	windowExpr = regexp.MustCompile(`\[(\d+)d(?::5m)?\]`)
)

func (p *limitedProm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.queries.Add(1)
	q := r.URL.Query().Get("query")
	w.Header().Set("Content-Type", "application/json")
	vector := func(rows []any) {
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": rows}})
	}
	if strings.HasPrefix(q, "count by (namespace)") {
		var rows []any
		for ns, n := range p.namespaces {
			rows = append(rows, map[string]any{"metric": map[string]string{"namespace": ns}, "value": []any{0, fmt.Sprint(n)}})
		}
		vector(rows)
		return
	}
	selected := p.namespaces
	if m := nsMatcher.FindStringSubmatch(q); m != nil {
		selected = map[string]int{}
		for _, ns := range strings.Split(m[1], "|") {
			selected[ns] = p.namespaces[ns]
		}
	}
	days := 7
	if m := windowExpr.FindStringSubmatch(q); m != nil {
		fmt.Sscanf(m[1], "%d", &days)
	}
	containers := 0
	for _, n := range selected {
		containers += n
	}
	samples := containers * days * 24 * 12 // a 5-minute step
	if samples > p.maxSamples {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{"status": "error", "errorType": "execution",
			"error": "query processing would load too many samples into memory in query execution"})
		return
	}
	if p.perPoint > 0 {
		select {
		case <-time.After(time.Duration(samples) * p.perPoint):
		case <-r.Context().Done():
			return
		}
	}
	var rows []any
	for ns, n := range selected {
		for i := 0; i < n; i++ {
			rows = append(rows, map[string]any{"metric": map[string]string{"namespace": ns, "pod": fmt.Sprintf("p-%d", i),
				"container": "c"}, "value": []any{0, "0.5"}})
		}
	}
	vector(rows)
}

// A CLUSTER TOO BIG FOR ONE QUERY IS READ IN SHARDS, AND A NAMESPACE TOO BIG FOR A WEEK IS READ OVER A SHORTER
// WINDOW AND SAID SO. The single query this replaced is refused outright by the same server.
func TestUsageSharded_ReadsWhatOneQueryCannot(t *testing.T) {
	p := &limitedProm{namespaces: map[string]int{}, maxSamples: 5_000_000}
	for i := 0; i < 300; i++ {
		p.namespaces[fmt.Sprintf("team-%03d", i)] = 100 // 30,000 containers
	}
	p.namespaces["batch"] = 4000 // 4000 × 7d = 8M samples: refused at a week, read over 3d (3.5M)
	srv := httptest.NewServer(p)
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})

	// The unsharded query, as the engine asked before: refused.
	if _, err := c.Query(context.Background(), `quantile_over_time(0.95, rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[5m])[7d:5m])`); err == nil ||
		!strings.Contains(err.Error(), "too many samples") {
		t.Fatalf("the double does not refuse the single query: %v", err)
	}

	u, rep, err := c.UsageSharded(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Namespaces != 301 || rep.Read != 301 || len(rep.Unread) != 0 {
		t.Fatalf("coverage: %+v", rep)
	}
	if rep.Shorter["3d"] != 1 {
		t.Fatalf("batch should be read over 3d: %+v", rep.Shorter)
	}
	if len(u) != 34000 {
		t.Fatalf("%d containers read, want 34000", len(u))
	}
	if got := u["batch/p-0/c"].Window; got != "3d" {
		t.Fatalf("batch's window is %q", got)
	}
	if got := u["team-000/p-0/c"].Window; got != "7d" {
		t.Fatalf("team-000's window is %q", got)
	}
	if lines := rep.Coverage(); len(lines) != 1 || !strings.Contains(lines[0], "1 of 301 namespaces were read over 3d, not 7d") {
		t.Fatalf("coverage sentence: %q", lines)
	}
}

// A NAMESPACE NO WINDOW CAN READ IS NAMED, AND THE REST ARE STILL READ.
func TestUsageSharded_NamesWhatNoWindowCouldRead(t *testing.T) {
	p := &limitedProm{namespaces: map[string]int{"small": 10, "huge": 50_000}, maxSamples: 5_000_000}
	srv := httptest.NewServer(p)
	defer srv.Close()
	u, rep, err := NewClient(srv.URL, PromAuth{Mode: AuthNone}).UsageSharded(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Read != 1 || len(rep.Unread) != 1 || rep.Unread[0] != "huge" || len(u) != 10 {
		t.Fatalf("read %d, unread %v, %d containers", rep.Read, rep.Unread, len(u))
	}
	if lines := rep.Coverage(); len(lines) != 1 || !strings.Contains(lines[0], "usage was read for 1 of 2 namespaces") ||
		strings.Contains(lines[0], "huge") {
		t.Fatalf("coverage sentence must count, never name: %q", lines)
	}
	if !strings.Contains(rep.UnreadSaid(), "huge") {
		t.Fatalf("the log line does not name the unread namespace: %q", rep.UnreadSaid())
	}
}

// A NON-SIZE ERROR IS NOT RETRIED SMALLER: a refused credential on one shard fails the read, as before.
func TestUsageSharded_ANonSizeErrorIsNotRetried(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(q, "count by (namespace)") {
			json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector",
				"result": []any{map[string]any{"metric": map[string]string{"namespace": "a"}, "value": []any{0, "3"}}}}})
			return
		}
		n.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"status": "error", "errorType": "bad_data", "error": "parse error"})
	}))
	defer srv.Close()
	if _, _, err := NewClient(srv.URL, PromAuth{Mode: AuthNone}).UsageSharded(context.Background()); err == nil {
		t.Fatal("a bad_data error must fail the read")
	}
	if n.Load() != 1 {
		t.Fatalf("a non-size error was retried: %d usage queries", n.Load())
	}
}

func TestTooBig_KnowsTheBackendsRefusals(t *testing.T) {
	ctx := context.Background()
	for _, msg := range []string{
		"prom: query failed: execution: query processing would load too many samples into memory in query execution",
		"prom: query failed: timeout: query timed out in expression evaluation",
		"prom: query request: context deadline exceeded",
		"prom: query failed: execution: the query exceeded the maximum number of chunks",
		"cannot select more than -search.maxSamplesPerQuery=1000000000 samples",
	} {
		if !tooBig(ctx, fmt.Errorf("%s", msg)) {
			t.Errorf("not recognised as a size refusal: %s", msg)
		}
	}
	for _, msg := range []string{"prom: query failed: bad_data: parse error", "prom: query request: connection refused"} {
		if tooBig(ctx, fmt.Errorf("%s", msg)) {
			t.Errorf("retried smaller although size is not the cause: %s", msg)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if tooBig(cancelled, context.DeadlineExceeded) {
		t.Error("a cancelled run was retried")
	}
}

// A SHARD TOO SLOW FOR THE TIMEOUT IS RETRIED OVER A SHORTER WINDOW: latency, not only the sample limit, is a refusal.
func TestUsageSharded_ATimeoutStepsDownTheLadder(t *testing.T) {
	old := shardQueryTimeout
	shardQueryTimeout = 300 * time.Millisecond
	defer func() { shardQueryTimeout = old }()
	// 50 containers: 7d is 100,800 samples (500 ms at 5 µs each, past the timeout), 3d is 43,200 (216 ms).
	p := &limitedProm{namespaces: map[string]int{"slow": 50}, maxSamples: 50_000_000, perPoint: 5 * time.Microsecond}
	srv := httptest.NewServer(p)
	defer srv.Close()
	u, rep, err := NewClient(srv.URL, PromAuth{Mode: AuthNone}).UsageSharded(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Shorter["3d"] != 1 || len(u) != 50 || u["slow/p-0/c"].Window != "3d" {
		t.Fatalf("want slow read over 3d: %+v, %d containers", rep, len(u))
	}
}
