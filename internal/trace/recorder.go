package trace

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives each completed request. It is called synchronously, after the round trip returned, so a
// slow sink slows the audit — keep it to an append and a channel send.
type Sink func(Request)

// Tally is the running summary. Read it through Recorder.Tally, which returns a copy.
type Tally struct {
	Total     int
	Preflight int
	Run       int

	Read   int
	Stream int
	// Write is ClassWrite AGAINST THE API SERVER, and only that. It is the number every "zero object
	// writes" claim in this product is rendered from, so it is computed with the target restriction rather
	// than trusting the classifier to keep other destinations out of ClassWrite. A POST to a SaaS counted
	// here would make the read-only claim false while every test about the claim still passed.
	Write int
	// External is ClassExternal — a request to a system the operator configured that is not the cluster.
	// Counted, named on its own line, folded into neither cluster total. See ClassExternal.
	External int
	// OffTargetWrite is the home for a case that should be unreachable: a ClassWrite on a target that is
	// not the API server. It exists because Total must always equal the sum of its parts — the same rule
	// the report's headline follows — and restricting Write by target could otherwise have DROPPED such a
	// request silently, which is worse than miscounting it. If this is ever non-zero, Classify has a hole
	// and the fix is a class for that target, never a wider object-write total.
	OffTargetWrite int

	// Denied counts requests the server refused (403). It is reported beside Total rather than folded
	// into it: a refused read is a request we issued, and hiding it would make the trace disagree with
	// the audit log the reader is invited to check it against.
	Denied int
	// NoResponse counts round trips that never got an answer — a cancelled context, a refused
	// connection, a timeout. Also issued, also counted.
	NoResponse int
	// NoResponsePreflight and NoResponseByCluster attribute those failures, because the bare count is a dead
	// end for the person reading it.
	//
	// A real 3-cluster fleet run reported "21 never got an answer" and nothing else, and the operator could
	// not tell whether the audit had failed or something before it had. The difference is total: reproduced,
	// ONE pre-flight probe of ONE unreachable cluster issues exactly 21 requests and none of them is
	// answered, while all 99 audit requests came back ok. So the honest reading was "a cluster you clicked on
	// never replied", and the sentence read like data loss in the audit.
	NoResponsePreflight int
	NoResponseByCluster map[string]int
	// Retried counts requests that repeat a tuple whose previous attempt was throttled or failed, so an
	// appendix can separate a retry from a distinct read.
	Retried int

	// ByTuple counts requests per RBAC unit. A copy; safe to mutate.
	ByTuple map[string]int
	// ByVerbTuple counts per (verb, tuple), which is the grouping the appendix prints.
	ByVerbTuple map[string]int
}

// classify is the ONE place a request becomes a class line, so the running tally and TallySince cannot
// disagree about what an object write is. They were two copies of the same switch, and a target restriction
// applied to one of them would have made the app's live counter and the report's appendix report different
// numbers for the same run.
//
// Exhaustive on purpose: every branch increments exactly one counter and there is no path that increments
// none. See Tally.OffTargetWrite for the branch that should be unreachable.
func classify(t *Tally, q Request) {
	switch {
	case q.Class == ClassRead:
		t.Read++
	case q.Class == ClassStream:
		t.Stream++
	case q.Class == ClassExternal:
		t.External++
	case q.Target == TargetAPIServer:
		t.Write++
	default:
		t.OffTargetWrite++
	}
}

// Recorder observes every request issued through the transports it wraps.
//
// It is PROCESS-level, not run-level. The app probes the cluster before the operator presses Begin — a
// full collection per Prometheus probe, re-fired on every context toggle — so a recorder created per run
// would undercount the session substantially while presenting the number as the session total.
type Recorder struct {
	mu      sync.Mutex
	reqs    []Request
	tally   Tally
	pending map[string]bool // tuple+verb whose last attempt was throttled or failed

	seq     atomic.Int64
	phase   atomic.Uint32
	cluster atomic.Value // string

	sink Sink
}

// New returns a Recorder. sink may be nil.
func New(sink Sink) *Recorder {
	r := &Recorder{
		pending: map[string]bool{},
		sink:    sink,
		tally:   Tally{ByTuple: map[string]int{}, ByVerbTuple: map[string]int{}, NoResponseByCluster: map[string]int{}},
	}
	r.cluster.Store("")
	return r
}

// SetPhase marks subsequent requests as pre-flight or run.
func (r *Recorder) SetPhase(p Phase) { r.phase.Store(uint32(p)) }

// SetCluster attributes subsequent requests to a cluster, for a fleet run. The fleet loop is sequential,
// so one recorder with a moving label is correct; a parallel fleet would need one recorder per cluster.
func (r *Recorder) SetCluster(name string) { r.cluster.Store(name) }

// Seq returns the number of requests recorded so far. A run stores this at its start so it can present its
// own slice of a process-level journal without owning one.
func (r *Recorder) Seq() int64 { return r.seq.Load() }

// wrapped is client-go's RoundTripperWrapper contract, duck-typed here so this package stays a
// stdlib-only leaf. Every wrapper client-go layers around ours — bearer auth, user agent, impersonation,
// the debug wrapper — implements it.
type wrapped interface {
	WrappedRoundTripper() http.RoundTripper
}

type roundTripper struct {
	rec    *Recorder
	target Target
	base   http.RoundTripper
}

func (t *roundTripper) WrappedRoundTripper() http.RoundTripper { return t.base }

// Wrap returns a transport wrapper. Install it via rest.Config.Wrap (never by assigning WrapTransport,
// which would destroy an auth provider's own wrapper) or around an http.Client's Transport.
//
// If the transport being wrapped ALREADY passes through this recorder, Wrap returns it unchanged. That
// case is real and not defensive: a Prometheus client reached through the API server's service proxy is
// built from the same rest.Config the collector uses, so its transport already carries this recorder from
// underneath. Wrapping again would count every PromQL query twice — and would count it under the wrong
// description, because the record that matters is the Kubernetes-level `get services/proxy` that the
// cluster's own audit log will show, not a second "prometheus" row that no audit log contains.
//
// The check walks the wrapper chain rather than trusting the call site to know its own mode. A call site
// that has to remember drifts; a structural check cannot. If a future client-go wrapper stops
// implementing WrappedRoundTripper the walk stops early and the double count returns, which is why
// internal/prom pins this against the REAL rest.TransportFor chain rather than against a fake.
func (r *Recorder) Wrap(t Target) func(http.RoundTripper) http.RoundTripper {
	return func(base http.RoundTripper) http.RoundTripper {
		if base == nil {
			base = http.DefaultTransport
		}
		if r.records(base) {
			return base
		}
		return &roundTripper{rec: r, target: t, base: base}
	}
}

// records reports whether rt already routes through this recorder. The bound exists so a wrapper that
// returns itself cannot spin.
func (r *Recorder) records(rt http.RoundTripper) bool {
	for i := 0; rt != nil && i < 32; i++ {
		if ours, ok := rt.(*roundTripper); ok && ours.rec == r {
			return true
		}
		w, ok := rt.(wrapped)
		if !ok {
			return false
		}
		rt = w.WrappedRoundTripper()
	}
	return false
}

// RoundTrip records AFTER the request has been sent and resolved.
//
// That ordering is the whole honesty of the live ticker: a row appears only once the request actually went
// out and something came back, so nothing on screen is ever a request we merely intended. The cost is
// stated rather than hidden — a five-hundred-millisecond list shows up five hundred milliseconds late, so
// the ticker lags reality slightly. That is a pacing cost, not an honesty cost, and pacing loses.
//
// The response is passed through UNTOUCHED: not read, not buffered, not closed, not replaced. The
// port-forward upgrade depends on receiving the real *http.Response with its hijacked connection, and a
// recorder that helpfully inspected the body would break the opt-in fallback while the blame landed on
// the operator's cluster.
func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if what := refusal(t.target, req.URL); what != "" {
		// The RoundTripper contract: the request body is closed even when the request is not sent.
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("%w %s", ErrNeverRead, what)
	}
	start := time.Now()
	resp, err := t.base.RoundTrip(req)

	rec := Classify(t.target, req.Method, req.URL)
	rec.Duration = int64(time.Since(start))
	switch {
	case err != nil:
		rec.Status, rec.Outcome = 0, "no-response"
	default:
		rec.Status = resp.StatusCode
		rec.Outcome = outcomeOf(resp.StatusCode)
	}
	t.rec.record(rec)
	return resp, err
}

func outcomeOf(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "ok"
	// 401 is a REJECTED CREDENTIAL, and it used to fall through to "other" — the one value in this
	// vocabulary that cannot be checked against anything. An expired EKS token and a wrong tracker API key
	// are both common and both diagnostic, and the trace exists to be read against the destination's own
	// access log. Named after folding internal/tracker's ledger in here silently downgraded it: that
	// package's own mapping had it and this one did not, and seven tests passed across the change.
	case code == 401:
		return "unauthorized"
	case code == 403:
		return "forbidden"
	case code == 404:
		return "not-found"
	case code == 429:
		return "throttled"
	case code >= 500:
		return "server-error"
	default:
		return "other"
	}
}

func (r *Recorder) record(rec Request) {
	rec.Seq = r.seq.Add(1)
	rec.Phase = Phase(r.phase.Load())
	if s, ok := r.cluster.Load().(string); ok {
		rec.Cluster = s
	}

	// The retry key includes the DESTINATION and the CLUSTER, not just the verb and resource. Without them a
	// first list against the second cluster of a fleet looked like a retry of the first cluster's, and the
	// report would say a request was repeated after a throttle that never happened.
	key := fmt.Sprintf("%d|%s|%s %s", rec.Target, rec.Cluster, rec.Verb, rec.Tuple())
	retryable := rec.Status == 429 || rec.Status >= 500 || rec.Status == 0

	r.mu.Lock()
	if r.pending[key] {
		rec.Retry = true
		r.tally.Retried++
	}
	// A throttled or unanswered attempt arms the flag: client-go's retry loop sits ABOVE the transport
	// (rest.Request retries a 429 or 5xx with a parseable Retry-After up to ten times), so each attempt
	// is its own round trip and the next one with the same tuple is that retry. Anything that deduped
	// them would hide that the cluster was hit twice.
	r.pending[key] = retryable

	r.tally.Total++
	if rec.Phase == PhaseRun {
		r.tally.Run++
	} else {
		r.tally.Preflight++
	}
	classify(&r.tally, rec)
	if rec.Outcome == "forbidden" {
		r.tally.Denied++
	}
	if rec.Outcome == "no-response" {
		r.tally.NoResponse++
		if rec.Phase != PhaseRun {
			r.tally.NoResponsePreflight++
		}
		if r.tally.NoResponseByCluster == nil {
			r.tally.NoResponseByCluster = map[string]int{}
		}
		r.tally.NoResponseByCluster[rec.Cluster]++
	}
	r.tally.ByTuple[rec.Tuple()]++
	r.tally.ByVerbTuple[key]++
	r.reqs = append(r.reqs, rec)
	sink := r.sink
	r.mu.Unlock()

	if sink != nil {
		sink(rec)
	}
}

// TallySince summarises only the requests recorded AFTER cursor.
//
// A report is about one audit, and the sentence above its appendix says "issued while producing this report".
// The recorder is process-level, so on a second run in the same app session the whole-process tally would put
// the first run's requests into the second run's report — the report would claim traffic it did not cause.
// The run passes the recorder's sequence at its own start, and gets the window that belongs to it, including
// the pre-flight probing that preceded it and excluding everything before that.
func (r *Recorder) TallySince(cursor int64) Tally {
	r.mu.Lock()
	rows := append([]Request(nil), r.reqs...)
	r.mu.Unlock()

	t := Tally{ByTuple: map[string]int{}, ByVerbTuple: map[string]int{}, NoResponseByCluster: map[string]int{}}
	for _, q := range rows {
		if q.Seq <= cursor {
			continue
		}
		t.Total++
		if q.Phase == PhaseRun {
			t.Run++
		} else {
			t.Preflight++
		}
		classify(&t, q)
		switch q.Outcome {
		case "forbidden":
			t.Denied++
		case "no-response":
			t.NoResponse++
			if q.Phase != PhaseRun {
				t.NoResponsePreflight++
			}
			t.NoResponseByCluster[q.Cluster]++
		}
		if q.Retry {
			t.Retried++
		}
		t.ByTuple[q.Tuple()]++
		t.ByVerbTuple[q.Verb+" "+q.Tuple()]++
	}
	return t
}

// GroupsSince aggregates only the requests recorded after cursor. See TallySince for why a window exists.
func (r *Recorder) GroupsSince(cursor int64) []Group {
	return r.groups(cursor)
}

// Since returns the records after cursor and the new cursor. Cursor is a Seq, so a caller polling a
// process-level journal can start from any point — which is how a run presents its own slice without
// owning a journal.
func (r *Recorder) Since(cursor int64) ([]Request, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Request, 0, len(r.reqs))
	for _, q := range r.reqs {
		if q.Seq > cursor {
			out = append(out, q)
		}
	}
	// THE MAX SEQUENCE HANDED BACK, not the last row appended.
	//
	// record() assigns Seq with an atomic BEFORE taking the mutex — deliberately, because holding the lock
	// across a round trip would serialise every request in the session. So append order is not Seq order: a
	// goroutine holding Seq 64 can append before the one holding 63, and `r.reqs[len-1].Seq` was then 63.
	// The caller had already been handed row 64 in `out` and was told to resume from 63, so the app's
	// 220ms poll fetched it again and the live trace showed one request twice.
	next := cursor
	for _, q := range out {
		if q.Seq > next {
			next = q.Seq
		}
	}
	return out, next
}

// Tally returns a copy of the running summary.
func (r *Recorder) Tally() Tally {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tally
	t.ByTuple = make(map[string]int, len(r.tally.ByTuple))
	for k, v := range r.tally.ByTuple {
		t.ByTuple[k] = v
	}
	t.ByVerbTuple = make(map[string]int, len(r.tally.ByVerbTuple))
	for k, v := range r.tally.ByVerbTuple {
		t.ByVerbTuple[k] = v
	}
	// Copied like the others: Tally documents itself as returning a copy safe to mutate, and a map shared
	// with the live tally would break that promise silently.
	t.NoResponseByCluster = make(map[string]int, len(r.tally.NoResponseByCluster))
	for k, v := range r.tally.NoResponseByCluster {
		t.NoResponseByCluster[k] = v
	}
	return t
}

// Group is one row of the session-trace appendix: every request that shares a canonical resource and scope,
// with the set of verbs used against it.
//
// The appendix is grouped at THIS level and not per request, for a reason worth stating. (verb × apiGroup ×
// resource) is the RBAC unit — the exact unit in which the read-only claim is made, the unit deploy/rbac.yaml
// grants in, and the unit internal/collect/permissions.go already publishes as this repo's source of truth.
// The report already carries the per-run instance of that list unredacted, by deliberate decision, in
// Methodology.CollectedKinds. So an appendix at this level adds verbs and counts to a list the schema already
// contains: no new leak surface at all, which is what makes it safe under --redact without redaction needing
// to grow a new hand-written branch for it.
type Group struct {
	Verbs    []string // sorted, deduped
	Resource string   // the canonical tuple: "core/pods", "apps/deployments", "core/services/proxy"
	Scope    string
	Requests int
	// Outcomes counts each outcome under this group, so a refused list is visible as refused rather than
	// disappearing into a total.
	Outcomes map[string]int
	// Class is the strongest class seen in the group: write beats stream beats read. A group is displayed
	// with its strongest class so a single create cannot hide inside a hundred reads.
	Class Class
	// NonResourcePaths are the whitelisted discovery routes this group covers, sorted. Empty for resources.
	NonResourcePaths []string
}

// ExternalHosts returns every distinct non-cluster destination this session contacted, sorted.
//
// Derived from what was ACTUALLY contacted, not from what was configured, which is what makes the
// path-separation property checkable after the fact from the operator's own terminal rather than only in CI:
// a redirect or a mistyped base URL appears here. It states what WAS contacted and never asserts that
// nothing else was — that claim belongs to make transport-gate, which proves it structurally.
func (r *Recorder) ExternalHosts() []string { return r.externalHosts(0) }

// ExternalHostsSince is ExternalHosts over the window one run owns.
func (r *Recorder) ExternalHostsSince(cursor int64) []string { return r.externalHosts(cursor) }

func (r *Recorder) externalHosts(cursor int64) []string {
	r.mu.Lock()
	rows := append([]Request(nil), r.reqs...)
	r.mu.Unlock()

	seen := map[string]bool{}
	var out []string
	for _, q := range rows {
		if q.Seq <= cursor || q.Class != ClassExternal || q.Host == "" || seen[q.Host] {
			continue
		}
		seen[q.Host] = true
		out = append(out, q.Host)
	}
	sort.Strings(out)
	return out
}

// Groups aggregates the whole journal into appendix rows, sorted for a stable report.
func (r *Recorder) Groups() []Group { return r.groups(0) }

func (r *Recorder) groups(cursor int64) []Group {
	r.mu.Lock()
	all := append([]Request(nil), r.reqs...)
	r.mu.Unlock()
	rows := make([]Request, 0, len(all))
	for _, q := range all {
		if q.Seq > cursor {
			rows = append(rows, q)
		}
	}

	type key struct{ res, scope string }
	idx := map[key]*Group{}
	verbSeen := map[key]map[string]bool{}
	pathSeen := map[key]map[string]bool{}
	var order []key
	for _, q := range rows {
		k := key{q.Tuple(), q.Scope.String()}
		g := idx[k]
		if g == nil {
			g = &Group{Resource: k.res, Scope: k.scope, Outcomes: map[string]int{}}
			idx[k] = g
			verbSeen[k] = map[string]bool{}
			pathSeen[k] = map[string]bool{}
			order = append(order, k)
		}
		g.Requests++
		g.Outcomes[q.Outcome]++
		if q.Class > g.Class {
			g.Class = q.Class
		}
		// A Prometheus request carries no Kubernetes verb on purpose. The group still needs something in
		// that column, because a blank cell reads as missing data — which invites the reader either to
		// distrust the row or to assume a verb nobody measured. It says what it is instead.
		v := q.Verb
		if v == "" && q.Target == TargetPrometheus {
			v = "(not a Kubernetes request)"
		}
		if v != "" && !verbSeen[k][v] {
			verbSeen[k][v] = true
			g.Verbs = append(g.Verbs, v)
		}
		if q.NonResourcePath != "" && !pathSeen[k][q.NonResourcePath] {
			pathSeen[k][q.NonResourcePath] = true
			g.NonResourcePaths = append(g.NonResourcePaths, q.NonResourcePath)
		}
	}

	out := make([]Group, 0, len(order))
	for _, k := range order {
		g := idx[k]
		sort.Strings(g.Verbs)
		sort.Strings(g.NonResourcePaths)
		out = append(out, *g)
	}
	// Object writes first so one can never be buried, then streams, then by resource name for stability.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class > out[j].Class
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}
