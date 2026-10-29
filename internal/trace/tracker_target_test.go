package trace

import (
	"net/url"
	"testing"
)

// THE "ZERO OBJECT WRITES" CLAIM IS ABOUT KUBERNETES OBJECTS, AND IT MUST BE COMPUTED THAT WAY.
//
// Before TargetTracker existed, a POST to api.linear.app classified as TargetAPIServer fell through to
// unclassified("POST") → Verb "create", Class ClassWrite, and every "0 object writes" line in the product
// would have been counting a POST to a SaaS. internal/tracker kept its own ledger to avoid exactly that,
// which was the right call and the wrong end state.
//
// This test is the invariant, written so it can fail: record one tracker request, assert the object-write
// total is UNCHANGED, and assert the tracker request is present on a line of its own with its own count.
func TestTally_ATrackerRequestIsNotAnObjectWrite(t *testing.T) {
	rec := New(nil)

	// One real Kubernetes read, so the tally is not trivially empty.
	rec.record(ok(Classify(TargetAPIServer, "GET", mustURL(t, "/api/v1/namespaces/default/pods"))))
	// One POST to an operator-configured tracker.
	rec.record(ok(Classify(TargetTracker, "POST", mustURL(t, "/graphql"))))

	got := rec.Tally()

	if got.Write != 0 {
		t.Errorf("Tally.Write = %d, want 0 — a POST to an issue tracker is not a Kubernetes object write, "+
			"and every read-only claim in this product is rendered from this number", got.Write)
	}
	if got.External != 1 {
		t.Errorf("Tally.External = %d, want 1 — the tracker request must be counted on its own line, "+
			"not dropped: a request we issued and did not report is the one thing the trace exists to prevent",
			got.External)
	}
	if got.Total != 2 {
		t.Errorf("Tally.Total = %d, want 2", got.Total)
	}
	// NON-VACUITY: an object write must still be counted, or "Write = 0" proves nothing about the
	// restriction and everything about an empty counter.
	rec.record(ok(Classify(TargetAPIServer, "POST", mustURL(t, "/api/v1/namespaces/default/pods"))))
	if w := rec.Tally().Write; w != 1 {
		t.Errorf("after a real object write Tally.Write = %d, want 1 — the counter is not measuring anything", w)
	}
}

// THE TARGET RESTRICTION ITSELF, AND WHY IT NEEDS ITS OWN TEST.
//
// The test above passes with the restriction REMOVED. Measured, not assumed: deleting `case q.Target ==
// TargetAPIServer` and letting ClassWrite fall through leaves it green, because Classify never produces a
// ClassWrite on a tracker target — the class branch catches it first. So that test proves the CLASS is
// right and says nothing about the restriction the brief asked for.
//
// This one constructs the request Classify cannot: ClassWrite arriving on a target that is not the API
// server. That is what a future target whose branch someone forgot looks like, and it is the case where
// "0 object writes" would quietly become "0 writes to anything, we think". The restriction is what makes
// the claim structurally true instead of true-by-convention, and OffTargetWrite is where the request goes
// so that nothing is dropped and Total still equals the sum of its parts.
func TestTally_AWriteOnANonClusterTargetIsNotAnObjectWrite(t *testing.T) {
	rec := New(nil)
	rec.record(ok(Classify(TargetAPIServer, "GET", mustURL(t, "/api/v1/pods"))))
	// Hand-built on purpose: Classify gives TargetTracker its own class, so this shape can only arrive
	// from a classifier that grew a target and not a branch.
	rec.record(ok(Request{Target: TargetTracker, Class: ClassWrite, Resource: "tracker", Scope: ScopeNonResource}))

	got := rec.Tally()
	if got.Write != 0 {
		t.Errorf("Tally.Write = %d, want 0 — a ClassWrite that did not go to the API server is not a "+
			"Kubernetes object write, and the claim must be computed with the target restriction rather "+
			"than trusting every future target to pick the right class", got.Write)
	}
	if got.OffTargetWrite != 1 {
		t.Errorf("Tally.OffTargetWrite = %d, want 1 — the request must land somewhere, or restricting Write "+
			"by target silently drops it and Total stops equalling the sum of its parts", got.OffTargetWrite)
	}
	if sum := got.Read + got.Stream + got.Write + got.External + got.OffTargetWrite; sum != got.Total {
		t.Errorf("the parts sum to %d and Total is %d", sum, got.Total)
	}
}

// TOTAL ALWAYS EQUALS THE SUM OF ITS PARTS. This is the same rule the report's headline follows, and here
// it is what makes the target restriction safe: restricting Write to TargetAPIServer could have silently
// dropped a ClassWrite on another target, and a dropped request is worse than a miscounted one.
//
// OffTargetWrite is the named home for the case that should be unreachable. It is asserted zero, so the day
// the classifier grows a hole the test says which hole rather than the totals quietly disagreeing.
func TestTally_EveryRequestLandsInExactlyOneClassLine(t *testing.T) {
	rec := New(nil)
	rows := []Request{
		Classify(TargetAPIServer, "GET", mustURL(t, "/api/v1/pods")),
		Classify(TargetAPIServer, "GET", mustURL(t, "/apis/apps/v1/namespaces/x/deployments/y")),
		Classify(TargetAPIServer, "POST", mustURL(t, "/api/v1/namespaces/x/pods/y/portforward")),
		Classify(TargetAPIServer, "DELETE", mustURL(t, "/api/v1/namespaces/x/pods/y")),
		Classify(TargetPrometheus, "GET", mustURL(t, "/api/v1/query")),
		Classify(TargetTracker, "POST", mustURL(t, "/graphql")),
		Classify(TargetTracker, "GET", mustURL(t, "/rest/api/3/myself")),
	}
	for _, q := range rows {
		rec.record(ok(q))
	}

	for _, tc := range []struct {
		name string
		t    Tally
	}{
		{"Tally", rec.Tally()},
		{"TallySince(0)", rec.TallySince(0)},
	} {
		sum := tc.t.Read + tc.t.Stream + tc.t.Write + tc.t.External + tc.t.OffTargetWrite
		if sum != tc.t.Total {
			t.Errorf("%s: Read %d + Stream %d + Write %d + External %d + OffTargetWrite %d = %d, "+
				"but Total is %d — a request was counted twice or not at all",
				tc.name, tc.t.Read, tc.t.Stream, tc.t.Write, tc.t.External, tc.t.OffTargetWrite, sum, tc.t.Total)
		}
		if tc.t.OffTargetWrite != 0 {
			t.Errorf("%s: OffTargetWrite = %d — Classify produced a ClassWrite on a target that is not the "+
				"API server. The object-write claim is NOT the thing to widen; give that target its own class",
				tc.name, tc.t.OffTargetWrite)
		}
		if tc.t.Write != 1 {
			t.Errorf("%s: Write = %d, want 1 (the DELETE)", tc.name, tc.t.Write)
		}
		if tc.t.External != 2 {
			t.Errorf("%s: External = %d, want 2 (both tracker requests)", tc.name, tc.t.External)
		}
		if tc.t.Stream != 1 {
			t.Errorf("%s: Stream = %d, want 1 (the portforward)", tc.name, tc.t.Stream)
		}
	}
}

// A TRACKER REQUEST IS GIVEN NO KUBERNETES VERB, for the same reason a Prometheus request is not: the
// cluster's audit log will never contain it, and a Kubernetes verb on it is a cluster-shaped claim about
// something that never touched the cluster.
//
// And the class does not say whether the request CHANGED anything at the destination, because the wire does
// not say. Every Linear call — Probe, Find and Create — is a POST to /graphql (internal/tracker/linear.go:113,
// `postJSON`); what separates a lookup from a mutation is in the GraphQL document body, which internal/trace
// deliberately never keeps. The count of tickets created comes from the API response, not from counting POSTs.
func TestClassify_ATrackerRequestCarriesNoKubernetesClaim(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		r := Classify(TargetTracker, method, mustURL(t, "/graphql"))
		if r.Verb != "" {
			t.Errorf("%s: Verb = %q, want empty — a ticket request has no Kubernetes verb", method, r.Verb)
		}
		if r.Class != ClassExternal {
			t.Errorf("%s: Class = %v, want external", method, r.Class)
		}
		if r.Scope != ScopeNonResource {
			t.Errorf("%s: Scope = %v, want non-resource", method, r.Scope)
		}
		if r.Group != "" {
			t.Errorf("%s: Group = %q, want empty", method, r.Group)
		}
		// The path is not kept. A Jira issue path names a project key and a Linear route could carry a
		// query; the safest redaction is data that was never kept.
		if r.NonResourcePath != "" {
			t.Errorf("%s: NonResourcePath = %q — the tracker's path must not be recorded", method, r.NonResourcePath)
		}
	}
	// The class must read as itself on the line the CLI prints, not as "write".
	if got := ClassExternal.String(); got == "write" || got == "read" || got == "" {
		t.Errorf("ClassExternal.String() = %q — it must not read as either cluster total", got)
	}
}

// ok stamps the fields the recording round tripper fills in after a 200.
func ok(r Request) Request {
	r.Status = 200
	r.Outcome = "ok"
	return r
}

func mustURL(t *testing.T, p string) *url.URL {
	t.Helper()
	u, err := url.Parse(p)
	if err != nil {
		t.Fatalf("parse %q: %v", p, err)
	}
	return u
}

// THE CURSOR MUST BE THE HIGHEST SEQUENCE THE CALLER WAS HANDED, NOT THE LAST ONE APPENDED.
//
// record() assigns Seq with an atomic BEFORE it takes the mutex, deliberately — the sequence is a session
// ordering and holding the lock across the round trip would serialise every request. The consequence is
// that append order is NOT Seq order: a goroutine holding Seq 64 can append before the one holding 63.
//
// `next` was computed as `r.reqs[len-1].Seq`, the last row appended. So a caller could be handed row 64 and
// told to resume from 63 — and the app polls /api/run/trace?after=<next> every 220ms, so that row arrives a
// second time and the live trace shows a request that happened once, twice.
//
// This test builds the state the race produces instead of racing for it, so it cannot be flaky and cannot
// pass by luck. The concurrency test below still exercises the real path.
func TestSince_CursorIsTheMaxSequenceNotTheLastAppended(t *testing.T) {
	rec := New(nil)
	// Exactly what an out-of-order append leaves behind: Seq 2 landed before Seq 1.
	rec.reqs = []Request{
		{Seq: 2, Target: TargetAPIServer, Class: ClassRead, Resource: "pods", Outcome: "ok"},
		{Seq: 1, Target: TargetAPIServer, Class: ClassRead, Resource: "nodes", Outcome: "ok"},
	}

	rows, next := rec.Since(0)
	if len(rows) != 2 {
		t.Fatalf("Since(0) returned %d rows, want 2", len(rows))
	}
	if next != 2 {
		t.Errorf("next = %d, want 2 — the caller has been handed sequence 2 and told to resume from %d, so "+
			"the next poll hands it sequence 2 again and the trace shows one request twice", next, next)
	}
	// And resuming from the cursor must hand back nothing, which is the property the cursor exists for.
	again, next2 := rec.Since(next)
	if len(again) != 0 {
		t.Errorf("resuming from %d returned %d row(s), want 0: %+v", next, len(again), again)
	}
	if next2 != next {
		t.Errorf("an empty page moved the cursor from %d to %d", next, next2)
	}
}
