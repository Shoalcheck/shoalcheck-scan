package pipeline

import (
	"context"
	"net/http"
	"net/url"
	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// A rule declares its dependencies as collector step names. Nothing in the type system connects the two,
// so a rename on either side — or a plain typo — would leave a rule permanently declaring a dependency on
// a step that does not exist, and every comparison of its findings would be withheld forever with no
// error anywhere. This test is the only thing standing between that and a silent hole in the product.
//
// It lives in the pipeline package because that is the one place that imports both sides, and it derives
// the step names by RUNNING a collection rather than restating them, so it cannot drift from the
// collector the way a hand-written list would.
func TestRuleDependencies_NameRealCollectorSteps(t *testing.T) {
	// A DYNAMIC CLIENT IS SUPPLIED THOUGH THIS TEST READS NO CUSTOM RESOURCE, and the reason is an
	// interaction between two correctness measures worth stating. The CRD step is guarded by `c.dyn != nil`
	// because attempting a read with no client would record a DENIAL — "we asked and were refused" — for a
	// request that was never sent. Correct, and it makes the step INVISIBLE to a gate that validates step
	// names by observing what ran: with a nil dynamic client the step neither succeeds nor is denied, so
	// `customresourcedefinitions` would look like a name no collector uses and this test would report a hole
	// that is not there. Supplying the client is what keeps the observation honest.
	crdGVR := schema.GroupVersionResource{
		Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{crdGVR: "CustomResourceDefinitionList"})
	c := collect.NewWithClients(fake.NewSimpleClientset(), dyn, nil)
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect against the fake client: %v", err)
	}

	// Every step the collector ATTEMPTED, whether it succeeded or was refused: both outcomes prove the
	// step name is real, and a step's success against a fake client is not the point here.
	attempted := map[string]bool{}
	for _, k := range inv.Meta.Collected {
		attempted[k] = true
	}
	for _, d := range inv.Meta.Denied {
		attempted[strings.SplitN(d, ":", 2)[0]] = true
	}
	if len(attempted) < 15 {
		t.Fatalf("only %d collector steps ran (%v) — the fixture is not exercising the collector, "+
			"so this test would pass without checking anything", len(attempted), attempted)
	}

	for id, dep := range FindingDependencies() {
		for _, kind := range dep.Kinds {
			// A custom-resource step is validated by construction rather than by observation: it is
			// derived from the analyzer's RequiredGVRs with the same expression the collector uses, and
			// the fake client serves no CRDs, so no such step can have been attempted here.
			if strings.HasPrefix(kind, analyzers.CRStepPrefix) {
				if !strings.Contains(strings.TrimPrefix(kind, analyzers.CRStepPrefix), ".") {
					t.Errorf("%s depends on %q — a custom-resource step is cr:<resource>.<group>, and a "+
						"bare resource name would never match a step the collector recorded", id, kind)
				}
				continue
			}
			if !attempted[kind] {
				t.Errorf("rule %s depends on %q, which is not a step the collector runs — "+
					"every comparison of this rule's findings would be withheld forever", id, kind)
			}
		}
	}
}

// The reverse direction is a coverage signal rather than a rule: a collected kind no rule depends on is
// either dead collection or an undeclared dependency. Reported, never failed — some kinds are collected
// for the architecture and cost model rather than for a rule.
func TestRuleDependencies_ReportKindsNoRuleClaims(t *testing.T) {
	c := collect.NewWithClient(fake.NewSimpleClientset())
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect against the fake client: %v", err)
	}
	claimed := map[string]bool{}
	for _, dep := range FindingDependencies() {
		for _, k := range dep.Kinds {
			claimed[k] = true
		}
	}
	var orphans []string
	for _, k := range inv.Meta.Collected {
		if !claimed[k] && !strings.HasPrefix(k, "cr:") {
			orphans = append(orphans, k)
		}
	}
	if len(orphans) > 0 {
		t.Logf("collected but claimed by no rule (expected for architecture/cost inputs): %v", orphans)
	}
}

// Every producer of a finding must have a declaration, and no two may share an ID: an ID collision makes
// one producer invisible to the comparison, and a missing declaration makes its findings uncomparable
// forever. Both are silent failures, which is why they are asserted rather than left to review.
//
// A PRODUCER IS AN ID A FINDING CAN CARRY, AND THIS GATE SAID IT WAS AN ANALYZER. It asserted one entry per
// analyzer, keyed by a.ID(), while internal/history looks the map up with the id on a FINDING. So it
// enforced the defect: fifteen keys nothing could mint, sixteen ids that could all absent, every analyzer
// finding refused in every comparison and published with "basis unknown". Corrected 2026-09-15 (M-136), and
// the shape is worth keeping in mind — a gate can hold a table to the wrong vocabulary just as firmly as to
// the right one.
func TestFindingDependencies_OneEntryPerProducer(t *testing.T) {
	deps := FindingDependencies()
	analyzerIDs := 0
	for _, a := range analyzers.All() {
		analyzerIDs += len(a.FindingIDs())
	}
	want := len(rules.All()) + analyzerIDs
	if len(deps) != want {
		t.Errorf("FindingDependencies holds %d entries for %d rules + %d analyzer finding id(s) — an ID "+
			"collision hides a producer", len(deps), len(rules.All()), analyzerIDs)
	}
	for _, r := range rules.All() {
		if _, ok := deps[r.ID()]; !ok {
			t.Errorf("rule %s has no dependency entry", r.ID())
		}
	}
	for _, a := range analyzers.All() {
		for _, id := range a.FindingIDs() {
			if _, ok := deps[id]; !ok {
				t.Errorf("analyzer %s can mint %s and the dependency registry does not describe it, so "+
					"every comparison of a finding with that id is refused", a.ID(), id)
			}
		}
		d, ok := deps[firstID(a.FindingIDs())]
		if !ok {
			continue
		}
		if len(d.Kinds) == 0 {
			t.Errorf("analyzer %s declares nothing — every analyzer reads either a CRD or a core kind, "+
				"and a declaration of nothing cannot be checked against a run", a.ID())
		}
	}
}

// A report says its requests were "issued while producing this report". The recorder is process-level, so
// without a window the second audit in an app session stamps the first one's requests into its own appendix —
// a report claiming traffic it did not cause, which is the most expensive kind of wrong number because it is
// the one a reviewer can check against their own logs.
//
// The window boundary is the end of the PREVIOUS run, not the start of this one: the appendix states how many
// requests came "before it while probing the cluster", and a window starting at the run would report zero
// there whenever a pre-flight probe had in fact run.
func TestAttachSessionTrace_ClaimsOnlyItsOwnWindow(t *testing.T) {
	rec := trace.New(nil)
	rt := rec.Wrap(trace.TargetAPIServer)(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	do := func(n int, path string) {
		for i := 0; i < n; i++ {
			u, _ := url.Parse("https://k" + path)
			resp, _ := rt.RoundTrip(&http.Request{Method: "GET", URL: u, Header: http.Header{}})
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}
	}

	// A first session: three probe requests, then a run of five.
	do(3, "/api/v1/services")
	firstWindow := int64(0)
	rec.SetPhase(trace.PhaseRun)
	do(5, "/api/v1/pods")

	ar1 := &types.AuditReport{}
	attachSessionTrace(ar1, rec, firstWindow, "")
	if ar1.Methodology.SessionTrace.Total != 8 {
		t.Fatalf("the first report claims %d requests, want 8 (3 pre-flight + 5 run)",
			ar1.Methodology.SessionTrace.Total)
	}
	if ar1.Methodology.SessionTrace.Preflight != 3 {
		t.Errorf("the first report reports %d pre-flight requests, want 3",
			ar1.Methodology.SessionTrace.Preflight)
	}

	// The next run's window starts where that one ended.
	secondWindow := rec.Seq()
	rec.SetPhase(trace.PhasePreflight)
	do(2, "/api/v1/services") // the operator changed the selection; probing re-ran
	rec.SetPhase(trace.PhaseRun)
	do(4, "/api/v1/pods")

	ar2 := &types.AuditReport{}
	attachSessionTrace(ar2, rec, secondWindow, "")
	st := ar2.Methodology.SessionTrace
	if st.Total != 6 {
		t.Errorf("the second report claims %d requests, want 6 — it is counting the first audit's traffic", st.Total)
	}
	if st.Preflight != 2 || st.Run != 4 {
		t.Errorf("second report: preflight=%d run=%d, want 2/4", st.Preflight, st.Run)
	}
	// Nothing is double-claimed and nothing is dropped: the two windows partition the session exactly.
	if ar1.Methodology.SessionTrace.Total+st.Total != int(rec.Seq()) {
		t.Errorf("the two windows cover %d of %d recorded requests",
			ar1.Methodology.SessionTrace.Total+st.Total, rec.Seq())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// firstID is the id an analyzer's dependency list is sampled through: every id it mints rests on the same
// reads, so one of them answers for the analyzer.
func firstID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}
