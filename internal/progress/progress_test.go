package progress

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A nil Func must silently discard every event — this is the CLI path, where
// no sink is set. A panic here would crash every non-desktop audit.
func TestNilFuncDiscardsEverything(t *testing.T) {
	var f Func // nil
	// None of these may panic.
	f.Collected("pods", 12)
	f.Unread("secrets", "not permitted")
	f.NodeSeen("m6i.large", "2 vCPU · 8 GiB", 3)
	f.PromConnect("prometheus", "service-proxy")
	f.UsageResolved(Usage{Source: "prometheus"})
	f.PricingRan(Pricing{})
	f.NodePriced(NodePriced{})
	f.FindingFound(FindingEvt{Finding: &types.Finding{}})
	f.MapReady(MapBuilt{Tier: "declared"})
	f.Compared(Comparison{})
	f.Report("report.html", "/Users/someone/Library/Application Support/shoalcheck/reports/report.html")
	f.Done(RunDone{})
	f.Error("collect", "boom")
}

// Emit must stamp the wall-clock and route the right payload for each kind, so
// the journal carries true engine timing and the UI can switch on Kind.
func TestConstructorsStampTimeAndSetPayload(t *testing.T) {
	var got []Event
	f := Func(func(e Event) { got = append(got, e) })

	f.Collected("pods", 214)
	f.Unread("networkpolicies", "not reachable")
	f.NodePriced(NodePriced{InstanceType: "m6i.large", Count: 2, Priced: false})
	f.MapReady(MapBuilt{Tier: "observed", Edges: 7})

	if len(got) != 4 {
		t.Fatalf("emitted %d events, want 4", len(got))
	}
	for i, e := range got {
		if e.T.IsZero() {
			t.Errorf("event %d (%s): timestamp not stamped", i, e.Kind)
		}
	}
	if got[0].Kind != KindCollected || got[0].Collected == nil || got[0].Collected.Count != 214 {
		t.Errorf("collected payload wrong: %+v", got[0])
	}
	// THE CAUSE TRAVELS WITH THE KIND. This event carried only a name, and the two surfaces that render it
	// each supplied a reason of their own — "denied by RBAC" in the terminal frame, "refused" in the app —
	// for kinds that had been unreachable, timed out, or simply not served by the cluster.
	if got[1].Kind != KindUnread || got[1].Unread == nil || got[1].Unread.Kind != "networkpolicies" {
		t.Errorf("unread payload wrong: %+v", got[1])
	}
	if got[1].Unread != nil && got[1].Unread.Cause != "not reachable" {
		t.Errorf("unread payload dropped the cause: %+v", got[1].Unread)
	}
	// Honesty contract: an unpriced pool carries Priced=false — the UI keys off
	// this to render "unpriced" instead of "$0".
	if got[2].Kind != KindNodePriced || got[2].NodePriced == nil || got[2].NodePriced.Priced {
		t.Errorf("node_priced should carry Priced=false: %+v", got[2])
	}
	if got[3].Kind != KindMapBuilt || got[3].MapBuilt == nil || got[3].MapBuilt.Tier != "observed" {
		t.Errorf("map_built payload wrong: %+v", got[3])
	}
}

// THE DURABLE PATH MUST SURVIVE THE JOURNAL.
//
// A UI reads this event as JSON off /api/run/events, so a field the encoder drops is a field the operator
// never sees — and what it names here is the only copy of a finished audit that outlives the process. The
// served basename and the durable path are BOTH carried, because they are different things: one is a URL
// that dies with the server, the other is a document.
func TestReportReady_CarriesBothPathsThroughJSON(t *testing.T) {
	const durable = "/Users/someone/Library/Application Support/shoalcheck/reports/report-20260828-101500.html"
	var got Event
	Func(func(e Event) { got = e }).Report("report-20260828-101500.html", durable)

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.ReportReady == nil {
		t.Fatal("the report_ready payload did not survive the round trip")
	}
	if back.ReportReady.DurablePath != durable {
		t.Errorf("durablePath came back %q, want %q", back.ReportReady.DurablePath, durable)
	}
	// NON-VACUITY: the two fields must be distinguishable in the encoded form, or a UI reading the wrong
	// one would still pass. The served name is a basename; the durable one is absolute.
	if back.ReportReady.Path == back.ReportReady.DurablePath {
		t.Error("the served name and the durable path encoded to the same value — the UI cannot tell them apart")
	}
	if !strings.Contains(string(b), `"durablePath"`) {
		t.Errorf("the encoded event has no durablePath key: %s", string(b))
	}
}

// TestVerdictReady_IsAdditiveAndNilSafe guards the two properties that let the judgment layer
// extend a contract the spec calls frozen: the new kind carries its own payload, and a nil sink
// still swallows it. A consumer that has never heard of "verdict" loses nothing, because every
// leader it names was already streamed as its own finding event.
func TestVerdictReady_IsAdditiveAndNilSafe(t *testing.T) {
	var got []Event
	f := Func(func(e Event) { got = append(got, e) })
	f.VerdictReady(Verdict{
		Leaders: []VerdictItem{{
			FindingID: "f-1", RuleID: "r.1", Title: "t", Severity: "high",
			Safety: "manual", Rationale: "why", CollapsedFrom: 3,
		}},
		StartHere:    &VerdictItem{FindingID: "f-2", Safety: "safe-now"},
		RestCount:    7,
		RestDollars:  1.5,
		TotalDollars: 10,
	})
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1", len(got))
	}
	e := got[0]
	if e.Kind != KindVerdict {
		t.Errorf("Kind = %q, want %q", e.Kind, KindVerdict)
	}
	if e.Verdict == nil {
		t.Fatal("Verdict payload is nil")
	}
	if e.T.IsZero() {
		t.Error("event carries no timestamp — the journal stamps real times")
	}
	if e.Verdict.StartHere == nil || e.Verdict.StartHere.Safety != "safe-now" {
		t.Error("StartHere must survive the round trip and may only ever be safe-now")
	}

	// A nil sink must not panic: the CLI runs with no Progress at all.
	var nilSink Func
	nilSink.VerdictReady(Verdict{})
}

// THE RUN SAYS WHICH READING IT IS, FIRST. A surface that decides from the key on the machine draws a full reading
// around a stream the engine put on the free line; the line event carries the decision and the licence's reason.
func TestOnLine_CarriesTheDecisionAndItsReason(t *testing.T) {
	var got []Event
	Func(func(e Event) { got = append(got, e) }).OnLine(Line{Why: "this pass licence reads only the 1 cluster(s) it was bought for"})
	if len(got) != 1 || got[0].Kind != KindLine || got[0].Line == nil || got[0].T.IsZero() {
		t.Fatalf("OnLine emitted %+v", got)
	}
	if got[0].Line.Full || got[0].Line.Why == "" {
		t.Errorf("the line lost its decision or its reason: %+v", *got[0].Line)
	}
	Func(nil).OnLine(Line{Full: true}) // nil-safe, like every constructor
}
