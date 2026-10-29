package history

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// readings of one cluster, oldest first, a week apart, saved into a fresh store
func storeWith(t *testing.T, reports ...*types.AuditReport) *Store {
	t.Helper()
	s := &Store{Dir: t.TempDir()}
	base := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	for i, ar := range reports {
		ar.GeneratedAt = base.AddDate(0, 0, i*7)
		if _, err := s.Save(ar, ar.GeneratedAt); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func stampedFull(uid string, fs ...types.Finding) *types.AuditReport {
	return withRuleSet(full("c", uid, fs...), "0.19.0", stampTest)
}

func row(t *testing.T, tl Timeline, id string) Row {
	t.Helper()
	for _, r := range tl.Rows {
		if r.FindingID == id {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", id, tl.Rows)
	return Row{}
}

func kinds(r Row) []StateKind {
	out := make([]StateKind, len(r.States))
	for i, s := range r.States {
		out[i] = s.Kind
	}
	return out
}

// Spec §7 test 1. A denied interval is UNKNOWN, never a gap — and the same three readings with every kind
// read must produce present · absent · present, or a walk that answers "unknown" to everything passes.
func TestTimeline_ADeniedIntervalIsUnknownNotAbsent(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	denied := withRuleSet(withBasis(mkReport("c"), "uid-A", nil, []string{"deployments"}, "none"), "0.19.0", stampTest)
	s := storeWith(t, stampedFull("uid-A", f), denied, stampedFull("uid-A", f))
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(row(t, tl, "f-1"))
	if !reflect.DeepEqual(got, []StateKind{StatePresent, StateNotReadable, StatePresent}) {
		t.Fatalf("states %v", got)
	}
	if r := row(t, tl, "f-1").States[1].Reason; !strings.Contains(r, "deployments") {
		t.Errorf("the unknown interval does not name the kind: %q", r)
	}
	s2 := storeWith(t, stampedFull("uid-A", f), stampedFull("uid-A"), stampedFull("uid-A", f))
	tl2, _ := s2.Timeline("c", testDeps(), 10)
	if got := kinds(row(t, tl2, "f-1")); !reflect.DeepEqual(got, []StateKind{StatePresent, StateAbsent, StatePresent}) {
		t.Fatalf("with every kind read the states must be present · absent · present, got %v", got)
	}
}

// Spec §7 test 2. A rule version move is its own state; equal versions read present.
func TestTimeline_ARuleVersionMoveIsItsOwnState(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	f2 := f
	f2.RuleVersion = "1.1.0"
	third := withRuleSet(full("c", "uid-A", f2), "0.19.0", types.RuleStamp{ID: "k8s.test.rule", Version: "1.1.0"})
	s := storeWith(t, stampedFull("uid-A", f), stampedFull("uid-A", f), third)
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil {
		t.Fatal(err)
	}
	r := row(t, tl, "f-1")
	if got := kinds(r); !reflect.DeepEqual(got, []StateKind{StatePresent, StatePresent, StateRuleChanged}) {
		t.Fatalf("states %v", got)
	}
	if r.States[2].RuleVersion != "1.1.0" || r.States[0].RuleVersion != "1.0.0" {
		t.Errorf("rule versions not carried: %+v", r.States)
	}
	same := storeWith(t, stampedFull("uid-A", f), stampedFull("uid-A", f), stampedFull("uid-A", f))
	tl2, _ := same.Timeline("c", testDeps(), 10)
	if got := kinds(row(t, tl2, "f-1")); !reflect.DeepEqual(got, []StateKind{StatePresent, StatePresent, StatePresent}) {
		t.Fatalf("equal versions must read present, got %v", got)
	}
}

// Spec §7 test 4, structural: nothing in these types can carry a rate.
func TestTimeline_NoRateIsComputed(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Timeline{}), reflect.TypeOf(Row{}), reflect.TypeOf(State{}), reflect.TypeOf(Reading{}), reflect.TypeOf(Segment{})} {
		if typ.NumField() == 0 {
			t.Fatalf("%s has no fields — this test would prove nothing", typ.Name())
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			switch f.Type.Kind() {
			case reflect.Float32, reflect.Float64:
				t.Errorf("%s.%s is a float — a rate or a percentage has no place here", typ.Name(), f.Name)
			}
			if f.Type == reflect.TypeOf(time.Duration(0)) {
				t.Errorf("%s.%s is a Duration — an interval is the operator's, never ours to compute with", typ.Name(), f.Name)
			}
		}
	}
}

// Spec §7 test 5. Gaps of 1 day and 40 days survive as recorded.
func TestTimeline_TheAxisIsTheRecordedTimestamps(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	s := &Store{Dir: t.TempDir()}
	t0 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{t0, t0.AddDate(0, 0, 1), t0.AddDate(0, 0, 41)} {
		ar := stampedFull("uid-A", f)
		ar.GeneratedAt = at
		if _, err := s.Save(ar, at); err != nil {
			t.Fatal(err)
		}
	}
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil || len(tl.Readings) != 3 {
		t.Fatalf("readings %d err %v", len(tl.Readings), err)
	}
	g1 := tl.Readings[1].At.Sub(tl.Readings[0].At)
	g2 := tl.Readings[2].At.Sub(tl.Readings[1].At)
	if g1 != 24*time.Hour || g2 != 40*24*time.Hour {
		t.Errorf("gaps %v and %v were not preserved as recorded", g1, g2)
	}
	if tl.Kept != 3 || tl.Limit != 10 {
		t.Errorf("the count looked at must be stated: kept=%d limit=%d", tl.Kept, tl.Limit)
	}
}

// Spec §7 test 8 — writable now that RunBasis.RuleSet exists: a rule added between readings is "not readable"
// in the readings whose build lacked it, never "absent".
func TestTimeline_ARuleAddedBetweenReadingsIsNotAbsentEarlier(t *testing.T) {
	newRule := mkFinding("f-new", types.SeverityMedium, 0)
	newRule.RuleID = "k8s.test.newrule"
	old1 := withRuleSet(full("c", "uid-A"), "0.18.0", stampTest)
	old2 := withRuleSet(full("c", "uid-A"), "0.18.0", stampTest)
	cur := withRuleSet(full("c", "uid-A", newRule), "0.19.0", stampTest, stampNew)
	s := storeWith(t, old1, old2, cur)
	tl, err := s.Timeline("c", depsWithNewRule(), 10)
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(row(t, tl, "f-new"))
	if !reflect.DeepEqual(got, []StateKind{StateNotReadable, StateNotReadable, StatePresent}) {
		t.Fatalf("states %v — the earlier builds were not looking", got)
	}
	if !strings.Contains(row(t, tl, "f-new").States[0].Reason, "was not part of") {
		t.Errorf("reason %q does not name the build", row(t, tl, "f-new").States[0].Reason)
	}
}

// Spec §7 test 3. Four readings, the third with IncludeSystem flipped: three segments ([0,1] · [2] · [3]), each
// break carrying Gate 0's sentence verbatim, and every cell still decided. Four consistent readings: one segment.
func TestTimeline_AGate0BreakSplitsTheTimeline(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	a, b, d := stampedFull("uid-A", f), stampedFull("uid-A", f), stampedFull("uid-A", f)
	c := stampedFull("uid-A", f)
	c.Methodology.RunBasis.IncludeSystem = true
	s := storeWith(t, a, b, c, d)
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Segments) != 3 {
		t.Fatalf("want 3 segments: the flipped reading is comparable with neither neighbour; got %+v", tl.Segments)
	}
	want := comparable(b, c, testDeps()).Reason
	if tl.Segments[0].To != 1 || tl.Segments[0].BreakReason != want {
		t.Errorf("first segment %+v does not end at reading 1 with Gate 0's own sentence %q", tl.Segments[0], want)
	}
	if tl.Segments[2].BreakReason != "" {
		t.Errorf("the last segment carries a break reason: %q", tl.Segments[2].BreakReason)
	}
	for _, st := range row(t, tl, "f-1").States {
		if st.Kind == "" {
			t.Error("a cell inside a one-reading segment was left undecided")
		}
	}
	one := storeWith(t, stampedFull("uid-A", f), stampedFull("uid-A", f), stampedFull("uid-A", f), stampedFull("uid-A", f))
	tl2, _ := one.Timeline("c", testDeps(), 10)
	if len(tl2.Segments) != 1 || tl2.Segments[0].From != 0 || tl2.Segments[0].To != 3 {
		t.Fatalf("four consistent readings must be one segment, got %+v", tl2.Segments)
	}
}

// Spec §7 test 6. Every string the timeline can emit passes the lexicon in the comparison scope, the surface
// maps every scope, and the gate is proven to bite: a probe with the literal word "resolved" must fail.
func TestTimeline_ClearsTheComparisonScope(t *testing.T) {
	f := mkFinding("f-1", types.SeverityHigh, 10)
	denied := withRuleSet(withBasis(mkReport("c"), "uid-A", nil, []string{"deployments"}, "none"), "0.19.0", stampTest)
	flipped := stampedFull("uid-A", f)
	flipped.Methodology.RunBasis.IncludeSystem = true
	s := storeWith(t, stampedFull("uid-A", f), denied, stampedFull("uid-A"), flipped)
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil {
		t.Fatal(err)
	}
	text := tl.Text()
	if !strings.Contains(text, "not readable") || !strings.Contains(text, "absent") || !strings.Contains(text, "readings") {
		t.Fatalf("the text does not carry the states and the count:\n%s", text)
	}
	if un := lexicon.UnmappedScopes(TimelineSections(text)); len(un) != 0 {
		t.Fatalf("scopes this surface does not map: %v", un)
	}
	if v := lexicon.Scan(strings.ToLower(text), TimelineSections(text)); len(v) != 0 {
		t.Errorf("banned copy in the timeline: %+v", v)
	}
	probe := text + "\nresolved\n"
	if v := lexicon.Scan(strings.ToLower(probe), TimelineSections(probe)); len(v) == 0 {
		t.Fatal("the gate did not bite on the literal word 'resolved' — this test would prove nothing")
	}
}

// "0 FINDINGS" ON A TIMELINE ROW FOR A READING WHERE NOTHING COULD BE READ IS THE SAME WRONG SENTENCE THE
// TERMINAL TABLE USED TO PRINT, one surface along.
//
// Found by running the product against the readings on this machine:
//
//	shoalcheck history timeline --cluster dead
//	  [1] 2026-08-18T10:46:52Z  0 findings
//	  [2] 2026-08-18T10:47:13Z  0 findings
//
// Both readings have 0 collected kinds and 20 denied ones: no resource list succeeded. A reader scanning
// that column sees a cluster that has been quiet for two runs. The count is correct and the column is a
// false statement about the cluster, which is the distinction this product exists to keep.
func TestTimeline_AReadingThatReadNothingSaysSoOnItsRow(t *testing.T) {
	blind := withBasis(mkReport("c"), "uid-A", nil, []string{"pods", "nodes", "secrets"}, "none")
	partial := withBasis(mkReport("c", mkFinding("f-a", types.SeverityHigh, 100)), "uid-A",
		[]string{"pods"}, []string{"nodes"}, "none")
	whole := full("c", "uid-A", mkFinding("f-a", types.SeverityHigh, 100))

	s := storeWith(t, blind, partial, whole)
	tl, err := s.Timeline("c", testDeps(), 10)
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(tl.Readings) != 3 {
		t.Fatalf("%d reading(s) in the timeline, want 3", len(tl.Readings))
	}

	text := tl.Text()
	lines := strings.Split(text, "\n")
	var rows []string
	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "[") && strings.Contains(ln, "finding") {
			rows = append(rows, ln)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("found %d reading row(s) in the rendered timeline, want 3:\n%s", len(rows), text)
	}

	// [1] read nothing at all.
	if !strings.Contains(strings.ToLower(rows[0]), "nothing could be read") {
		t.Errorf("the row for a reading with 0 collected kinds and 3 denied ones does not say so:\n  %s", rows[0])
	}
	// [2] read some of it.
	if !strings.Contains(strings.ToLower(rows[1]), "not read") {
		t.Errorf("the row for a partially read reading does not name the shortfall:\n  %s", rows[1])
	}
	// [3] read everything — and must NOT be decorated, or the marker means nothing.
	if strings.Contains(strings.ToLower(rows[2]), "not read") ||
		strings.Contains(strings.ToLower(rows[2]), "nothing could be read") {
		t.Errorf("a reading that read every kind carries a shortfall marker, so the marker says nothing:\n  %s", rows[2])
	}
	t.Logf("3 reading row(s):\n%s\n%s\n%s", rows[0], rows[1], rows[2])
}
