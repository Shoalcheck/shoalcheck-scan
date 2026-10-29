package pipeline

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/headline"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// headline_order_test.go — the selection runs last.
//
// A live run against the kind testbed printed "this reading recorded no session trace" while the recorder held
// 39 requests: the headline was selected three lines after the calendar and before attachSessionTrace. One of
// its five lines is the reading's own cost, so the selection has to come after everything it quotes. A unit
// test cannot see pipeline ordering, so this asserts the property the ordering exists for.
func TestHeadline_QuotesTheTraceWhenThereIsOne(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1", GeneratedAt: time.Now(),
		Methodology: types.Methodology{SessionTrace: &types.SessionTrace{Total: 39, ObjectWrites: 0}},
	}
	ar.Summary = types.DeriveSummary(nil)
	if got := headline.Select(ar).Trace; !strings.Contains(got, "39 reads") {
		t.Fatalf("a reading with a trace produced %q", got)
	}
	// And the pipeline's own order: the trace attachment must precede the selection in the source, because
	// nothing else can catch this.
	src := pipelineSource(t)
	traceAt := strings.Index(src, "attachSessionTrace(ar,")
	headlineAt := strings.Index(src, "h := headline.SelectWith(ar,")
	if traceAt < 0 || headlineAt < 0 {
		t.Fatal("the pipeline no longer attaches a trace or selects a headline where this test expects")
	}
	if headlineAt < traceAt {
		t.Error("the headline is selected before the session trace is attached, so it will report no trace on every run")
	}
	calendarAt := strings.Index(src, "ar.Calendar = buildCalendar(")
	if calendarAt < 0 || headlineAt < calendarAt {
		t.Error("the headline is selected before the calendar it quotes")
	}
}

func pipelineSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("pipeline.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
