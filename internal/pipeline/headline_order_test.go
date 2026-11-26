package pipeline

import (
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
	// And the pipeline's own order. The assembly derives it from each stage's declared needs (assembly.go), so the
	// property is that the headline needs the trace and the calendar, directly or through another stage.
	order, err := orderStages(assemblyStages)
	if err != nil {
		t.Fatal(err)
	}
	at := map[string]int{}
	for i, s := range order {
		at[s.name] = i
	}
	for _, before := range []string{"session trace", "calendar"} {
		if at[before] > at["headline"] {
			t.Errorf("the headline is selected before the %s it quotes", before)
		}
	}
	if !needsTransitively("headline", "trace") || !needsTransitively("headline", "calendar") {
		t.Error("the headline stage does not declare the trace and the calendar among what it needs")
	}
}

// needsTransitively reports whether stage name needs key, directly or through the stage that provides one of its needs.
func needsTransitively(name, key string) bool {
	byName, provider := map[string]stage{}, map[string]string{}
	for _, s := range assemblyStages {
		byName[s.name] = s
		for _, k := range s.provides {
			provider[k] = s.name
		}
	}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if seen[n] {
			return false
		}
		seen[n] = true
		for _, k := range byName[n].needs {
			if k == key || walk(provider[k]) {
				return true
			}
		}
		return false
	}
	return walk(name)
}
