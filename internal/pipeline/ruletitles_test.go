package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/ruletitles"
)

// EVERY PROBLEM THE ENGINE CAN FIND HAS A NAME THAT NAMES NO OBJECT. The free line prints these instead of a
// finding's title; a rule added without one would fall back to its humanised id, which is subject-free but reads
// worse — so the table must keep up with the registry, and every entry must still be subject-free.
func TestRuleTitles_CoverEveryProducerAndNameNoObject(t *testing.T) {
	deps := FindingDependencies()
	if len(deps) < 90 {
		t.Fatalf("only %d producers in the registry — this test is measuring nothing", len(deps))
	}
	for id := range deps {
		if !ruletitles.Known(id) {
			t.Errorf("%s has no subject-free title in internal/ruletitles", id)
		}
	}
	seen := map[string]string{}
	ruletitles.Each(func(id, title string) {
		if _, ok := deps[id]; !ok {
			t.Errorf("internal/ruletitles names %s, which no producer emits", id)
		}
		if strings.ContainsAny(title, "/:") {
			t.Errorf("%s's title %q looks like it names an object", id, title)
		}
		if prev, dup := seen[title]; dup {
			t.Errorf("%s and %s share the title %q", prev, id, title)
		}
		seen[title] = id
	})
}
