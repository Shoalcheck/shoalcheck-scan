package pipeline

import (
	"sort"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// The stamp is read from the SAME two registries the engine-version digest reads, so the two cannot
// disagree about what a producer is.
func TestRuleSetStamp_NamesEveryProducerOnce(t *testing.T) {
	got := RuleSetStamp()
	want := len(rules.All()) + len(analyzers.All())
	if len(got) != want {
		t.Fatalf("stamp has %d entries, registries have %d producers", len(got), want)
	}
	seen := map[string]bool{}
	for i, s := range got {
		if s.ID == "" || s.Version == "" {
			t.Errorf("entry %d has an empty ID or Version: %+v", i, s)
		}
		if seen[s.ID] {
			t.Errorf("producer %q appears twice", s.ID)
		}
		seen[s.ID] = true
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].ID < got[j].ID }) {
		t.Error("stamp is not sorted by ID — a snapshot's bytes would depend on registration order")
	}
}
