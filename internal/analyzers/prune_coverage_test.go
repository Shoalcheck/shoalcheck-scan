package analyzers

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// Every kind an analyzer asks the collector for has declared the fields its readers use. Without a rule the
// collector keeps only an object's identity (collect/prune.go), which would silently starve the analyzer;
// this names the kind instead.
func TestEveryRequestedKindDeclaresTheFieldsItsReadersUse(t *testing.T) {
	gvrs := RequiredGVRsUnion()
	if len(gvrs) == 0 {
		t.Fatal("no analyzer requests a kind: the check would pass over nothing")
	}
	for _, gvr := range gvrs {
		if !collect.HasPruneRule(gvr.GroupResource()) {
			t.Errorf("%s is requested by an analyzer but has no rule in collect/prune.go: declare the fields it reads", gvr.GroupResource())
		}
	}
	t.Logf("%d requested kind(s) checked", len(gvrs))
}
