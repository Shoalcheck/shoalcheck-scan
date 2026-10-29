package pipeline

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE CHECKS A PERSON WOULD MAKE BY HAND. Pairs is what the "hours by hand" figure multiplies by an assumed
// time per check, so it must be exactly Σ over rules of the objects in the kinds each reads — a kind nobody
// read contributes nothing, and a reading with no volume gets no count at all rather than zero.
func TestCountPairs_SumsEachRulesKindsOverWhatWasRead(t *testing.T) {
	v := &types.ReadVolume{ByKind: []types.KindVolume{{Kind: "pods", Objects: 10}, {Kind: "nodes", Objects: 3}}}
	countPairs(v, map[string]rules.Dependencies{
		"a": {Kinds: []string{"pods", "nodes"}}, // 13
		"b": {Kinds: []string{"pods"}},          // 10
		"c": {Kinds: []string{"ingresses"}},     // 0: not read
	})
	if v.Pairs != 23 {
		t.Errorf("pairs = %d, want 23", v.Pairs)
	}
	countPairs(nil, map[string]rules.Dependencies{"a": {Kinds: []string{"pods"}}}) // must not panic
}
