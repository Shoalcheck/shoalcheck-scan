package pipeline

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// RuleSetStamp lists every producer this build can put a finding under, sorted by ID.
//
// THE SAME TWO REGISTRIES AS THE ENGINE-VERSION DIGEST (engine_version_test.go): rules.All() and
// analyzers.All(). Reading them here rather than keeping a list means a rule added to the registry is in
// the stamp by existing, and the stamp and the digest cannot disagree about what a producer is.
func RuleSetStamp() []types.RuleStamp {
	var out []types.RuleStamp
	for _, r := range rules.All() {
		out = append(out, types.RuleStamp{ID: r.ID(), Version: r.Version()})
	}
	for _, a := range analyzers.All() {
		out = append(out, types.RuleStamp{ID: a.ID(), Version: a.Version()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
