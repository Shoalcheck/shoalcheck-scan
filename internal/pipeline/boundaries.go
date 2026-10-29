package pipeline

import (
	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// attachClaimBoundaries stamps each finding with what it does NOT establish.
//
// WHY HERE, and it is the fifth time this shape has been the answer. `scripts/depcheck.sh` rule 1 forbids
// internal/report from importing internal/rules, so a renderer cannot ask a rule anything — and the same is
// true of the evidence pack, of a SARIF export, of the app and of anything else downstream. Resolving
// boundaries by rule id at each surface would put them only where somebody remembered to look them up. So the
// declaration lives with the rules and travels to every surface on the finding, exactly as Pillar,
// CommandSafety, PriceBasis and Basis already do.
//
// TWO PRODUCERS, MERGED HERE. The family boundaries come from internal/boundaries by rule id and are true on
// every cluster. A CONDITIONAL boundary is a property of THIS RUN and is appended by the rule itself at
// Evaluate time, so it is already on the finding when this runs — which is why the merge is a union rather
// than an assignment. Getting that backwards would silently drop the more valuable half.
//
// DE-DUPLICATED, because a rule may belong to two families and because the same sentence arriving from a
// family and from a conditional append should appear once.
//
// AND ORDERED: the conditional lines first, in the order the rule appended them, then the family lines in
// the order they are declared. This used to end in sort.Strings, for determinism — two readings of one
// cluster must produce the same bytes, which is the property internal/collect/capture.go exists to protect.
// That property survives without it, because both inputs are slices Go iterates in order, and the sort was
// buying it at a price nobody chose: the first sentence a reader saw was whichever started with the earliest
// letter. Measured on stack.hpa.no-headroom, the sentence saying what KIND of claim the finding is came
// third. The conditional half leads because it is the more valuable one — a family line is true on every
// cluster, and a conditional line is what THIS reading could not establish.
func attachClaimBoundaries(findings []types.Finding) {
	for i := range findings {
		seen := map[string]bool{}
		var merged []string
		for _, line := range findings[i].ClaimBoundaries {
			if line != "" && !seen[line] {
				seen[line] = true
				merged = append(merged, line)
			}
		}
		for _, line := range boundaries.For(findings[i].RuleID) {
			if !seen[line] {
				seen[line] = true
				merged = append(merged, line)
			}
		}
		findings[i].ClaimBoundaries = merged
	}
}
