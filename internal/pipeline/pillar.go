package pipeline

import (
	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// attachPillar stamps each finding with which of the product's two headline claims it belongs to.
//
// WHY HERE. scripts/depcheck.sh rule 1 forbids internal/report from importing internal/rules, so the renderer
// cannot ask a rule anything; and a rule-ID-to-pillar map inside the renderer would be a copy of the registry
// maintained by hand, which is the defect class this project found four times in two days. So the declaration
// lives with the rules and travels to the renderer on the finding — the same path Basis, PriceBasis and
// Requests already take. Third time that shape has been the answer.
//
// A rule with no entry gets PillarNone and rules.TestEveryRuleDeclaresAPillar fails the build for it, so this
// function never has to guess: by the time it runs, every registered rule has an explicit answer.
//
// ANALYZER FINDINGS NOW DECLARE TOO, in their own package, because internal/rules cannot see IDs that
// internal/analyzers mints. Almost every analyzer abstains and says why; the monitoring four are the third
// pillar, which exists because a monitoring stack is the one component whose failure removes the thing that
// would report it. The two tables are merged here, and a key in both is a bug in one of them — asserted by
// TestPillarTables_DoNotOverlap.
func attachPillar(findings []types.Finding) {
	table := rules.PillarByRule()
	for id, p := range analyzers.PillarByRule() {
		table[id] = p
	}
	for i := range findings {
		findings[i].Pillar = table[findings[i].RuleID]
	}
}
