package rules

import (
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The per-family banned-phrase lists are DOMAIN vocabularies — "rotation" and "traffic path" belong
// to the drain family, "will schedule" to the rollout family — and they are correctly separate.
// A handful of words are not domain-specific at all: they are the product's global copy policy, and
// `internal/lexicon` is the one table that holds it.
//
// "guaranteed" had drifted into both. Restating a global term in a family list is the failure the
// lexicon package was created to end: a word added to one list is unknown to the others. So the
// family lists keep only their own vocabulary, and this test applies the GLOBAL table to every
// rule's output — one table, many consumers, the same shape the report and the app already use.
func TestRuleOutput_ClearsTheGlobalCopyPolicy(t *testing.T) {
	inv := rolloutInventory() // any populated fixture: the point is coverage of the policy, not of the cluster
	var fired int
	var silent []string
	for _, r := range All() {
		out := r.Evaluate(inv, Options{IncludeSystem: true})
		if len(out) == 0 {
			silent = append(silent, r.ID())
		}
		for _, f := range out {
			fired++
			blob := strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " ")
			// Scope: a finding is not a document region, so the whole string is scanned against the
			// unscoped terms. A scoped term (one that names a document region) cannot apply here.
			for _, v := range lexicon.Scan(blob, func(lexicon.Scope) (string, bool) { return "", true }) {
				t.Errorf("%s emits the globally banned %q — %s\n  finding: %s",
					r.ID(), v.Term.Text, v.Term.Why, f.Title)
			}
		}
	}
	if fired == 0 {
		t.Fatal("no rule fired on the fixture — this gate would pass vacuously")
	}

	// NAMED, NOT ASSUMED. This test was called TestEveryRuleOutput_… and measured 18 of 37 rules: the guard
	// above proves the scan is not empty, and proves nothing about its reach. A check that cannot say what it
	// did not cover invites the reading that it covered everything — the same defect as a browser gate that
	// only ever measured one fixture, and as the golden fixture that hid `clean-cluster` for a day.
	//
	// A silent rule is NOT a defect: this fixture is a rollout fixture and most rules have nothing to say
	// about it. What is a defect is the number quietly shrinking, so the floor is asserted and the gap is
	// printed with its members. Raise the floor when a fixture covers more; never lower it without a sentence.
	const minRulesCovered = 18
	covered := len(All()) - len(silent)
	sort.Strings(silent)
	t.Logf("global copy policy scanned %d finding(s) from %d of %d rules; silent on this fixture:\n  %s",
		fired, covered, len(All()), strings.Join(silent, "\n  "))
	if covered < minRulesCovered {
		t.Errorf("only %d of %d rules produced output to scan, down from %d — the policy's reach over rule "+
			"output has shrunk, or the fixture has", covered, len(All()), minRulesCovered)
	}
	_ = types.SeverityLow
}
