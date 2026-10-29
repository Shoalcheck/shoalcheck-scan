package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// EVERY REMEDIATION COMMAND THE PRODUCT SHIPS MUST PASS ITS OWN SAFETY CLASSIFIER.
//
// The standing rule is that a safe command may get a copy button and a destructive one must be rendered as
// commented manual documentation. `rules.SafeRemediationCommand` is the classifier that decides — and until
// 2026-08-28 it had **no production caller anywhere**. The report renders every RemediationCommand under a
// summary reading "Run this command" with a copy button beside it, consulting nothing.
//
// Measured before writing this: 21 findings on a real cluster carry a command and **none** would be rejected.
// So the hazard is latent, not live — the rule has been held by rule authors censoring themselves, which is a
// convention. This project's own lesson is that a rule somebody must remember is not a rule, and the cheapest
// place to make it one is here: internal/report may not import internal/rules (depcheck rule 1), so the
// renderer cannot ask, and internal/pipeline is the one package that sees both.
//
// This does NOT change the renderer and does not reword anything. It makes the convention mechanical, so the
// first destructive command anybody writes fails the build instead of shipping with a copy button.
func TestEveryRemediationCommand_PassesTheSafetyClassifier(t *testing.T) {
	ar := personaReport(t)
	withCmd := 0
	for _, f := range ar.Findings {
		if f.RemediationCommand == "" {
			continue
		}
		withCmd++
		if ok, reason := rules.SafeRemediationCommand(f.RemediationCommand); !ok {
			t.Errorf("%s (%s) ships a command the product's own classifier rejects — and the report gives it a "+
				"copy button under \"Run this command\":\n  reason: %s\n  command: %s\n\n"+
				"Either make it safe, or move it into RemediationYAML as commented manual documentation.",
				f.ID, f.RuleID, reason, f.RemediationCommand)
		}
	}
	if withCmd == 0 {
		t.Fatal("no finding in this fixture carries a remediation command, so this gate would pass vacuously")
	}
	t.Logf("%d remediation command(s) checked against SafeRemediationCommand", withCmd)
}

// personaReport is the golden fixture, which internal/fixture generates by running the REAL pipeline over the
// persona cluster — so it carries whatever the rules actually emit rather than what a hand-written fixture
// claims they emit. That distinction is why this gate reads it rather than constructing findings.
func personaReport(t *testing.T) *types.AuditReport {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "sample-audit.json"))
	if err != nil {
		t.Fatalf("read the golden fixture: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse the golden fixture: %v", err)
	}
	if len(ar.Findings) == 0 {
		t.Fatal("the golden fixture has no findings")
	}
	return &ar
}
