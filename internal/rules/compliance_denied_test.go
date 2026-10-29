package rules

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// NEVER PASS AN UNCHECKED CONTROL — AND A DENIED READ IS UNCHECKED.
//
// BuildComplianceAssessment reaches PASS by one path: an evidence rule maps to the control and produced no
// finding. That is correct when the rule ran. It is a false clean bill when the rule's INPUTS were refused,
// because every rule in this package carries a denial guard and returns nothing rather than asserting an
// absence it could not observe. The two look identical from the outside: no findings.
//
// This became load-bearing the moment nine CIS §5.1 controls stopped being MANUAL. RBAC is the read a
// customer's cluster is most likely to refuse — a scoped auditor Role that omits `clusterroles` is a
// perfectly ordinary thing to hand a vendor — and "5.1.2 Minimize access to secrets: PASS" on a cluster
// whose roles we could not read is exactly the sentence this product exists not to print.
func TestCompliance_ADeniedEvidenceReadIsNotAPass(t *testing.T) {
	// The kinds the dangerous-grant rule rests on, refused.
	denied := map[string]bool{"clusterroles": true, "roles": true}

	got := BuildComplianceAssessmentWithCoverage(nil, func(kind string) bool { return !denied[kind] })
	if got == nil {
		t.Fatal("no assessment was produced")
	}

	byControl := map[string]types.ComplianceControl{}
	for _, c := range got.Controls {
		byControl[c.Control] = c
	}

	// Every control whose only evidence rule reads roles must be MANUAL, not PASS.
	for _, id := range []string{"5.1.2", "5.1.4", "5.1.8", "5.1.9", "5.1.10", "5.1.11", "5.1.12", "5.1.13"} {
		c, ok := byControl[id]
		if !ok {
			t.Errorf("%s is not in the control universe", id)
			continue
		}
		if c.Status == types.ControlStatusPass {
			t.Errorf("%s is PASS on a cluster whose Role/ClusterRole bodies were refused — a clean bill from "+
				"a read that never happened", id)
		}
		if c.Status != types.ControlStatusManual {
			t.Errorf("%s is %s with its evidence read denied; want manual", id, c.Status)
		}
		if !strings.Contains(strings.ToLower(c.Rationale), "denied") &&
			!strings.Contains(strings.ToLower(c.Rationale), "refused") &&
			!strings.Contains(strings.ToLower(c.Rationale), "not collected") {
			t.Errorf("%s degraded to manual without saying why: %q", id, c.Rationale)
		}
	}

	// NON-VACUITY: with the SAME empty finding set and nothing denied, those controls must PASS. Otherwise
	// "not PASS" would be true because the rule never passes anything, and this test would prove nothing.
	clean := BuildComplianceAssessmentWithCoverage(nil, func(string) bool { return true })
	passed := 0
	for _, c := range clean.Controls {
		switch c.Control {
		case "5.1.2", "5.1.4", "5.1.8", "5.1.9", "5.1.10", "5.1.11", "5.1.12", "5.1.13":
			if c.Status == types.ControlStatusPass {
				passed++
			} else {
				t.Errorf("%s is %s on a fully-read cluster with no findings; want pass", c.Control, c.Status)
			}
		}
	}
	if passed != 8 {
		t.Errorf("%d of 8 role-body controls passed on a clean, fully-read cluster", passed)
	}
}

// The old entry point must keep working and must keep the SAME posture: called without coverage
// information it cannot know a read was denied, so it must not invent one. Every existing caller goes
// through the pipeline, which does know.
func TestCompliance_TheCoverageFreeEntryPointStillWorks(t *testing.T) {
	got := BuildComplianceAssessment(nil)
	if got == nil || len(got.Controls) == 0 {
		t.Fatal("BuildComplianceAssessment produced nothing")
	}
}
