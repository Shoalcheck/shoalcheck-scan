package rules

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The coverage sentence's numbers are BUILD facts read off the tables, and this test recomputes them from the
// same tables independently: a control counts as checkable when the universe does not force its status and at
// least one evidence rule maps to it. Findings must not move Checkable or InScope — only Scored.
func TestComplianceScore_CheckableAndInScopeAreBuildFacts(t *testing.T) {
	evidence := cisEvidenceRuleIndex()
	wantCheckable := 0
	for _, u := range cisControlUniverse {
		if u.forceStatus == "" && len(evidence[u.Control]) > 0 {
			wantCheckable++
		}
	}
	if wantCheckable == 0 {
		t.Fatal("no universe control has an evidence rule — this test would prove nothing")
	}
	empty := BuildComplianceAssessment(nil)
	if empty.Score.Checkable != wantCheckable {
		t.Errorf("Checkable = %d, tables say %d", empty.Score.Checkable, wantCheckable)
	}
	if empty.Score.InScope != empty.Score.Total-empty.Score.NA {
		t.Errorf("InScope = %d, want Total-NA = %d", empty.Score.InScope, empty.Score.Total-empty.Score.NA)
	}
	if empty.Score.Checkable > empty.Score.InScope {
		t.Errorf("Checkable %d exceeds InScope %d", empty.Score.Checkable, empty.Score.InScope)
	}
	// A run with a finding under a mapped rule changes Scored, not the build facts.
	f := types.Finding{ID: "f-1", RuleID: "k8s.rbac.cluster-admin-serviceaccount", RuleVersion: "1.0.0", Title: "t",
		Severity: types.SeverityHigh, Category: types.CategorySecurity, EstimatedEffort: types.EffortLow, Confidence: 0.9}
	withFinding := BuildComplianceAssessment([]types.Finding{f})
	if withFinding.Score.Checkable != empty.Score.Checkable || withFinding.Score.InScope != empty.Score.InScope {
		t.Errorf("findings moved a build fact: %+v vs %+v", withFinding.Score, empty.Score)
	}
}

// A CONTROL PINNED TO MANUAL STILL POINTS AT WHAT WAS FOUND.
//
// CIS 5.1.7 "Avoid use of system:masters group" is forced to MANUAL for a reason that does not change: a
// client certificate carrying O=system:masters makes its holder a member with no RBAC object anywhere, so a
// clean read cannot assert clean. Since k8s.rbac.binding-to-builtin-subject exists, a reading CAN contain
// the bindings that name that group — and the control row was showing "assess manually" with no pointer to
// them, in a document that held the finding two sections away.
//
// STATUS IS UNCHANGED. The PASS is what the force withholds, and it stays withheld; what is attached is the
// evidence, so a reader following the control reaches the finding instead of searching for it. Checkable is
// a build fact and must not move — a forced control has no automated verdict however much it found.
func TestComplianceControl_ForcedManualStillCarriesItsFindings(t *testing.T) {
	f := types.Finding{
		ID: "f-masters", RuleID: "k8s.rbac.binding-to-builtin-subject", RuleVersion: "1.0.0",
		Title: "ClusterRoleBinding break-glass binds Group system:masters", Severity: types.SeverityHigh,
		Category: types.CategorySecurity, EstimatedEffort: types.EffortMedium, Confidence: 1,
	}
	before := BuildComplianceAssessment(nil)
	got := BuildComplianceAssessment([]types.Finding{f})

	var c *types.ComplianceControl
	for i := range got.Controls {
		if got.Controls[i].Control == "5.1.7" {
			c = &got.Controls[i]
		}
	}
	if c == nil {
		t.Fatal("5.1.7 is not in the assessment at all")
	}
	if c.Status != types.ControlStatusManual {
		t.Errorf("5.1.7 is %q: the force exists because an absence of bindings is not an absence of the "+
			"group, and a finding does not change that", c.Status)
	}
	if len(c.FindingIDs) == 0 {
		t.Error("5.1.7 carries no finding id while the reading holds a finding for the rule mapped to it: " +
			"a reader following the control has to go looking for what the document already knows")
	}
	if len(c.EvidenceRuleIDs) == 0 {
		t.Error("5.1.7 names no evidence rule, so nothing says which check produced what it shows")
	}
	if got.Score.Checkable != before.Score.Checkable {
		t.Errorf("Checkable moved from %d to %d: a forced control has no automated verdict however much it "+
			"found, and Checkable is a build fact", before.Score.Checkable, got.Score.Checkable)
	}
}
