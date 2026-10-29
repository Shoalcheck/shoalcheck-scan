package rules

import (
	"fmt"
	"sort"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func find(id, ruleID string) types.Finding {
	return types.Finding{ID: id, RuleID: ruleID}
}

// rowKey is a compact identity for assertions.
func rowKey(r types.ComplianceRow) string { return r.Framework + " " + r.Control }

func TestBuildCompliance_EmptyFindingsIsNil(t *testing.T) {
	if got := BuildCompliance(nil); got != nil {
		t.Fatalf("empty findings must produce nil, got %+v", got)
	}
	if got := BuildCompliance([]types.Finding{}); got != nil {
		t.Fatalf("empty slice must produce nil, got %+v", got)
	}
}

func TestBuildCompliance_UnmappedRuleProducesNoRows(t *testing.T) {
	// Cost rules are deliberately absent from the compliance map.
	findings := []types.Finding{
		find("f-1", "k8s.cost.node-headroom"),
		find("f-2", "k8s.cost.idle-loadbalancer"),
	}
	if got := BuildCompliance(findings); got != nil {
		t.Fatalf("cost-only findings must map to no controls, got %+v", got)
	}
}

func TestBuildCompliance_MapsControlsWithFindingIDsSortedDeterministically(t *testing.T) {
	// cluster-admin (PCI 7.2.1, SOC2 CC6.3, CIS 5.1.1, NSA-CISA AUTH.least-priv)
	// + no-network-policy (PCI 1.3.1, CIS 5.3.2, NSA-CISA NET.netpol). Each
	// control should get exactly the finding IDs from the rule that maps to it,
	// Status "gap", sorted by framework/control.
	findings := []types.Finding{
		find("f-admin", "k8s.rbac.cluster-admin-serviceaccount"),
		find("f-netpol", "k8s.namespace.no-network-policy"),
	}
	rows := BuildCompliance(findings)

	want := []types.ComplianceRow{
		{Framework: "CIS-K8s", Control: "5.1.1", Status: "gap", FindingIDs: []string{"f-admin"}},
		{Framework: "CIS-K8s", Control: "5.3.2", Status: "gap", FindingIDs: []string{"f-netpol"}},
		{Framework: "NSA-CISA", Control: "AUTH.least-priv", Status: "gap", FindingIDs: []string{"f-admin"}},
		{Framework: "NSA-CISA", Control: "NET.netpol", Status: "gap", FindingIDs: []string{"f-netpol"}},
		{Framework: "PCI-DSS", Control: "1.3.1", Status: "gap", FindingIDs: []string{"f-netpol"}},
		{Framework: "PCI-DSS", Control: "7.2.1", Status: "gap", FindingIDs: []string{"f-admin"}},
		{Framework: "SOC2", Control: "CC6.3", Status: "gap", FindingIDs: []string{"f-admin"}},
	}
	if len(rows) != len(want) {
		t.Fatalf("want %d rows, got %d: %+v", len(want), len(rows), rows)
	}

	// Verify deterministic sort: framework then control, ascending.
	if !sort.SliceIsSorted(rows, func(i, j int) bool {
		if rows[i].Framework != rows[j].Framework {
			return rows[i].Framework < rows[j].Framework
		}
		return rows[i].Control < rows[j].Control
	}) {
		t.Errorf("rows not sorted by framework then control: %+v", rows)
	}

	for i, w := range want {
		got := rows[i]
		if got.Framework != w.Framework || got.Control != w.Control {
			t.Errorf("row %d: got %s, want %s", i, rowKey(got), rowKey(w))
		}
		if got.Status != "gap" {
			t.Errorf("row %s: status = %q, want \"gap\"", rowKey(got), got.Status)
		}
		if got.Title == "" {
			t.Errorf("row %s: empty title", rowKey(got))
		}
		if len(got.FindingIDs) != len(w.FindingIDs) || got.FindingIDs[0] != w.FindingIDs[0] {
			t.Errorf("row %s: findingIDs = %v, want %v", rowKey(got), got.FindingIDs, w.FindingIDs)
		}
	}
}

func TestBuildCompliance_MergesFindingsSharingAControl(t *testing.T) {
	// Multiple reliability rules map to SOC2 A1.2 — their findings must collapse
	// into one row carrying all the matching finding IDs.
	findings := []types.Finding{
		find("f-replica", "k8s.workload.single-replica-no-pdb"),
		find("f-affinity", "k8s.workload.no-anti-affinity"),
		find("f-rollout", "k8s.workload.risky-rollout-strategy"),
	}
	rows := BuildCompliance(findings)
	if len(rows) != 1 {
		t.Fatalf("three rules sharing SOC2 A1.2 must yield 1 row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Framework != "SOC2" || r.Control != "A1.2" {
		t.Errorf("merged row = %s, want SOC2 A1.2", rowKey(r))
	}
	if len(r.FindingIDs) != 3 {
		t.Errorf("merged row must carry all 3 finding IDs, got %v", r.FindingIDs)
	}
}

func TestBuildCompliance_CapsFindingIDs(t *testing.T) {
	// More than maxFindingIDs findings against the same control must be capped.
	var findings []types.Finding
	for i := 0; i < maxFindingIDs+5; i++ {
		findings = append(findings, find(fmt.Sprintf("f-%d", i), "k8s.workload.no-probes"))
	}
	rows := BuildCompliance(findings)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if len(rows[0].FindingIDs) != maxFindingIDs {
		t.Errorf("findingIDs not capped: got %d, want %d", len(rows[0].FindingIDs), maxFindingIDs)
	}
}

// TestBuildCompliance_EveryMappedRuleIDIsRealRule guards against typos in the
// compliance table: every ruleID key must correspond to a registered rule.
func TestBuildCompliance_EveryMappedRuleIDIsRealRule(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	registered := map[string]bool{}
	for _, r := range All() {
		registered[r.ID()] = true
	}
	for ruleID := range complianceMap {
		if !registered[ruleID] {
			t.Errorf("compliance map references unknown ruleID %q", ruleID)
		}
	}
}

// TestBuildCompliance_NSACISAFansOut verifies the P3 NSA/CISA mapping: a single
// finding whose rule maps to NSA-CISA produces an NSA-CISA row alongside the
// CIS/PCI/SOC2 rows, carries the synthetic citation in Control, the real section
// name in Title, and still emits Status "gap" (so the renderer reframes it to
// "Potential gap" exactly like every other framework).
func TestBuildCompliance_NSACISAFansOut(t *testing.T) {
	findings := []types.Finding{
		find("f-priv", "k8s.workload.privileged-host-access"),
		find("f-netpol", "k8s.namespace.no-network-policy"),
	}
	rows := BuildCompliance(findings)

	var nsa []types.ComplianceRow
	for _, r := range rows {
		if r.Framework == "NSA-CISA" {
			nsa = append(nsa, r)
		}
	}
	if len(nsa) == 0 {
		t.Fatalf("expected NSA-CISA rows, got none in %+v", rows)
	}
	// Every NSA-CISA row uses the synthetic <Section>.<topic> scheme and stays "gap".
	wantSynthetic := map[string]bool{
		"PS.privileged": false, "PS.hostpath": false, "NET.netpol": false,
	}
	for _, r := range nsa {
		if r.Status != "gap" {
			t.Errorf("NSA-CISA row %q: status = %q, want \"gap\"", r.Control, r.Status)
		}
		if r.Title == "" {
			t.Errorf("NSA-CISA row %q: empty Title (must carry the real section name)", r.Control)
		}
		if _, ok := wantSynthetic[r.Control]; ok {
			wantSynthetic[r.Control] = true
		}
	}
	for ctrl, seen := range wantSynthetic {
		if !seen {
			t.Errorf("expected NSA-CISA synthetic control %q to be emitted, missing", ctrl)
		}
	}
}

// TestBuildComplianceAssessment_EveryCISControlInMapIsEnumerated guards against
// the two-table-drift risk between complianceMap and cisControlUniverse: every
// Framework=="CIS-K8s" control that has an evidence rule must also appear in the
// universe, or its findings would have nowhere to land and the reverse-indexed
// EvidenceRuleIDs would silently drop. Mirrors the drift-guard above.
func TestBuildComplianceAssessment_EveryCISControlInMapIsEnumerated(t *testing.T) {
	enumerated := map[string]bool{}
	for _, u := range cisControlUniverse {
		enumerated[u.Control] = true
	}
	for _, refs := range complianceMap {
		for _, c := range refs {
			if c.Framework != "CIS-K8s" {
				continue
			}
			if !enumerated[c.Control] {
				t.Errorf("complianceMap maps CIS-K8s control %q but it is absent from cisControlUniverse", c.Control)
			}
		}
	}
}

// TestBuildComplianceAssessment_PassRequiresEvidenceRule is the honesty
// invariant in test form: a control may be PASS only if it carries at least one
// EvidenceRuleIDs entry. A PASS with no evidence rule would mean "we didn't look"
// masquerading as "we checked and it's clean" — the exact overclaim the product
// exists to eliminate.
func TestBuildComplianceAssessment_PassRequiresEvidenceRule(t *testing.T) {
	a := BuildComplianceAssessment(nil)
	for _, c := range a.Controls {
		if c.Status == types.ControlStatusPass && len(c.EvidenceRuleIDs) == 0 {
			t.Errorf("control %s is PASS with no evidence rule — violates honesty invariant", c.Control)
		}
		if c.Status == types.ControlStatusNA && (c.Control[0] < '1' || c.Control[0] > '4') {
			t.Errorf("control %s is NA but not in §1-4: %q", c.Control, c.Control)
		}
	}
}

// TestBuildComplianceAssessment_ScoreIsDenominatorHonest checks the score math:
// Total == len(Controls), Scored == Passed+Failed, MANUAL/NA excluded from
// PassRate, and the Totals tally matches the per-status counts.
func TestBuildComplianceAssessment_ScoreIsDenominatorHonest(t *testing.T) {
	// Drive a FAIL via a real mapped finding (no-network-policy → CIS 5.3.2).
	findings := []types.Finding{find("f-netpol", "k8s.namespace.no-network-policy")}
	a := BuildComplianceAssessment(findings)
	s := a.Score

	if s.Total != len(a.Controls) {
		t.Errorf("Total=%d but %d controls", s.Total, len(a.Controls))
	}
	if s.Scored != s.Passed+s.Failed {
		t.Errorf("Scored=%d but Passed+Failed=%d", s.Scored, s.Passed+s.Failed)
	}
	if s.Total != s.Passed+s.Failed+s.Manual+s.NA {
		t.Errorf("status counts %d/%d/%d/%d don't sum to Total %d", s.Passed, s.Failed, s.Manual, s.NA, s.Total)
	}
	if s.Scored > 0 {
		want := float64(s.Passed) / float64(s.Scored)
		if s.PassRate != want {
			t.Errorf("PassRate=%v, want %v (MANUAL/NA must be excluded)", s.PassRate, want)
		}
	}
	for status, n := range map[types.ControlStatus]int{
		types.ControlStatusPass:   s.Passed,
		types.ControlStatusFail:   s.Failed,
		types.ControlStatusManual: s.Manual,
		types.ControlStatusNA:     s.NA,
	} {
		if s.Totals[status] != n {
			t.Errorf("Totals[%s]=%d but per-status count is %d", status, s.Totals[status], n)
		}
	}

	// 5.3.2 must be FAIL with the finding + evidence rule attached.
	var found bool
	for _, c := range a.Controls {
		if c.Control == "5.3.2" {
			found = true
			if c.Status != types.ControlStatusFail {
				t.Errorf("5.3.2 status=%q, want FAIL", c.Status)
			}
			if len(c.FindingIDs) == 0 || len(c.EvidenceRuleIDs) == 0 {
				t.Errorf("5.3.2 FAIL must carry findingIDs (%v) and evidenceRuleIDs (%v)", c.FindingIDs, c.EvidenceRuleIDs)
			}
		}
	}
	if !found {
		t.Fatal("5.3.2 not enumerated")
	}
}

// statusOf returns the assessed status of one control number, failing if absent.
func statusOf(t *testing.T, a *types.ComplianceAssessment, control string) types.ComplianceControl {
	t.Helper()
	for _, c := range a.Controls {
		if c.Control == control {
			return c
		}
	}
	t.Fatalf("control %q not enumerated in assessment", control)
	return types.ComplianceControl{}
}

// TestBuildComplianceAssessment_PSSControlsNoLongerManual is the P2 universe
// upgrade in test form: controls that gained a real evidence rule in P2 must now
// be DERIVED (PASS with no finding, FAIL with one), never forced MANUAL. This is
// the whole point of removing the forced-MANUAL override.
func TestBuildComplianceAssessment_PSSControlsNoLongerManual(t *testing.T) {
	// With no findings, every PSS-backed control PASSES (a rule ran, found nothing).
	clean := BuildComplianceAssessment(nil)
	for _, control := range []string{"5.2.1", "5.2.2", "5.2.6", "5.2.7", "5.2.8", "5.2.10", "5.2.13"} {
		c := statusOf(t, clean, control)
		if c.Status != types.ControlStatusPass {
			t.Errorf("control %s should be PASS (rule ran, no finding), got %s", control, c.Status)
		}
		if len(c.EvidenceRuleIDs) == 0 {
			t.Errorf("control %s PASS must carry EvidenceRuleIDs (the honesty invariant)", control)
		}
	}

	// 5.2.11 (Windows HostProcess) has NO rule and must stay MANUAL.
	if c := statusOf(t, clean, "5.2.11"); c.Status != types.ControlStatusManual {
		t.Errorf("5.2.11 has no rule and must stay MANUAL, got %s", c.Status)
	}

	// With a matching finding, the control FAILS and carries the finding + rule.
	findings := []types.Finding{
		find("f-priv", "k8s.workload.allow-privilege-escalation"), // → CIS 5.2.6
		find("f-caps", "k8s.workload.dangerous-capabilities"),     // → CIS 5.2.8 + 5.2.9
	}
	fired := BuildComplianceAssessment(findings)

	c526 := statusOf(t, fired, "5.2.6")
	if c526.Status != types.ControlStatusFail {
		t.Errorf("5.2.6 with a matching finding must be FAIL, got %s", c526.Status)
	}
	if len(c526.FindingIDs) == 0 || len(c526.EvidenceRuleIDs) == 0 {
		t.Errorf("5.2.6 FAIL must carry findingIDs (%v) + evidenceRuleIDs (%v)", c526.FindingIDs, c526.EvidenceRuleIDs)
	}
	if c528 := statusOf(t, fired, "5.2.8"); c528.Status != types.ControlStatusFail {
		t.Errorf("5.2.8 with a matching finding must be FAIL, got %s", c528.Status)
	}
	// Controls without a matching finding still PASS in the same run.
	if c527 := statusOf(t, fired, "5.2.7"); c527.Status != types.ControlStatusPass {
		t.Errorf("5.2.7 (no matching finding) must PASS, got %s", c527.Status)
	}
}

// TestBuildComplianceAssessment_DefaultNamespaceDerivesPassFail verifies that
// 5.7.4 (default namespace) is now DERIVED (PASS with no finding, FAIL with one)
// rather than forced MANUAL — the forced-MANUAL override was removed in this
// pass now that default-namespace-in-use ships as an evidence rule.
func TestBuildComplianceAssessment_DefaultNamespaceDerivesPassFail(t *testing.T) {
	// No findings → a rule ran and found nothing → PASS with an evidence rule.
	clean := statusOf(t, BuildComplianceAssessment(nil), "5.7.4")
	if clean.Status != types.ControlStatusPass {
		t.Errorf("5.7.4 with no finding must PASS (not MANUAL), got %s", clean.Status)
	}
	if len(clean.EvidenceRuleIDs) == 0 {
		t.Errorf("5.7.4 PASS must carry EvidenceRuleIDs (the honesty invariant), got %v", clean.EvidenceRuleIDs)
	}

	// A matching finding → FAIL with the finding + evidence rule attached.
	findings := []types.Finding{find("f-default", "k8s.namespace.default-namespace-in-use")}
	fired := statusOf(t, BuildComplianceAssessment(findings), "5.7.4")
	if fired.Status != types.ControlStatusFail {
		t.Errorf("5.7.4 with a matching finding must be FAIL, got %s", fired.Status)
	}
	if len(fired.FindingIDs) == 0 || len(fired.EvidenceRuleIDs) == 0 {
		t.Errorf("5.7.4 FAIL must carry findingIDs (%v) + evidenceRuleIDs (%v)", fired.FindingIDs, fired.EvidenceRuleIDs)
	}

	// 5.7.2 stays MANUAL (no discrete evidence rule; seccomp folds into 5.2.1).
	if c := statusOf(t, BuildComplianceAssessment(nil), "5.7.2"); c.Status != types.ControlStatusManual {
		t.Errorf("5.7.2 has no discrete rule and must stay MANUAL, got %s", c.Status)
	}
}

// TestBuildComplianceAssessment_PrivilegedHostAccessFansOut verifies the
// renumbered privileged-host-access row drives every CIS v1.9 control it maps to.
func TestBuildComplianceAssessment_PrivilegedHostAccessFansOut(t *testing.T) {
	findings := []types.Finding{find("f-priv", "k8s.workload.privileged-host-access")}
	a := BuildComplianceAssessment(findings)
	for _, control := range []string{"5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.12", "5.2.13"} {
		c := statusOf(t, a, control)
		if c.Status != types.ControlStatusFail {
			t.Errorf("privileged-host-access must drive %s to FAIL, got %s", control, c.Status)
		}
	}
}

// TestBuildComplianceAssessment_Deterministic asserts controls come back sorted
// by control number on every call (templates and golden diffs depend on it).
func TestBuildComplianceAssessment_Deterministic(t *testing.T) {
	a := BuildComplianceAssessment(nil)
	if !sort.SliceIsSorted(a.Controls, func(i, j int) bool { return a.Controls[i].Control < a.Controls[j].Control }) {
		t.Errorf("controls not sorted by control number")
	}
	if a.Framework != "CIS-K8s" {
		t.Errorf("framework=%q, want CIS-K8s", a.Framework)
	}
	if a.Version == "" {
		t.Error("version must be set so 'N of M' never reads as the whole benchmark")
	}
}
