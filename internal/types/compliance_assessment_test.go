package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControlStatus_Valid(t *testing.T) {
	for _, s := range []ControlStatus{ControlStatusPass, ControlStatusFail, ControlStatusManual, ControlStatusNA} {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []ControlStatus{"", "pass", "Pass", "OK", "violation"} {
		if s.Valid() {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestProfileLevel_Valid(t *testing.T) {
	for _, p := range []ProfileLevel{0, ProfileLevel1, ProfileLevel2} {
		if !p.Valid() {
			t.Errorf("profile %d should be valid (0 = unspecified)", p)
		}
	}
	for _, p := range []ProfileLevel{-1, 3, 99} {
		if p.Valid() {
			t.Errorf("profile %d should be invalid", p)
		}
	}
}

// TestComplianceAssessment_NilSerializesIdentically is the contract that lets
// the golden fixture stay un-regenerated: a report with a nil
// ComplianceAssessment must marshal WITHOUT the complianceAssessment key
// (omitempty), so existing fixtures serialize byte-identically.
func TestComplianceAssessment_NilSerializesIdentically(t *testing.T) {
	ar := AuditReport{SchemaVersion: "v1"}
	data, err := json.Marshal(&ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "complianceAssessment") {
		t.Errorf("nil ComplianceAssessment must be omitted, got: %s", data)
	}
}

func TestComplianceAssessment_JSONRoundTrip(t *testing.T) {
	in := AuditReport{
		SchemaVersion: "v1",
		ComplianceAssessment: &ComplianceAssessment{
			Framework: "CIS-K8s",
			Version:   "CIS Kubernetes Benchmark v1.9 (Section 5 subset)",
			Controls: []ComplianceControl{{
				Control: "5.3.2", Title: "NetworkPolicies", Status: ControlStatusFail,
				Profile: ProfileLevel2, FindingIDs: []string{"f-1"},
				EvidenceRuleIDs: []string{"k8s.namespace.no-network-policy"},
			}},
			Score: ComplianceScore{Total: 1, Failed: 1, Scored: 1,
				Totals: map[ControlStatus]int{ControlStatusFail: 1}},
		},
	}
	data, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AuditReport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ComplianceAssessment == nil || out.ComplianceAssessment.Controls[0].Control != "5.3.2" {
		t.Fatalf("round-trip lost data: %+v", out.ComplianceAssessment)
	}
}

// TestValidate_ComplianceAssessmentGuard checks the validate.go guard fires only
// when populated and catches a bad status / mismatched total.
func TestValidate_ComplianceAssessmentGuard(t *testing.T) {
	base := func() *AuditReport {
		ar := &AuditReport{SchemaVersion: "v1"}
		ar.Summary = DeriveSummary(nil)
		return ar
	}

	// Nil assessment: no new errors.
	if err := base().Validate(); err != nil {
		t.Fatalf("nil assessment must validate clean, got: %v", err)
	}

	// Valid populated assessment.
	good := base()
	good.ComplianceAssessment = &ComplianceAssessment{
		Framework: "CIS-K8s",
		// A PASS control must cite the evidence rule that checked it (the
		// "never PASS an unchecked control" invariant enforced in validate.go).
		Controls: []ComplianceControl{{Control: "5.3.2", Status: ControlStatusPass, Profile: ProfileLevel2, EvidenceRuleIDs: []string{"k8s.namespace.no-network-policy"}}},
		Score:    ComplianceScore{Total: 1, Passed: 1, Scored: 1, PassRate: 1},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid assessment must pass, got: %v", err)
	}

	// Bad status.
	badStatus := base()
	badStatus.ComplianceAssessment = &ComplianceAssessment{
		Controls: []ComplianceControl{{Control: "5.3.2", Status: "bogus"}},
		Score:    ComplianceScore{Total: 1},
	}
	if err := badStatus.Validate(); err == nil {
		t.Error("invalid control status must fail validation")
	}

	// Total mismatch.
	badTotal := base()
	badTotal.ComplianceAssessment = &ComplianceAssessment{
		Controls: []ComplianceControl{{Control: "5.3.2", Status: ControlStatusManual}},
		Score:    ComplianceScore{Total: 5},
	}
	if err := badTotal.Validate(); err == nil {
		t.Error("score.total != len(controls) must fail validation")
	}
}
