package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validFinding(id string) Finding {
	return Finding{
		ID: id, RuleID: "k8s.test.rule", RuleVersion: "1.0.0",
		Title: "t", Description: "d", WhyItMatters: "w",
		Evidence: []string{"e"}, Severity: SeverityHigh, Category: CategoryCost,
		AffectedResources:   []ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: "x"}},
		DollarImpactMonthly: 100, EstimatedEffort: EffortLow,
		RemediationCommand: "kubectl get pods", Confidence: 0.9,
		Provenance: Provenance{Collector: "kubernetes", Version: "v0"},
	}
}

func validReport() *AuditReport {
	f := validFinding("f-001")
	ar := &AuditReport{
		SchemaVersion: "v1", GeneratedAt: time.Now(),
		Cluster:     ClusterInfo{Name: "c", KubernetesVersion: "1.30", Provider: "kind"},
		Findings:    []Finding{f},
		Methodology: Methodology{CollectorsRun: []string{"kubernetes"}, DataSources: []string{"api"}},
	}
	ar.Summary = DeriveSummary(ar.Findings)
	return ar
}

func TestValidate_OK(t *testing.T) {
	if err := validReport().Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
}

func TestValidate_RejectsBadEnum(t *testing.T) {
	ar := validReport()
	ar.Findings[0].Severity = "catastrophic"
	ar.Summary = DeriveSummary(ar.Findings) // keep summary consistent so enum is the failure
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("want severity enum error, got %v", err)
	}
}

func TestValidate_RejectsLyingSummary(t *testing.T) {
	ar := validReport()
	ar.Summary.TotalFindings = 999
	ar.Summary.EstimatedSavingsUSD = 1234567
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "summary") {
		t.Fatalf("want summary consistency error, got %v", err)
	}
}

func TestValidate_RejectsBadConfidence(t *testing.T) {
	ar := validReport()
	ar.Findings[0].Confidence = 1.5
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("want confidence error, got %v", err)
	}
}

func TestValidate_EmptyFindingsIsValid(t *testing.T) {
	ar := validReport()
	ar.Findings = nil
	ar.Summary = DeriveSummary(nil)
	if err := ar.Validate(); err != nil {
		t.Fatalf("empty findings must be valid (clean cluster): %v", err)
	}
}

func TestDeriveSummary(t *testing.T) {
	f1 := validFinding("f-1") // high/cost/$100
	f2 := validFinding("f-2")
	f2.Severity, f2.Category, f2.DollarImpactMonthly = SeverityCritical, CategorySecurity, 0
	s := DeriveSummary([]Finding{f1, f2})
	if s.TotalFindings != 2 || s.BySeverity[SeverityCritical] != 1 ||
		s.ByCategory[CategoryCost] != 1 || s.EstimatedSavingsUSD != 100 {
		t.Fatalf("bad summary: %+v", s)
	}
	if s.HighestPriorityID != "f-2" { // critical beats high
		t.Fatalf("highest priority = %q, want f-2", s.HighestPriorityID)
	}
}

func TestValidate_RejectsInflatedSeverityKey(t *testing.T) {
	ar := validReport()                         // one high finding
	ar.Summary.BySeverity[SeverityCritical] = 5 // no critical findings exist
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "bySeverity[critical]=5, derived 0") {
		t.Fatalf("want inflated-severity-key error, got %v", err)
	}
}

func TestValidate_RejectsDuplicateID(t *testing.T) {
	ar := validReport()
	ar.Findings = append(ar.Findings, ar.Findings[0]) // same ID twice
	ar.Summary = DeriveSummary(ar.Findings)
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate id error, got %v", err)
	}
}

func TestValidate_RejectsWrongHighestPriority(t *testing.T) {
	f2 := validFinding("f-low")
	f2.Severity = SeverityLow
	ar := validReport() // f-001, high
	ar.Findings = append(ar.Findings, f2)
	ar.Summary = DeriveSummary(ar.Findings)
	ar.Summary.HighestPriorityID = "f-low" // claim the low finding is top priority
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "highestPriorityId") {
		t.Fatalf("want wrong-highest-priority error, got %v", err)
	}
}

func TestValidate_RejectsDollarWithoutEvidence(t *testing.T) {
	// The node-headroom class, structural: a confident $-finding with no Evidence
	// must not validate, no matter which rule (or hand edit) produced it.
	ar := validReport()
	ar.Findings[0].DollarImpactMonthly = 1121
	ar.Findings[0].Evidence = nil
	ar.Summary = DeriveSummary(ar.Findings) // keep summary honest so evidence is the failure
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "no evidence") {
		t.Fatalf("want dollar-without-evidence error, got %v", err)
	}
}

func TestValidate_AllowsZeroDollarWithoutEvidence(t *testing.T) {
	// A $0 finding (no cost claim) is not subject to the dollar-evidence guard.
	// Evidence is still good practice, but only a BILLED dollar mandates it here.
	ar := validReport()
	ar.Findings[0].DollarImpactMonthly = 0
	ar.Findings[0].Evidence = nil
	ar.Summary = DeriveSummary(ar.Findings)
	if err := ar.Validate(); err != nil {
		t.Fatalf("zero-dollar finding with no evidence must validate: %v", err)
	}
}

func TestValidate_RejectsNegativeDollar(t *testing.T) {
	ar := validReport()
	ar.Findings[0].DollarImpactMonthly = -50
	ar.Summary = DeriveSummary(ar.Findings) // summary sum stays consistent with the negative
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("want negative-dollar error, got %v", err)
	}
}

func TestValidate_RejectsPassWithoutEvidenceRule(t *testing.T) {
	// "Never PASS an unchecked control" — a PASS with no evidenceRuleIds is a
	// machine-unchecked control claimed as passing. Reject it at the schema gate.
	ar := validReport()
	ar.ComplianceAssessment = &ComplianceAssessment{
		Framework: "CIS-K8s",
		Controls:  []ComplianceControl{{Control: "5.3.2", Status: ControlStatusPass}},
		Score:     ComplianceScore{Total: 1, Passed: 1, Scored: 1, PassRate: 1},
	}
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "never PASS an unchecked control") {
		t.Fatalf("want PASS-without-evidence error, got %v", err)
	}
}

func TestValidate_RejectsLyingComplianceScore(t *testing.T) {
	// PassRate:1.0 / Passed:2 / Scored:2 claimed while both controls actually FAIL.
	// A compliance score must be re-derivable from its controls, like Summary.
	ar := validReport()
	ar.ComplianceAssessment = &ComplianceAssessment{
		Framework: "CIS-K8s",
		Controls: []ComplianceControl{
			{Control: "5.1.1", Status: ControlStatusFail, EvidenceRuleIDs: []string{"r1"}, FindingIDs: []string{"x"}},
			{Control: "5.1.2", Status: ControlStatusFail, EvidenceRuleIDs: []string{"r2"}, FindingIDs: []string{"y"}},
		},
		Score: ComplianceScore{Total: 2, Passed: 2, Scored: 2, PassRate: 1},
	}
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "score inconsistent") {
		t.Fatalf("want lying-compliance-score error, got %v", err)
	}
}

func TestValidate_AcceptsHonestComplianceScore(t *testing.T) {
	// A correctly-derived score over a mix of statuses must validate. MANUAL/NA
	// are excluded from Scored, so PassRate = 1/(1+1) = 0.5.
	ar := validReport()
	controls := []ComplianceControl{
		{Control: "5.1.1", Status: ControlStatusPass, EvidenceRuleIDs: []string{"r1"}},
		{Control: "5.1.2", Status: ControlStatusFail, EvidenceRuleIDs: []string{"r2"}, FindingIDs: []string{"y"}},
		{Control: "5.2.1", Status: ControlStatusManual, Rationale: "assess manually"},
		{Control: "1.1.1", Status: ControlStatusNA, Rationale: "out of scope"},
	}
	ar.ComplianceAssessment = &ComplianceAssessment{
		Framework: "CIS-K8s",
		Controls:  controls,
		Score:     DeriveComplianceScore(controls),
	}
	if err := ar.Validate(); err != nil {
		t.Fatalf("honest compliance score must validate: %v", err)
	}
	if got := ar.ComplianceAssessment.Score.PassRate; got != 0.5 {
		t.Fatalf("passRate = %v, want 0.5 (1 pass / 2 scored)", got)
	}
}

func TestDeriveComplianceScore(t *testing.T) {
	controls := []ComplianceControl{
		{Control: "a", Status: ControlStatusPass, EvidenceRuleIDs: []string{"r"}},
		{Control: "b", Status: ControlStatusPass, EvidenceRuleIDs: []string{"r"}},
		{Control: "c", Status: ControlStatusFail, EvidenceRuleIDs: []string{"r"}},
		{Control: "d", Status: ControlStatusManual},
		{Control: "e", Status: ControlStatusNA},
	}
	s := DeriveComplianceScore(controls)
	if s.Total != 5 || s.Passed != 2 || s.Failed != 1 || s.Manual != 1 || s.NA != 1 {
		t.Fatalf("bad sub-counts: %+v", s)
	}
	if s.Scored != 3 { // passed + failed, NOT manual/na
		t.Fatalf("scored = %d, want 3", s.Scored)
	}
	if s.PassRate != float64(2)/float64(3) {
		t.Fatalf("passRate = %v, want 2/3", s.PassRate)
	}
}

func TestSortByPriority(t *testing.T) {
	a := validFinding("a") // high, $100
	b := validFinding("b")
	b.Severity, b.DollarImpactMonthly = SeverityCritical, 0
	c := validFinding("c")
	c.DollarImpactMonthly = 900 // high, $900
	fs := []Finding{a, b, c}
	SortByPriority(fs)
	if fs[0].ID != "b" || fs[1].ID != "c" || fs[2].ID != "a" {
		t.Fatalf("order = %s,%s,%s; want b,c,a", fs[0].ID, fs[1].ID, fs[2].ID)
	}
}

func TestTierConstants(t *testing.T) {
	cases := []struct {
		tier Tier
		want string
	}{
		{TierObserved, "observed"},
		{TierPartial, "partial"},
		{TierDeclared, "declared"},
	}
	for _, c := range cases {
		if string(c.tier) != c.want {
			t.Errorf("Tier %v = %q, want %q", c.tier, string(c.tier), c.want)
		}
	}
}

func TestObservedEdgeJSON(t *testing.T) {
	e := ObservedEdge{
		From: "Deployment/web", To: "Deployment/api", Protocol: "http",
		RequestsPerSec: 12.5, ErrorRatePct: 5.0, P99Ms: 120,
		MTLS: "strict", Source: "istio", Window: "5m", Confidence: "high",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// omitempty fields left zero must NOT appear; required fields must.
	s := string(b)
	for _, want := range []string{`"from":"Deployment/web"`, `"requestsPerSec":12.5`, `"mtls":"strict"`} {
		if !strings.Contains(s, want) {
			t.Errorf("ObservedEdge JSON missing %s; got %s", want, s)
		}
	}
	if strings.Contains(s, `"p50Ms"`) {
		t.Errorf("zero P50Ms must be omitted; got %s", s)
	}
}

func TestArchitectureObservedFieldsOmitEmpty(t *testing.T) {
	a := Architecture{} // all observed fields zero
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, omit := range []string{"tier", "observedEdges", "observedSource", "observedWindow", "observedAsOf", "observedNote"} {
		if strings.Contains(s, `"`+omit+`"`) {
			t.Errorf("zero %q must be omitted (v1-additive); got %s", omit, s)
		}
	}
	a2 := Architecture{Tier: TierObserved, ObservedSource: "istio", ObservedEdges: []ObservedEdge{{From: "a", To: "b"}}}
	b2, _ := json.Marshal(a2)
	if !strings.Contains(string(b2), `"tier":"observed"`) {
		t.Errorf("set Tier must serialize; got %s", b2)
	}
}
