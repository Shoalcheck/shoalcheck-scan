package types

import (
	"strings"
	"testing"
	"time"
)

func clusterReport(name string, savings, spend float64, crit, high int) *AuditReport {
	var findings []Finding
	add := func(n int, sev Severity) {
		for i := 0; i < n; i++ {
			f := validFinding(name + "-" + string(sev) + "-" + string(rune('a'+i)))
			f.Severity = sev
			f.DollarImpactMonthly = 0
			findings = append(findings, f)
		}
	}
	add(crit, SeverityCritical)
	add(high, SeverityHigh)
	if len(findings) > 0 && savings > 0 {
		findings[0].DollarImpactMonthly = savings
	}
	ar := &AuditReport{
		SchemaVersion: "v1", GeneratedAt: time.Now(),
		Cluster:     ClusterInfo{Name: name, Provider: "eks", KubernetesVersion: "1.30", EstimatedMonthlySpend: spend},
		Findings:    findings,
		Methodology: Methodology{CollectorsRun: []string{"kubernetes"}, DataSources: []string{"api"}},
	}
	ar.Summary = DeriveSummary(ar.Findings)
	return ar
}

func TestFleetValidate_OK(t *testing.T) {
	fr := &FleetReport{SchemaVersion: "v1", Clusters: []*AuditReport{
		clusterReport("prod", 100, 4000, 1, 2),
		clusterReport("staging", 0, 800, 0, 1),
	}}
	if err := fr.Validate(); err != nil {
		t.Fatalf("valid fleet rejected: %v", err)
	}
}

func TestFleetValidate_RejectsDuplicateNames(t *testing.T) {
	fr := &FleetReport{SchemaVersion: "v1", Clusters: []*AuditReport{
		clusterReport("prod", 0, 0, 0, 1),
		clusterReport("prod", 0, 0, 0, 1),
	}}
	if err := fr.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate cluster name") {
		t.Fatalf("want duplicate-name error, got %v", err)
	}
}

func TestFleetValidate_RejectsEmpty(t *testing.T) {
	fr := &FleetReport{SchemaVersion: "v1"}
	if err := fr.Validate(); err == nil || !strings.Contains(err.Error(), "no clusters") {
		t.Fatalf("want no-clusters error, got %v", err)
	}
}

func TestFleetValidate_PropagatesChildError(t *testing.T) {
	bad := clusterReport("prod", 0, 0, 0, 1)
	bad.Summary.TotalFindings = 999 // lie
	fr := &FleetReport{SchemaVersion: "v1", Clusters: []*AuditReport{bad}}
	if err := fr.Validate(); err == nil || !strings.Contains(err.Error(), "cluster \"prod\"") {
		t.Fatalf("want child error propagated with cluster name, got %v", err)
	}
}

func TestDeriveFleetSummary(t *testing.T) {
	fr := &FleetReport{SchemaVersion: "v1", Clusters: []*AuditReport{
		clusterReport("prod", 100, 4000, 1, 2),  // 3 findings, $100, $4000 spend
		clusterReport("staging", 50, 800, 0, 1), // 1 finding, $50, $800 spend
	}}
	s := DeriveFleetSummary(fr)
	if s.ClusterCount != 2 {
		t.Errorf("ClusterCount = %d, want 2", s.ClusterCount)
	}
	if s.TotalFindings != 4 {
		t.Errorf("TotalFindings = %d, want 4", s.TotalFindings)
	}
	if s.BySeverity[SeverityCritical] != 1 || s.BySeverity[SeverityHigh] != 3 {
		t.Errorf("bySeverity wrong: %+v", s.BySeverity)
	}
	if s.EstimatedSavingsUSD != 150 || s.EstimatedSpendUSD != 4800 {
		t.Errorf("totals wrong: savings %.0f spend %.0f", s.EstimatedSavingsUSD, s.EstimatedSpendUSD)
	}
}
