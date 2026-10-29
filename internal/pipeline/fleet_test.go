package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// syntheticReport builds a schema-valid AuditReport for the given cluster name
// and finding count, cluster-free. It exists so the fleet-aggregation contract
// (assembleFleet) can be tested without standing up real clusters; RunFleet's
// only cluster dependency is collect.New, which assembleFleet does not touch.
func syntheticReport(t *testing.T, name string, findings int) *types.AuditReport {
	t.Helper()
	var fs []types.Finding
	for i := 0; i < findings; i++ {
		fs = append(fs, types.Finding{
			ID:                  name + "-" + string(rune('a'+i)),
			RuleID:              "k8s.test.rule",
			RuleVersion:         "1.0.0",
			Title:               "t",
			Description:         "d",
			WhyItMatters:        "w",
			Evidence:            []string{"e"},
			Severity:            types.SeverityHigh,
			Category:            types.CategoryCost,
			AffectedResources:   []types.ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: "x"}},
			DollarImpactMonthly: 100,
			EstimatedEffort:     types.EffortLow,
			RemediationCommand:  "kubectl get pods",
			Confidence:          0.9,
			Provenance:          types.Provenance{Collector: "kubernetes", Version: "v0"},
		})
	}
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   time.Now(),
		Cluster:       types.ClusterInfo{Name: name, KubernetesVersion: "1.30", Provider: "kind", EstimatedMonthlySpend: 1000},
		Findings:      fs,
		Methodology:   types.Methodology{CollectorsRun: []string{"kubernetes"}, DataSources: []string{"api"}},
	}
	ar.Summary = types.DeriveSummary(ar.Findings)
	if err := ar.Validate(); err != nil {
		t.Fatalf("synthetic report %q is not valid: %v", name, err)
	}
	return ar
}

// TestAssembleFleet_OK proves the aggregation tail stamps the envelope (v1 +
// GeneratedAt), keeps every cluster, and returns a validated fleet.
func TestAssembleFleet_OK(t *testing.T) {
	reports := []*types.AuditReport{
		syntheticReport(t, "prod-eu", 2),
		syntheticReport(t, "prod-us", 3),
	}
	fr, err := assembleFleet(reports, nil, false)
	if err != nil {
		t.Fatalf("assembleFleet: %v", err)
	}
	if fr.SchemaVersion != "v1" {
		t.Errorf("SchemaVersion = %q, want v1", fr.SchemaVersion)
	}
	if fr.GeneratedAt.IsZero() {
		t.Error("GeneratedAt must be stamped, got zero")
	}
	if len(fr.Clusters) != 2 {
		t.Fatalf("Clusters = %d, want 2", len(fr.Clusters))
	}
	if err := fr.Validate(); err != nil {
		t.Errorf("assembled fleet must be valid: %v", err)
	}
	sum := types.DeriveFleetSummary(fr)
	if sum.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d, want 5", sum.TotalFindings)
	}
}

// TestAssembleFleet_SkipsNil proves nil child reports are dropped (a defensive
// guard; RunFleet only ever appends non-nil reports, but the contract holds).
func TestAssembleFleet_SkipsNil(t *testing.T) {
	reports := []*types.AuditReport{
		syntheticReport(t, "a", 1),
		nil,
		syntheticReport(t, "b", 1),
	}
	fr, err := assembleFleet(reports, nil, false)
	if err != nil {
		t.Fatalf("assembleFleet: %v", err)
	}
	if len(fr.Clusters) != 2 {
		t.Errorf("nil report must be dropped; Clusters = %d, want 2", len(fr.Clusters))
	}
}

// TestAssembleFleet_EmptyErrors proves an all-nil / empty input fails validation
// rather than producing a misreporting empty fleet.
func TestAssembleFleet_EmptyErrors(t *testing.T) {
	if _, err := assembleFleet(nil, nil, false); err == nil {
		t.Fatal("empty fleet must error")
	}
	if _, err := assembleFleet([]*types.AuditReport{nil, nil}, nil, false); err == nil {
		t.Fatal("all-nil fleet must error")
	}
}

// TestAssembleFleet_DuplicateNameErrors proves the cluster-name uniqueness
// contract (the switcher key) is enforced via FleetReport.Validate.
func TestAssembleFleet_DuplicateNameErrors(t *testing.T) {
	_, err := assembleFleet([]*types.AuditReport{
		syntheticReport(t, "dup", 1),
		syntheticReport(t, "dup", 1),
	}, nil, false)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate cluster name must error, got %v", err)
	}
}

// TestRunFleet_NoContextsErrors proves the zero-context guard fires before any
// cluster work (the only path through RunFleet that needs no real cluster).
func TestRunFleet_NoContextsErrors(t *testing.T) {
	_, err := RunFleet(context.Background(), FleetOptions{})
	if err == nil || !strings.Contains(err.Error(), "--context") {
		t.Fatalf("no contexts must error mentioning --context, got %v", err)
	}
}
