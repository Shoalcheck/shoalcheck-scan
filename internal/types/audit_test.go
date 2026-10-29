package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSampleAuditFixtureRoundTrip is the schema/fixture contract test.
//
// It loads testdata/golden/sample-audit.json and asserts:
//   - the JSON parses into AuditReport without error,
//   - every finding populates required fields and uses valid enums,
//   - Summary counts (BySeverity, ByCategory) match the actual Findings,
//   - Summary.EstimatedSavingsUSD equals sum of per-finding DollarImpactMonthly.
//
// This is the foundation the Day 6 structural HTML test builds on. If this
// test breaks, the fixture and schema are out of sync — fix one or the other
// before any rendering work.
func TestSampleAuditFixtureRoundTrip(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "golden", "sample-audit.json")

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}

	var report AuditReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if report.SchemaVersion != "v1" {
		t.Errorf("SchemaVersion = %q, want %q (v1 is a forever commitment)", report.SchemaVersion, "v1")
	}

	if len(report.Findings) == 0 {
		t.Fatal("Findings is empty — fixture must contain at least one finding")
	}

	// Summary consistency (counts, savings, highest priority) and enum/confidence
	// validity are the load-path contract — delegate to the same Validate() the
	// binary runs, so this test can't drift from production behavior.
	if err := report.Validate(); err != nil {
		t.Errorf("fixture fails Validate(): %v", err)
	}

	for i, f := range report.Findings {
		ref := f.ID
		if ref == "" {
			ref = "<missing id>"
		}
		if f.ID == "" {
			t.Errorf("Findings[%d]: missing ID", i)
		}
		if f.RuleID == "" {
			t.Errorf("Findings[%d] %s: missing RuleID", i, ref)
		}
		if f.RuleVersion == "" {
			t.Errorf("Findings[%d] %s: missing RuleVersion", i, ref)
		}
		if f.Title == "" {
			t.Errorf("Findings[%d] %s: missing Title", i, ref)
		}
		if f.Description == "" {
			t.Errorf("Findings[%d] %s: missing Description", i, ref)
		}
		if f.WhyItMatters == "" {
			t.Errorf("Findings[%d] %s: missing WhyItMatters", i, ref)
		}
		if !f.Severity.Valid() {
			t.Errorf("Findings[%d] %s: invalid Severity %q", i, ref, f.Severity)
		}
		if !f.Category.Valid() {
			t.Errorf("Findings[%d] %s: invalid Category %q", i, ref, f.Category)
		}
		if !f.EstimatedEffort.Valid() {
			t.Errorf("Findings[%d] %s: invalid EstimatedEffort %q", i, ref, f.EstimatedEffort)
		}
		if f.Confidence < 0 || f.Confidence > 1 {
			t.Errorf("Findings[%d] %s: Confidence %f out of [0,1]", i, ref, f.Confidence)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("Findings[%d] %s: no Evidence — this is the credibility-defining field, never empty", i, ref)
		}
		// A finding that rests on telemetry and no object — alerts firing, scrape targets down — names its series
		// in the evidence, and its basis says so; every other finding names the objects it rests on.
		telemetryOnly := f.Basis != nil && len(f.Basis.Kinds) == 0 && f.Basis.UsageRequired && f.Basis.UsageSource != ""
		if len(f.AffectedResources) == 0 && !telemetryOnly {
			t.Errorf("Findings[%d] %s: no AffectedResources", i, ref)
		}
		// A FINDING MAY HAVE NO MECHANICAL FIX, and requiring one was the wrong invariant.
		//
		// It went unnoticed while the fixture was hand-authored — every hand-written finding carried a
		// remediation because whoever wrote it supplied one. Generated from the real pipeline, 29
		// findings from 7 shipped rules carry none, and they are right to: "Drain of ip-10-0-1-b:
		// budget payments/payments-orchestrator-pdb is at zero right now" is an OBSERVATION. There is
		// no manifest for it. Inventing one to satisfy a test would be the worst kind of compliance.
		//
		// What must hold instead is that such a finding still tells the reader what it means and is
		// never offered as something to apply — which the safety classifier already decides. So the
		// requirement is prose, not YAML.
		if f.RemediationYAML == "" && f.RemediationCommand == "" {
			if strings.TrimSpace(f.WhyItMatters) == "" && strings.TrimSpace(f.Description) == "" {
				t.Errorf("Findings[%d] %s: no remediation AND no explanation — a finding with neither is a "+
					"line item, not information", i, ref)
			}
		}
		if f.Provenance.Collector == "" {
			t.Errorf("Findings[%d] %s: missing Provenance.Collector", i, ref)
		}
		if f.Provenance.Version == "" {
			t.Errorf("Findings[%d] %s: missing Provenance.Version", i, ref)
		}
	}

	if report.Cluster.Name == "" {
		t.Error("Cluster.Name is empty — fixture should identify the cluster")
	}
	if report.Cluster.KubernetesVersion == "" {
		t.Error("Cluster.KubernetesVersion is empty")
	}
}
