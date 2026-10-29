package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// AN ANALYZER'S FINDING IS COMPARED UNDER THE ID ITS BUILD STAMPED.
//
// The rule set a reading records names an analyzer by ITS id — stack.argocd.sync — and the analyzer files its
// findings under others: stack.argocd.outofsync, stack.argocd.degraded. Gate 1 looked the finding's own id up in
// the other reading's rule set, found nothing, and held every one-sided analyzer finding back as "rule
// stack.argocd.outofsync was not part of the … reading's build" — between two readings by the SAME build. An
// Argo application that went out of sync was never "new", one that was repaired never "no longer in the set",
// and `gate --fail-on new:high` could not fire on a degraded application at all.
func TestCompare_AnAnalyzerFindingIsComparedUnderItsStampedProducer(t *testing.T) {
	kinds := []string{"cr:applications.argoproj.io", "nodes", "pods"}
	reading := func(at time.Time, findings []types.Finding, stamp []types.RuleStamp, collected []string) *types.AuditReport {
		ar := &types.AuditReport{SchemaVersion: "v1", GeneratedAt: at, Cluster: types.ClusterInfo{Name: "prod"},
			Findings: findings,
			Methodology: types.Methodology{CollectedKinds: collected, RunBasis: &types.RunBasis{
				ClusterUID: "uid-1", EngineVersion: "0.22.0", RuleSet: stamp}}}
		ar.Summary = types.DeriveSummary(findings)
		return ar
	}
	degraded := types.Finding{ID: "f-aaaaaaaaaaaa", RuleID: "stack.argocd.degraded", RuleVersion: "1.0.0",
		Title: "Argo Application shop/payments is Degraded", Severity: types.SeverityHigh, Category: types.CategoryReliability,
		AffectedResources: []types.ResourceRef{{Kind: "Application", Namespace: "argocd", Name: "payments"}}}
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	stamp := RuleSetStamp()

	// The same build, both readings read the Applications: the finding is NEW.
	d := history.Compute(reading(t0, nil, stamp, kinds), reading(t0.Add(time.Hour), []types.Finding{degraded}, stamp, kinds), HistoryDeps())
	if !d.Comparable.OK {
		t.Fatalf("the pair is not comparable: %s", d.Comparable.Reason)
	}
	if len(d.NewInSet) != 1 {
		var why []string
		for _, u := range d.NotEvaluated {
			why = append(why, u.Reason)
		}
		t.Fatalf("a degraded application that appeared between two readings by one build is not new: %d new, held back because %v",
			len(d.NewInSet), why)
	}
	// And repaired: NO LONGER IN THE SET.
	d = history.Compute(reading(t0, []types.Finding{degraded}, stamp, kinds), reading(t0.Add(time.Hour), nil, stamp, kinds), HistoryDeps())
	if len(d.NoLongerInSet) != 1 {
		t.Errorf("a repaired application is not reported as gone (%d no longer, %d not evaluated)", len(d.NoLongerInSet), len(d.NotEvaluated))
	}

	// The earlier reading could not read Applications: held back, and the reason is the unread kind.
	d = history.Compute(reading(t0, nil, stamp, []string{"nodes", "pods"}), reading(t0.Add(time.Hour), []types.Finding{degraded}, stamp, kinds), HistoryDeps())
	if len(d.NewInSet) != 0 || len(d.NotEvaluated) != 1 || !strings.Contains(d.NotEvaluated[0].Reason, "applications.argoproj.io") {
		t.Errorf("an analyzer that could not read its input in the earlier reading: %d new, %+v", len(d.NewInSet), d.NotEvaluated)
	}

	// The analyzer changed version between the builds: held back, and the reason names the version.
	older := append([]types.RuleStamp(nil), stamp...)
	for i := range older {
		if older[i].ID == "stack.argocd.sync" {
			older[i].Version = "0.9.0"
		}
	}
	prev := reading(t0, nil, older, kinds)
	prev.Methodology.RunBasis.EngineVersion = "0.21.0"
	d = history.Compute(prev, reading(t0.Add(time.Hour), []types.Finding{degraded}, stamp, kinds), HistoryDeps())
	if len(d.NewInSet) != 0 || len(d.NotEvaluated) != 1 || !strings.Contains(d.NotEvaluated[0].Reason, "0.9.0") {
		t.Errorf("a re-versioned analyzer's finding was not held back on its version: %d new, %+v", len(d.NewInSet), d.NotEvaluated)
	}
}
