package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// mkReport builds a minimal schema-valid AuditReport for the named cluster with
// the given findings. Summary is derived so the report is self-consistent.
func mkReport(cluster string, findings ...types.Finding) *types.AuditReport {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   time.Now().UTC(),
		Cluster:       types.ClusterInfo{Name: cluster},
		Findings:      findings,
		Methodology:   types.Methodology{CollectorsRun: []string{"kubernetes"}},
	}
	ar.Summary = types.DeriveSummary(findings)
	return ar
}

// mkFinding builds a finding with a stable ID and a dollar impact.
func mkFinding(id string, sev types.Severity, dollars float64) types.Finding {
	return types.Finding{
		ID: id, RuleID: "k8s.test.rule", RuleVersion: "1.0.0",
		Title: "t " + id, Description: "d", WhyItMatters: "w", Evidence: []string{"e"},
		Severity: sev, Category: types.CategoryCost,
		AffectedResources:   []types.ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: id}},
		DollarImpactMonthly: dollars, EstimatedEffort: types.EffortLow,
		RemediationCommand: "kubectl get pods", Confidence: 0.9,
		Provenance: types.Provenance{Collector: "kubernetes", Version: "v0"},
	}
}

// TestStore_SaveListLatestRoundTrip exercises the full lifecycle: Save several
// snapshots, List them newest-first, and Latest-before-time picks the right one.
func TestStore_SaveListLatestRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}

	t1 := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 5, 9, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)

	r1 := mkReport("prod-eu", mkFinding("f-a", types.SeverityHigh, 100))
	r2 := mkReport("prod-eu", mkFinding("f-a", types.SeverityHigh, 100), mkFinding("f-b", types.SeverityMedium, 50))
	r3 := mkReport("prod-eu", mkFinding("f-b", types.SeverityMedium, 50))

	for _, tc := range []struct {
		ar *types.AuditReport
		at time.Time
	}{{r1, t1}, {r2, t2}, {r3, t3}} {
		p, err := s.Save(tc.ar, tc.at)
		if err != nil {
			t.Fatalf("save: %v", err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("saved file missing: %v", err)
		}
	}

	snaps, err := s.List("prod-eu")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("want 3 snapshots, got %d", len(snaps))
	}
	// newest-first
	if !snaps[0].At.Equal(t3) || !snaps[1].At.Equal(t2) || !snaps[2].At.Equal(t1) {
		t.Fatalf("snapshots not newest-first: %v %v %v", snaps[0].At, snaps[1].At, snaps[2].At)
	}
	if snaps[0].Cluster != "prod-eu" {
		t.Errorf("snapshot cluster = %q, want prod-eu", snaps[0].Cluster)
	}

	// Latest strictly before t3 must be the t2 snapshot (2 findings).
	prev, at, ok, err := s.LatestOf("prod-eu", "", t3)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if !ok {
		t.Fatal("expected a snapshot before t3")
	}
	if !at.Equal(t2) {
		t.Fatalf("latest-before-t3 at = %v, want %v", at, t2)
	}
	if len(prev.Findings) != 2 {
		t.Fatalf("loaded prev has %d findings, want 2", len(prev.Findings))
	}

	// Latest strictly before t1 (the earliest) must be absent — "before" is exclusive.
	if _, _, ok, err := s.LatestOf("prod-eu", "", t1); err != nil || ok {
		t.Fatalf("expected no snapshot strictly before earliest; ok=%v err=%v", ok, err)
	}

	// "before" is exclusive: asking before t2 returns t1, not t2 itself.
	_, at, ok, err = s.LatestOf("prod-eu", "", t2)
	if err != nil || !ok || !at.Equal(t1) {
		t.Fatalf("latest-before-t2 should be t1 (exclusive): ok=%v at=%v err=%v", ok, at, err)
	}
}

// TestStore_ListEmptyClusterNoError proves a cluster with no history yet returns
// an empty slice and no error (missing directory handled gracefully).
func TestStore_ListEmptyClusterNoError(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	snaps, err := s.List("never-audited")
	if err != nil {
		t.Fatalf("list of empty cluster must not error: %v", err)
	}
	if len(snaps) != 0 {
		t.Fatalf("want 0 snapshots, got %d", len(snaps))
	}
	// Latest on an empty cluster is ok=false, no error.
	if _, _, ok, err := s.LatestOf("never-audited", "", time.Now()); err != nil || ok {
		t.Fatalf("latest on empty cluster: ok=%v err=%v", ok, err)
	}
}

// TestStore_SlugSeparatesClusters proves names that differ only by punctuation/
// case map to filesystem-safe slugs and that distinct names don't collide.
func TestStore_SlugSeparatesClusters(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	at := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)

	// A name with spaces, slashes, and mixed case must produce a safe single
	// path segment and save without error.
	p, err := s.Save(mkReport("Acme Pay / EKS:prod"), at)
	if err != nil {
		t.Fatalf("save slugged name: %v", err)
	}
	if filepath.Base(filepath.Dir(p)) != "acme-pay-eks-prod" {
		t.Fatalf("slug = %q, want acme-pay-eks-prod", filepath.Base(filepath.Dir(p)))
	}
	// List must round-trip via the same slug (caller passes the original name).
	snaps, err := s.List("Acme Pay / EKS:prod")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("slugged list: n=%d err=%v", len(snaps), err)
	}

	// A different cluster must land in its own directory.
	if _, err := s.Save(mkReport("staging"), at); err != nil {
		t.Fatalf("save second cluster: %v", err)
	}
	if other, _ := s.List("staging"); len(other) != 1 {
		t.Fatalf("staging should have exactly 1 snapshot, got %d", len(other))
	}
	// The first cluster still has exactly one (no collision).
	if again, _ := s.List("Acme Pay / EKS:prod"); len(again) != 1 {
		t.Fatalf("cluster collision: acme has %d snapshots", len(again))
	}
}

// TestSlug covers the slug helper's edge cases directly.
func TestSlug(t *testing.T) {
	cases := map[string]string{
		"prod-eu":             "prod-eu",
		"Acme Pay":            "acme-pay",
		"EKS:prod/eu-central": "eks-prod-eu-central",
		"  weird  ":           "weird",
		"!!!":                 "cluster",
		"":                    "cluster",
		"UPPER_snake":         "upper-snake",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSave_UserOnlyPerms(t *testing.T) {
	st := &Store{Dir: t.TempDir() + "/h"}
	ar := mkReport("prod", mkFinding("f-1", types.SeverityHigh, 0))
	path, err := st.Save(ar, time.Now())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot file mode = %o, want 0600 (contains cluster internals)", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("snapshot dir mode = %o, want 0700", di.Mode().Perm())
	}
}

func TestList_ReadsTheLabelFromTheSnapshotHead(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	ar := mkReport("c")
	ar.Methodology.Label = "before upgrade to 1.32"
	if _, err := s.Save(ar, time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	snaps, err := s.List("c")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("list: %v (%d)", err, len(snaps))
	}
	if snaps[0].Label != "before upgrade to 1.32" {
		t.Errorf("Label = %q", snaps[0].Label)
	}
}
