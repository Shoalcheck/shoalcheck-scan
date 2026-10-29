package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// §6.1 — ENUMERATION READS THE SNAPSHOT, NOT THE DIRECTORY NAME.
//
// A cluster's directory is its slug, and `cmd/shoalcheck/history.go` listed clusters by passing that directory
// name back into List() — so the display name a reader saw was `acme-pay-eks-prod`, not `Acme Pay / EKS:prod`.
// The slug is lossy on purpose (it has to be a filename); recovering a name from it is not possible, so the
// name has to come from inside the newest snapshot.
//
// ClusterUID matters more than the name. It is the kube-system namespace UID and the only stable cluster
// identity a read-only snapshot has: a slug collides — `Acme Pay / EKS:prod` and `acme-pay-eks-prod` share a
// directory — and a kubeconfig context can be renamed or reused for a rebuilt cluster. Grouping timelines by
// anything else eventually compares two clusters and calls the difference a change.
func TestStoreClusters_ReadsTheNameAndUIDFromTheNewestSnapshot(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	older := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)

	// Same cluster, two readings. The newer one is where the name and UID must come from.
	save(t, s, report("Acme Pay / EKS:prod", "uid-acme", 4), older)
	save(t, s, report("Acme Pay / EKS:prod", "uid-acme", 7), newer)
	save(t, s, report("dr-aks", "uid-dr", 1), newer)

	got, err := s.Clusters()
	if err != nil {
		t.Fatalf("Clusters: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 clusters, got %d: %+v", len(got), got)
	}
	byUID := map[string]ClusterRef{}
	for _, c := range got {
		byUID[c.ClusterUID] = c
	}
	acme, ok := byUID["uid-acme"]
	if !ok {
		t.Fatalf("no cluster carries uid-acme; got %+v", got)
	}
	if acme.Name != "Acme Pay / EKS:prod" {
		t.Errorf("Name = %q, want the display name out of the snapshot — a slug is not a name", acme.Name)
	}
	if strings.Contains(acme.Name, "-eks-") {
		t.Errorf("Name = %q, which is the directory slug: the name was recovered from the filename rather "+
			"than read from the snapshot", acme.Name)
	}
	if acme.Runs != 2 {
		t.Errorf("Runs = %d, want 2", acme.Runs)
	}
	if !acme.Newest.Equal(newer) {
		t.Errorf("Newest = %v, want %v", acme.Newest, newer)
	}
	// The listing must not have to parse every finding to answer this.
	if acme.LatestFindings != 7 {
		t.Errorf("LatestFindings = %d, want 7 (from the newest snapshot's summary)", acme.LatestFindings)
	}
}

// A cluster with no ClusterUID is listed and MARKED, because Gate 0 will refuse to compare it and learning
// that after choosing two runs is worse than being told first (§4.1 item 6).
func TestStoreClusters_MarksAClusterWithNoStableIdentity(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	save(t, s, report("legacy", "", 3), time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC))
	got, err := s.Clusters()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 cluster, got %d", len(got))
	}
	if got[0].ClusterUID != "" {
		t.Fatalf("this fixture has no UID, so this test is not measuring what it says")
	}
	if got[0].Comparable {
		t.Error("a run with no ClusterUID was listed as comparable; Gate 0 refuses it (diff.go:242), so the " +
			"browser must say so before the operator picks a pair, not after")
	}
	if got[0].NotComparableReason == "" {
		t.Error("the row is marked not comparable and gives no reason — a refusal without its reason is the " +
			"thing this project refuses everywhere else")
	}
}

// §6.1 — Load VALIDATES. Snapshots are trusted on read today because they were validated when written,
// which stops being true the moment a snapshot outlives the schema that wrote it. A snapshot that fails
// validation must be listable and refusable, never rendered.
func TestStoreLoad_ValidatesAndRefusesAnInconsistentSnapshot(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	at := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	path := save(t, s, report("prod", "uid-prod", 2), at)

	if _, err := s.Load(path); err != nil {
		t.Fatalf("a valid snapshot must load: %v", err)
	}

	// Corrupt the summary so the report contradicts itself: 2 findings, a headline claiming 9.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"totalFindings": 2`, `"totalFindings": 9`, 1)
	if bad == string(raw) {
		t.Fatal("the fixture's summary shape changed, so this test would corrupt nothing")
	}
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.Load(path)
	if err == nil {
		t.Error("a snapshot whose summary contradicts its findings loaded without complaint — it would be " +
			"rendered as a report whose headline does not match what is under it")
	} else if !strings.Contains(err.Error(), "summary") {
		t.Errorf("the error does not name what is wrong: %v", err)
	}
}

func report(cluster, uid string, findings int) *types.AuditReport {
	fs := make([]types.Finding, 0, findings)
	for i := 0; i < findings; i++ {
		fs = append(fs, types.Finding{
			ID: "f-" + string(rune('a'+i)) + "00000000000", RuleID: "k8s.test.rule", RuleVersion: "1.0.0",
			Title: "t", Severity: types.SeverityLow, Category: types.CategoryConfig,
			EstimatedEffort: types.EffortLow, Confidence: 0.9,
		})
	}
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC),
		Cluster:       types.ClusterInfo{Name: cluster},
		Findings:      fs,
		Methodology:   types.Methodology{RunBasis: &types.RunBasis{ClusterUID: uid, EngineVersion: "0.2.0"}},
	}
	ar.Summary = types.DeriveSummary(ar.Findings)
	return ar
}

func save(t *testing.T, s *Store, ar *types.AuditReport, at time.Time) string {
	t.Helper()
	p, err := s.Save(ar, at)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if filepath.Ext(p) != ".json" {
		t.Fatalf("Save returned %q", p)
	}
	return p
}

// §8 test 10 — TWO CLUSTER UIDs IN ONE DIRECTORY ARE NOT ONE TIMELINE.
//
// A slug is lossy by construction, so two distinct clusters can share a directory: `Acme Pay / EKS:prod` and
// `acme-pay-eks-prod` slug identically, and so does a context reused for a rebuilt cluster. A listing that
// reads the UID off the newest snapshot alone reports them as one cluster with N runs — a false statement
// about the timeline, even though Gate 0 would refuse to compare across them.
//
// The refusal has to be on the ROW, before the operator picks a pair, for the same reason §4.1 item 6 marks
// an empty ClusterUID early: learning it after choosing two runs is work done for nothing.
func TestStoreClusters_TwoClusterUIDsInOneSlugAreNotOneTimeline(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	// Same display name, so the same directory — and two genuinely different clusters.
	save(t, s, report("prod", "uid-first", 3), time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC))
	save(t, s, report("prod", "uid-second", 4), time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC))

	got, err := s.Clusters()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the two readings share a directory, so there is one timeline row; got %d", len(got))
	}
	c := got[0]
	if c.Runs != 2 {
		t.Fatalf("want 2 runs in the row, got %d — this test is not measuring the collision", c.Runs)
	}
	if c.Comparable {
		t.Error("a directory holding two different ClusterUIDs was reported as comparable; Gate 0 refuses " +
			"across them (diff.go:246), so the row must say so before the operator picks a pair")
	}
	if !strings.Contains(strings.ToLower(c.NotComparableReason), "cluster") {
		t.Errorf("the reason does not say the directory holds more than one cluster: %q", c.NotComparableReason)
	}
	// And the count of distinct clusters must be visible, or "not comparable" is unexplainable.
	if c.DistinctUIDs < 2 {
		t.Errorf("DistinctUIDs = %d, want at least 2 — the row cannot explain its own refusal without it",
			c.DistinctUIDs)
	}
}
