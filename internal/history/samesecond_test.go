package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// TWO READINGS IN ONE SECOND ARE TWO READINGS. A snapshot was named by its second and written with os.WriteFile, so
// a second reading of the same cluster in the same second — two windows, the window and the CLI, a schedule that
// fired twice — replaced the first without a word; measured on the desktop app, two starts 150 ms apart left one
// snapshot behind two ledger lines. The second one takes the next free name, "<stamp>-2.json", the listing reads
// both, and the newer is still first.
func TestStore_TwoReadingsInOneSecondAreBothKept(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	at := time.Date(2026, 10, 21, 0, 15, 35, 0, time.UTC)
	first, err := s.Save(mkReport("prod-eu", mkFinding("f-a", types.SeverityHigh, 10)), at)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Save(mkReport("prod-eu", mkFinding("f-b", types.SeverityHigh, 20)), at)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both readings were written to %s; the second replaced the first", first)
	}
	if filepath.Base(first) != "2026-10-21T00-15-35Z.json" {
		t.Errorf("the first reading of a second is named %s; the plain stamp is what every earlier reading carries", filepath.Base(first))
	}
	if filepath.Base(second) != "2026-10-21T00-15-35Z-2.json" {
		t.Errorf("the second reading of the second is named %s, want <stamp>-2.json", filepath.Base(second))
	}
	snaps, err := s.List("prod-eu")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].Path != second || snaps[1].Path != first {
		t.Fatalf("listed %+v; want both, the later-written first", snaps)
	}
	if !snaps[0].At.Equal(at) {
		t.Errorf("the suffixed name parsed to %s, want %s", snaps[0].At, at)
	}
	got, _, ok, err := s.LatestOf("prod-eu", "", at.Add(time.Second))
	if err != nil || !ok || len(got.Findings) != 1 || got.Findings[0].ID != "f-b" {
		t.Errorf("the latest reading is not the one written last: %v %v", got, err)
	}
	// A file that merely looks like a suffix is not a reading.
	if err := os.WriteFile(filepath.Join(filepath.Dir(first), "2026-10-21T00-15-35Z-x.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if snaps, _ := s.List("prod-eu"); len(snaps) != 2 {
		t.Errorf("a file named <stamp>-x.json was listed as a reading: %d", len(snaps))
	}
}

// A CLUSTER NAME LONGER THAN A FILE NAME IS STILL A CLUSTER. The history directory is the cluster's slug, and a
// kubeconfig context of 283 characters made a slug no filesystem accepts (255 bytes): the save failed, the reading
// was not kept, the comparison said "an earlier snapshot of this cluster could not be read" — and the licence was
// charged. A long slug is cut and keeps a short digest of the whole name, so two long names that share a beginning
// stay two clusters.
func TestStore_ALongClusterNameIsKept(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	long := "ctx-" + strings.Repeat("very-long-context-name-", 12) + "end"
	other := "ctx-" + strings.Repeat("very-long-context-name-", 12) + "other"
	at := time.Date(2026, 10, 21, 0, 21, 24, 0, time.UTC)
	if _, err := s.Save(mkReport(long), at); err != nil {
		t.Fatalf("a %d-character cluster name could not be kept: %v", len(long), err)
	}
	if _, err := s.Save(mkReport(other), at); err != nil {
		t.Fatal(err)
	}
	if n := len(Slug(long)); n > 120 {
		t.Errorf("the slug of a long name is %d characters", n)
	}
	if Slug(long) == Slug(other) {
		t.Error("two long names that share a beginning share a directory")
	}
	if snaps, err := s.List(long); err != nil || len(snaps) != 1 {
		t.Errorf("the long-named cluster lists %d reading(s): %v", len(snaps), err)
	}
	if Slug("prod-eu") != "prod-eu" {
		t.Errorf("a short name's slug changed: %q", Slug("prod-eu"))
	}
}
