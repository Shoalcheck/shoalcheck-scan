package history

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A FLEET MEMBER IS KEPT LIKE ANY READING, AND SAYS WHICH CLUSTERS WERE READ BESIDE IT. The note is a sidecar: the
// listing carries it, a reading of one cluster carries none, the reading itself is not touched (it still loads and
// still verifies), and a cluster's listing still counts only that cluster's readings.
func TestStore_NoteReadWith_IsListedBesideTheReadingAndChangesNothingElse(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	at := time.Date(2026, 10, 22, 13, 37, 29, 0, time.UTC)
	member, err := s.Save(mkReport("aks-prod", mkFinding("f-a", types.SeverityHigh, 10)), at)
	if err != nil {
		t.Fatal(err)
	}
	single, err := s.Save(mkReport("aks-prod", mkFinding("f-a", types.SeverityHigh, 10)), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.NoteReadWith(member, []string{"aks-stage", "aks-dev"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(member + readWithSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the note is %v; it names clusters, so it is user-only like the reading", fi.Mode().Perm())
	}
	snaps, err := s.List("aks-prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("the note was listed as a reading: %d snapshots, want 2", len(snaps))
	}
	byPath := map[string]Snapshot{}
	for _, sn := range snaps {
		byPath[sn.Path] = sn
	}
	if got := strings.Join(byPath[member].ReadWith, ","); got != "aks-stage,aks-dev" {
		t.Errorf("the fleet member lists read-with %q", got)
	}
	if byPath[single].ReadWith != nil {
		t.Errorf("a reading of one cluster says it was read with %q", byPath[single].ReadWith)
	}
	if _, err := s.Load(member); err != nil {
		t.Errorf("the noted reading no longer loads: %v", err)
	}
	if err := s.NoteReadWith(single, nil); err != nil {
		t.Errorf("an empty note is not an error: %v", err)
	}
	if _, err := os.Stat(single + readWithSuffix); !os.IsNotExist(err) {
		t.Errorf("an empty note left a file: %v", err)
	}
}
