package history_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/signing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func goldenReading(t *testing.T, at time.Time) *types.AuditReport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "sample-audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	ar := &types.AuditReport{}
	if err := json.Unmarshal(raw, ar); err != nil {
		t.Fatal(err)
	}
	ar.GeneratedAt = at
	return ar
}

// A SNAPSHOT SIGNED BY A KEY THIS INSTALL NO LONGER HOLDS IS NOT A TAMPERED ONE.
//
// Found by copying a history directory to a machine without its keys — and it is exactly what the rendered CI
// schedule does every run, because the job restores history from its cache and creates a fresh install key. Every
// genuine snapshot was branded TAMPERED, LatestOf refused it, and `audit --save-history` then saved nothing at all,
// warning and exiting 0, forever. The sidecar names the key that signed it, so the two cases are told apart: a
// signature by this install's own key that no longer matches the bytes is tampering; a signature by another key
// is a fact this install cannot check, and it reads like an unsigned file — no more trusted, and no less.
func TestStore_AnotherKeysSignatureIsNotTampering(t *testing.T) {
	dir := t.TempDir()
	old, err := signing.LoadOrCreate(filepath.Join(dir, "old-keys"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := signing.LoadOrCreate(filepath.Join(dir, "new-keys"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	path, err := (&history.Store{Dir: filepath.Join(dir, "history"), Key: old}).Save(goldenReading(t, at), at)
	if err != nil {
		t.Fatal(err)
	}

	st, err := history.Verify(path, cur.Public())
	if err != nil {
		t.Fatal(err)
	}
	if st != history.OtherKey {
		t.Fatalf("a snapshot signed by a previous key of this install reads as %q, want %q", st, history.OtherKey)
	}
	store := &history.Store{Dir: filepath.Join(dir, "history"), Key: cur}
	ar := goldenReading(t, at)
	prev, _, ok, err := store.LatestOf(ar.Cluster.Name, "", at.Add(time.Hour))
	if err != nil || !ok || prev == nil {
		t.Fatalf("LatestOf refused a genuine reading signed by another key: ok=%v err=%v", ok, err)
	}

	// Tampering is still tampering: this install's own signature over bytes that changed.
	path2, err := store.Save(goldenReading(t, at.Add(2*time.Hour)), at.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path2)
	if err := os.WriteFile(path2, append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := history.Verify(path2, cur.Public()); st != history.Tampered {
		t.Errorf("an edited file signed by this install's own key reads as %q, want tampered", st)
	}
}
