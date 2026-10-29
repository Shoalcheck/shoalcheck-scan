package statedir

import (
	"os"
	"path/filepath"
	"testing"
)

// THE RENAME KEEPS EVERY READING, KEY AND LICENCE. ~/.assay held the founder's signed readings, the install key
// that signs them, the licence and the reference-data cache. The first run after the rename moves the directory
// to ~/.shoalcheck and leaves ~/.assay pointing at it, so a reading kept last month is still "the prior" and a
// key already pinned by a reviewer still signs.
func TestMigrateLegacy_MovesTheOldDirectoryAndLeavesALinkBehind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHOALCHECK_HOME", "")
	t.Setenv("ASSAY_HOME", "")
	old := filepath.Join(home, ".assay", "history", "prod")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "r.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	note, err := MigrateLegacy()
	if err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if note == "" {
		t.Error("a migration happened and said nothing")
	}
	if _, err := os.Stat(filepath.Join(home, ".shoalcheck", "history", "prod", "r.json")); err != nil {
		t.Errorf("the reading did not arrive under ~/.shoalcheck: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(home, ".assay")); err != nil || target != filepath.Join(home, ".shoalcheck") {
		t.Errorf("~/.assay is not a link to ~/.shoalcheck: %q, %v", target, err)
	}
	// Idempotent: the second run finds nothing to do.
	if note, err := MigrateLegacy(); err != nil || note != "" {
		t.Errorf("a second run did something: %q, %v", note, err)
	}
}

// Nothing to migrate, a new directory already present, or an explicit home: no move, no note.
func TestMigrateLegacy_LeavesEverythingElseAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHOALCHECK_HOME", "")
	t.Setenv("ASSAY_HOME", "")
	if note, err := MigrateLegacy(); err != nil || note != "" {
		t.Errorf("a fresh machine migrated something: %q, %v", note, err)
	}
	for _, d := range []string{".assay", ".shoalcheck"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if note, err := MigrateLegacy(); err != nil || note != "" {
		t.Errorf("both directories present, and one was moved: %q, %v", note, err)
	}
	t.Setenv("SHOALCHECK_HOME", filepath.Join(home, "elsewhere"))
	if note, _ := MigrateLegacy(); note != "" {
		t.Errorf("an explicit SHOALCHECK_HOME still migrated: %q", note)
	}
}

// A NEW DIRECTORY THAT HOLDS NOTHING OF THE CUSTOMER'S DOES NOT BLOCK THE MOVE. Measured on the founder's Mac
// 2026-10-17: a test that wrote into the real home created ~/.shoalcheck with a fresh key, a price cache and three
// rendered reports before any binary ran, and the migration then refused to move ~/.assay — every kept reading
// and the licence stayed behind. A ~/.shoalcheck with no history and no licence is moved aside (kept, never
// deleted) and the old directory moves in.
func TestMigrateLegacy_AnEmptyNewDirectoryIsSetAsideNotObeyed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHOALCHECK_HOME", "")
	t.Setenv("ASSAY_HOME", "")
	if err := os.MkdirAll(filepath.Join(home, ".assay", "history", "prod"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".assay", "license"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".shoalcheck", "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	note, err := MigrateLegacy()
	if err != nil || note == "" {
		t.Fatalf("a fresh ~/.shoalcheck blocked the move: %q %v", note, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".shoalcheck", "license")); err != nil {
		t.Errorf("the licence did not arrive: %v", err)
	}
	aside, _ := filepath.Glob(filepath.Join(home, ".shoalcheck.pre-migration-*"))
	if len(aside) != 1 {
		t.Errorf("the fresh directory was not kept aside: %v", aside)
	}
	// And a ~/.shoalcheck that DOES hold readings is the customer's: never moved.
	home2 := t.TempDir()
	t.Setenv("HOME", home2)
	for _, d := range []string{".assay/history/a", ".shoalcheck/history/b"} {
		if err := os.MkdirAll(filepath.Join(home2, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if note, _ := MigrateLegacy(); note != "" {
		t.Errorf("a ~/.shoalcheck with readings of its own was moved aside: %q", note)
	}
}

// One answer to "where does this install keep its state": SHOALCHECK_HOME (or its old name), else ~/.shoalcheck.
func TestHome_HonoursTheEnvironment(t *testing.T) {
	t.Setenv("SHOALCHECK_HOME", "/tmp/x-home")
	if h, _ := Home(); h != "/tmp/x-home" {
		t.Errorf("SHOALCHECK_HOME ignored: %s", h)
	}
	t.Setenv("SHOALCHECK_HOME", "")
	t.Setenv("ASSAY_HOME", "")
	t.Setenv("HOME", "/tmp/y")
	if h, _ := Home(); h != "/tmp/y/.shoalcheck" {
		t.Errorf("default home: %s", h)
	}
}
