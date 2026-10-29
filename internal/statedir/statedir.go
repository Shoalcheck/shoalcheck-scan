// Package statedir moves the pre-rename state directory (~/.assay) to its current home (~/.shoalcheck) once.
//
// Every reading this install kept, the key that signs them, the licence and the reference-data cache live there.
// A rename that started a fresh directory would make last month's reading vanish as "the prior", unpin a key a
// reviewer already trusts, and lose the licence — silently. So the first run moves the directory and leaves the
// old path as a link to the new one; nothing else in the product needs to know the old name existed.
package statedir

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/envx"
)

// MigrateLegacy moves ~/.assay to ~/.shoalcheck when only the old one exists and no home was set explicitly. It
// returns a one-line note when it moved something, "" when there was nothing to do.
func MigrateLegacy() (string, error) {
	// An explicit home (either name, non-empty — the same rule history.ShoalcheckHome applies) is the
	// operator's choice of place; nothing is moved for it.
	if envx.Get("SHOALCHECK_HOME") != "" {
		return "", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	oldDir, newDir := filepath.Join(home, ".assay"), filepath.Join(home, ".shoalcheck")
	fi, err := os.Lstat(oldDir)
	if err != nil || !fi.IsDir() {
		return "", nil // absent, or already a link: nothing of ours to move
	}
	aside := ""
	if _, err := os.Lstat(newDir); err == nil {
		// A ~/.shoalcheck that holds readings or a licence is the customer's: never touched. One that holds
		// neither was created by something that ran before the move — a fresh key, a cache, a stray report —
		// and obeying it would leave every kept reading and the licence behind. It is set aside, never deleted.
		if holdsCustomerState(newDir) || !holdsCustomerState(oldDir) {
			return "", nil
		}
		aside = fmt.Sprintf("%s.pre-migration-%d", newDir, time.Now().Unix())
		if err := os.Rename(newDir, aside); err != nil {
			return "", fmt.Errorf("set aside %s: %w", newDir, err)
		}
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		return "", fmt.Errorf("move %s to %s: %w", oldDir, newDir, err)
	}
	// The link is a convenience for anything that still names the old path; failing to make it loses nothing.
	_ = os.Symlink(newDir, oldDir)
	note := fmt.Sprintf("moved %s to %s — the product is now Shoalcheck; %s points to the new place", oldDir, newDir, oldDir)
	if aside != "" {
		note += fmt.Sprintf(" (a %s holding no readings was kept as %s)", newDir, aside)
	}
	return note, nil
}

// holdsCustomerState is whether a state directory carries something a customer would miss: kept readings or a
// licence. Keys, caches and rendered reports can be made again; those cannot.
func holdsCustomerState(dir string) bool {
	if entries, err := os.ReadDir(filepath.Join(dir, "history")); err == nil && len(entries) > 0 {
		return true
	}
	_, err := os.Stat(filepath.Join(dir, "license"))
	return err == nil
}

// Home is where this install keeps its state: SHOALCHECK_HOME (or its pre-rename name) when set, else
// ~/.shoalcheck. ONE ANSWER — six call sites each joined the home directory with ".shoalcheck" themselves and
// ignored the variable, which is how a test run wrote into the founder's real home.
func Home() (string, error) {
	if h := envx.Get("SHOALCHECK_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".shoalcheck"), nil
}
