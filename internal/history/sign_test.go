package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/signing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func signedStore(t *testing.T) *Store {
	t.Helper()
	t.Setenv(signing.EnvPrivateKey, "")
	k, err := signing.LoadOrCreate(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	return &Store{Dir: t.TempDir(), Key: k}
}

// Spec §5 test 2: the sidecar is written, and the three states are the only vocabulary — asserted on one file.
func TestSave_WritesASidecarAndVerifyNamesThreeStates(t *testing.T) {
	s := signedStore(t)
	path, err := s.Save(mkReport("c", mkFinding("f-1", types.SeverityHigh, 10)), time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := os.ReadFile(path + ".sig")
	if err != nil {
		t.Fatal("no sidecar written:", err)
	}
	if !strings.Contains(string(sc), signing.Fingerprint(s.Key.Public())) {
		t.Error("the sidecar does not name the signer's fingerprint")
	}
	if st, _ := Verify(path, s.Key.Public()); st != Signed {
		t.Fatalf("fresh snapshot is %q, want signed", st)
	}
	b, _ := os.ReadFile(path)
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := Verify(path, s.Key.Public()); st != Tampered {
		t.Fatalf("changed snapshot is %q, want tampered", st)
	}
	if err := os.Remove(path + ".sig"); err != nil {
		t.Fatal(err)
	}
	if st, _ := Verify(path, s.Key.Public()); st != Unsigned {
		t.Fatalf("snapshot without a sidecar is %q, want unsigned", st)
	}
}

// Spec §5 test 3: Load and Latest refuse a tampered snapshot by name and keep reading an unsigned one — history
// written before keys existed is not made worthless by their arrival.
func TestLoad_RefusesTamperedKeepsUnsigned(t *testing.T) {
	s := signedStore(t)
	t1 := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	older, err := s.Save(mkReport("c", mkFinding("f-1", types.SeverityHigh, 10)), t1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(older + ".sig"); err != nil { // an unsigned snapshot, as one from before keys existed
		t.Fatal(err)
	}
	newer, err := s.Save(mkReport("c", mkFinding("f-1", types.SeverityHigh, 10)), t1.AddDate(0, 0, 7))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(older); err != nil {
		t.Fatalf("an unsigned snapshot must load: %v", err)
	}
	b, _ := os.ReadFile(newer)
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(newer, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(newer); err == nil || !strings.Contains(err.Error(), "does not verify") || !strings.Contains(err.Error(), newer) {
		t.Fatalf("a tampered snapshot loaded, or the refusal does not name it: %v", err)
	}
	// Latest refuses rather than silently skipping: the caller logs "could not read an earlier snapshot".
	if _, _, _, err := s.LatestOf("c", "", t1.AddDate(0, 0, 30)); err == nil {
		t.Fatal("Latest returned a comparison baseline from a tampered snapshot")
	}
	snaps, err := s.List("c")
	if err != nil || len(snaps) != 2 {
		t.Fatalf("list: %v", err)
	}
	if snaps[0].Signed != Tampered || snaps[1].Signed != Unsigned {
		t.Errorf("list states %q / %q, want tampered / unsigned", snaps[0].Signed, snaps[1].Signed)
	}
	// A store without a key reports no state and reads everything, as every test before today did.
	plain := &Store{Dir: s.Dir}
	if ps, _ := plain.List("c"); ps[0].Signed != "" {
		t.Errorf("a keyless store reported a state %q", ps[0].Signed)
	}
}
