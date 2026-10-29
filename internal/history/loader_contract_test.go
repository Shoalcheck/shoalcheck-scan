package history_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE TWO LOADERS HAVE DIFFERENT CONTRACTS, AND BOTH HALVES ARE PINNED HERE.
//
// `Store.Load` refuses a tampered snapshot AND re-runs types.Validate. `LatestOf` — the path `shoalcheck findings`,
// `explain` and `browse` reach a saved reading through — refuses a tampered snapshot and does NOT re-Validate.
//
// THAT DIFFERENCE IS WHY THIS TEST EXISTS. M-85 was a third loader, in cmd/shoalcheck, whose comment read
// "Snapshots are trusted (written only from validated reports), so this does not re-Validate" — and
// `history diff` used it to compare a file that had been edited after signing. The sentence that licensed it
// was `loadSnapshot`'s own: "a stored snapshot is trusted on read". Measured afterwards, on one unsigned
// snapshot whose summary said 7 findings and $99,999 while its array held 191 worth $90.31:
//
//	shoalcheck history diff     → EXIT=1  "internally inconsistent and will not be rendered:
//	                                  totalFindings=7 but 191 findings present"
//	shoalcheck findings         → EXIT=0, 191 rows
//	shoalcheck explain          → EXIT=0
//
// NO FALSE FIGURE REACHED A READER, and that is the honest limit of the finding: those commands derive
// everything from ar.Findings and never print Summary — `-o json` is a LIST of findings with no summary
// object, and sarif and md carry no trace of the forged number. The guarantee is one refactor away from
// being load-bearing, so both contracts are asserted rather than described.
func TestLoaderContracts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHOALCHECK_HOME", "") // the store follows HOME only when no explicit home is set
	t.Setenv("ASSAY_HOME", "")
	store, err := history.DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore: %v", err)
	}
	if store.Key == nil {
		t.Skip("no signing key on this install, so the tampered half cannot be built")
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "sample-audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	ar := &types.AuditReport{}
	if err := json.Unmarshal(raw, ar); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	ar.GeneratedAt = at
	path, err := store.Save(ar, at)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	edit := func(f func(map[string]any)) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// ── HALF ONE: a signed file edited after signing is refused by BOTH loaders. ─────────────────────────
	edit(func(d map[string]any) {
		if s, ok := d["summary"].(map[string]any); ok {
			s["totalFindings"] = 1
		}
	})
	if st, err := history.Verify(path, store.Key.Public()); err != nil || st != history.Tampered {
		t.Fatalf("the edited snapshot verifies as %q (%v) — this test needs it tampered", st, err)
	}
	if _, err := store.Load(path); err == nil {
		t.Error("Store.Load read a snapshot that was edited after it was signed")
	}
	if _, _, ok, err := store.LatestOf(ar.Cluster.Name, "", at.Add(time.Minute)); ok || err == nil {
		t.Error("LatestOf returned a snapshot that was edited after it was signed — the tampered refusal is " +
			"the half of this contract that IS guaranteed, and `shoalcheck findings` depends on it")
	}

	// ── HALF TWO: an UNSIGNED but inconsistent file — the two loaders differ, on purpose. ────────────────
	if err := os.Remove(path + ".sig"); err != nil {
		t.Fatalf("remove the sidecar: %v", err)
	}
	if st, _ := history.Verify(path, store.Key.Public()); st != history.Unsigned {
		t.Fatalf("with the sidecar gone the snapshot verifies as %q, want unsigned", st)
	}
	_, err = store.Load(path)
	if err == nil {
		t.Error("Store.Load read an internally inconsistent snapshot. It is the loader that guarantees the " +
			"headline equals the sum of what is under it, and a document failing that prints a number a " +
			"reader cannot check.")
	} else if !strings.Contains(err.Error(), "inconsistent") {
		t.Errorf("Store.Load refused for some other reason than consistency: %v", err)
	}
	// LatestOf deliberately does NOT re-Validate. Asserted so the difference is a decision on the record
	// rather than an accident someone later "fixes" in either direction without noticing which surfaces
	// depend on it.
	if _, _, ok, err := store.LatestOf(ar.Cluster.Name, "", at.Add(time.Minute)); !ok || err != nil {
		t.Errorf("LatestOf refused an unsigned inconsistent snapshot (ok=%v err=%v). That is a change of "+
			"contract: `shoalcheck findings` and `explain` read through this path and print only ar.Findings, "+
			"so refusing withholds every correct row over a summary field they never show. If this is now "+
			"wanted, the surfaces have to be checked first.", ok, err)
	}
}
