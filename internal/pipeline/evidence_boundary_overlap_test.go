package pipeline

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A LIMIT BELONGS IN ONE BLOCK, AND THE BLOCKS MEAN DIFFERENT THINGS.
//
// `Evidence` is what the reading READ — quoted fields, counted objects, named bindings. `ClaimBoundaries` is
// what the finding does NOT establish. A sentence in both is not thoroughness; it is the same limit printed
// twice under two headings whose whole purpose is to be different, on every surface at once — the card, the
// terminal, the Markdown export and the ticket a colleague opens days later.
//
// MEASURED ON A LIVE 188-FINDING READING: fifty pairs at 0.96 similarity, all from one rule. Its evidence
// ended with "This names one rule and the bindings that activate it. It is not a total: …" while its
// boundary said "This names one role's rules and the bindings that activate it. It is not a total: …" — the
// same sentence, and the boundary's wording is the better one. The evidence line predates
// Finding.ClaimBoundaries: before the field existed it was the only place a rule could say this.
//
// THE THRESHOLD IS DELIBERATELY HIGH. Evidence and a boundary can legitimately share vocabulary — both talk
// about bindings, namespaces and what was read — so this fires only on near-identical sentences, which is
// the case where a reader is being shown one thought twice.
func TestGolden_NoEvidenceRepeatsABoundary(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(ar.Findings) == 0 {
		t.Fatal("the golden holds no findings, so this test would prove nothing")
	}

	type dup struct{ rule, ev, bd string }
	var dups []dup
	checked := 0
	for _, f := range ar.Findings {
		for _, ev := range f.Evidence {
			for _, bd := range f.ClaimBoundaries {
				checked++
				if similar(ev, bd) > 0.90 {
					dups = append(dups, dup{f.RuleID, ev, bd})
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no finding carries both evidence and a boundary, so nothing was compared")
	}
	for i, d := range dups {
		if i >= 3 {
			t.Errorf("… and %d more", len(dups)-3)
			break
		}
		t.Errorf("%s prints one limit twice — once as evidence, once as a boundary:\n  evidence: %s\n  boundary: %s\n\n"+
			"Evidence is what the reading READ; a boundary is what the finding does NOT establish. A sentence "+
			"in both is the same thought under two headings, on every surface at once.", d.rule, d.ev, d.bd)
	}
}

// similar is a token-overlap ratio, which is enough to find a sentence that was copied and lightly edited.
func similar(a, b string) float64 {
	fa, fb := words(a), words(b)
	if len(fa) == 0 || len(fb) == 0 {
		return 0
	}
	common := 0
	for w, n := range fa {
		if m, ok := fb[w]; ok {
			common += min(n, m)
		}
	}
	total := 0
	for _, n := range fa {
		total += n
	}
	for _, n := range fb {
		total += n
	}
	return 2 * float64(common) / float64(total)
}

func words(s string) map[string]int {
	out := map[string]int{}
	cur := ""
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			cur += string(r | 0x20)
			continue
		}
		if cur != "" {
			out[cur]++
			cur = ""
		}
	}
	if cur != "" {
		out[cur]++
	}
	return out
}
