package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// NO SENTENCE SAYS A KIND THE COLLECTOR READS IS NOT READ (ENG-15). A sentence that priority classes went unread was
// published in every feasibility finding after the collector began reading them. Every present-tense claim of the
// form "<kinds> are not collected / not read" in the engine's sources is checked against the collector's step
// table; a kind it reads fails. Runtime sentences ("were not collected on this run") are about one reading's
// denial and are not claims about the product.
func TestNotRead_NoSentenceDeniesAKindTheCollectorReads(t *testing.T) {
	claim := regexp.MustCompile(`([a-z]+) (?:are|is) not (?:collected|read)`)
	checked := 0
	for _, dir := range []string{".", "../report", "../pipeline", "../analyzers", "../preflight"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range claim.FindAllStringSubmatch(string(b), -1) {
				checked++
				if _, ok := collect.StepTuple(m[1]); ok {
					t.Errorf("%s: %q — the collector reads %s; build the clause with notRead() or say what is true", f, m[0], m[1])
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no not-read claim found in the engine's sources: the pattern no longer matches how they are written")
	}
	if got := notRead("csinodes"); got != "csinodes are not read by this product" {
		t.Errorf("notRead(csinodes) = %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("notRead(priorityclasses) did not panic: a false sentence would have been built")
		}
	}()
	_ = notRead("priorityclasses")
}
