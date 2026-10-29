package lexicon_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
)

// EPIC 0.1 — THE POLICY IS NOT ENFORCED ON ANYTHING THE PRODUCT ACTUALLY EMITS.
//
// This package's own doc comment states the design intent:
//
//	"It is a normal package rather than a test helper on purpose. The policy is not a property of
//	 the tests; the tests are one consumer of it."
//
// It is, today, a property of the tests. Every importer is a _test.go file, which means the banned-word table
// reaches exactly those strings some test happens to render. Three ways a claim gets to a reader untouched:
//
//   - A string assembled at RUNTIME from cluster data. A rule that interpolates a workload name, a namespace or
//     a provider label into a sentence produces text no fixture contains.
//   - A NEW template, or a new branch of an old one. The degraded sweep renders ten shapes; the report has more
//     branches than that, and a branch nobody wrote a test for is unscanned.
//   - A surface added later. The desktop app needed its own gate precisely because no Go template renders it;
//     the next surface will need one too, and nothing forces it.
//
// This is the same defect class as a browser gate that only ever measures one fixture, and it was found the same
// way — by asking who actually consults the thing, rather than whether it exists.
//
// FAILS TODAY BY DESIGN. It passes when some non-test file consults lexicon on real output.
func TestLexicon_IsConsultedByAProductionPath(t *testing.T) {
	root := moduleRoot(t)
	var prod, tests []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), `"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"`) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasSuffix(path, "_test.go") {
			tests = append(tests, rel)
		} else {
			prod = append(prod, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(tests) == 0 {
		t.Fatal("no file at all imports lexicon — this test can no longer tell an unenforced policy from a " +
			"deleted one, which means it has stopped being a gate")
	}
	if len(prod) == 0 {
		t.Errorf("lexicon is imported by %d test file(s) and ZERO production files, so the copy policy applies "+
			"only to the strings a test happens to render:\n  tests: %s\n\n"+
			"A sentence assembled at runtime from cluster data, a new template branch, or the next surface added "+
			"to the product all reach the reader unscanned. The package's own doc comment says the policy is not "+
			"a property of the tests.", len(tests), strings.Join(tests, "\n         "))
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find go.mod above the test's working directory")
	return ""
}

// NO SURFACE KEEPS ITS OWN BANNED LIST. That is the entire reason this package exists.
//
// The doc comment records that the policy was once "guarded in eight different files, each with its own list",
// and that consolidating them was the point. scripts/app-check.mjs then hand-rolled a ninth — six regexes over
// the desktop app's rendered text — and it had drifted exactly as predicted: no `realized`, no `notarized`, no
// bare `clean`, no `verified savings`, while carrying two patterns the table did not have.
//
// A second list cannot be found by asking whether one exists; it has to be looked for. This test looks for the
// SHAPE of one: a word-boundary matcher built around a term from the table, in a file that cannot import Go.
// Those are the surfaces with a motive to re-implement the policy, and the .mjs harnesses are all of them.
func TestNoSurfaceKeepsItsOwnBannedList(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(lexicon.Banned()); n < 20 {
		t.Fatalf("the registry holds %d banned term(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	root := moduleRoot(t)
	dir := filepath.Join(root, "scripts")
	var scanned int
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".mjs") && !strings.HasSuffix(path, ".js") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		scanned++
		src := string(b)
		rel, _ := filepath.Rel(root, path)
		for _, term := range lexicon.Banned() {
			// `\bterm` — a JavaScript regexp asserting a word boundary before a banned word. Prose that
			// merely mentions the word (this project's scripts discuss "the fixed shadow") does not match;
			// a matcher does.
			if strings.Contains(src, `\b`+term.Text) {
				t.Errorf("%s builds its own matcher for the banned term %q. The table is internal/lexicon "+
					"and there is exactly one of it: a list here is unknown to the Go side, and a word "+
					"added to the table is unknown to this list. The desktop app's copy is scanned by "+
					"TestUIVocabulary in cmd/shoalcheck-app.\n  If this is a COMMENT explaining the ban, write "+
					"the word plainly instead of as a regex — the escape is what this test looks for.",
					rel, term.Text)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	// NON-VACUITY: a walk that found no files, or a table with no terms, would pass having checked nothing.
	if scanned == 0 {
		t.Fatal("no .mjs file was scanned, so this test cannot see a second list even if one is added")
	}
	if len(lexicon.Banned()) == 0 {
		t.Fatal("the banned table is empty, so no pattern could match")
	}
}
