package rules

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/boundaries"
	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
)

// EVERY REGISTERED RULE CARRIES A BOUNDARY. A rule with none is a claim shipped without its limit, and the
// only reason a new one would have none is that whoever added it did not think about what it does not say.
func TestEveryRuleCarriesABoundary(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	var without []string
	for _, r := range All() {
		if len(ClaimBoundariesFor(r.ID())) == 0 {
			without = append(without, r.ID())
		}
	}
	if len(without) > 0 {
		t.Errorf("%d rule(s) carry no claim boundary — add each to a family in internal/boundaries, or write it a "+
			"family of its own:\n  %s", len(without), strings.Join(without, "\n  "))
	}
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rules; this gate was written against 85 and would read as full "+
			"coverage while measuring a fraction", n)
	}
}

// A FAMILY MAY NOT NAME A RULE THAT DOES NOT EXIST. A typo in the table is invisible otherwise: the rule it
// meant to cover silently has no boundary, and the gate above is what would catch it — but only if the typo
// is in a rule that has no other family. This makes the typo itself the failure.
//
// TWO PRODUCERS MINT FINDINGS, AND THIS GATE KNEW ABOUT ONE. `All()` is this package's registry; the stack
// analyzers in internal/analyzers mint their own `stack.*` ids and are not in it. So when fourteen analyzer
// rules were given boundaries on 2026-09-09 — they had none, and 21 of 2,176 findings in the local store
// were shipping with an empty ClaimBoundaries — this gate called every one of them an invented id.
//
// Both gates were right about their own producer, which is the shape of the underlying defect: a gate over
// one producer proves nothing about the other. The analyzers' ids are read from SOURCE rather than by
// importing the package, because internal/analyzers imports this one and the dependency cannot run both
// ways. internal/analyzers/finding_id_test.go holds the other direction.
func TestBoundaryFamiliesNameOnlyRealRules(t *testing.T) {
	real := map[string]bool{}
	for _, r := range All() {
		real[r.ID()] = true
	}
	// THE OTHER PRODUCER, BY ITS OWN DECLARATION — and this replaced two wrong things in one day.
	//
	// Until 2026-09-10 this block globbed ../analyzers/*.go and regexed every `"stack\..."` literal out of
	// it, subtracting the registration ids and pillars.go's keys, because nothing declared which ids an
	// analyzer's FINDINGS carry. That scan had to know three separate minting shapes — a named const
	// (istio.go), a helper ARGUMENT (hpa.go), and four types in one file (monitoring.go) — and a fourth
	// shape would have been invisible to it.
	//
	// It was first replaced by DELEGATION: this gate skipped every `stack.*` id and a second gate in
	// internal/analyzers checked them, on the strength of this file's own comment that "internal/analyzers
	// imports this package, so this one cannot import it back". THAT COMMENT WAS WRONG. Measured with
	// `go list -deps`: internal/analyzers depends on types, pricing, apiremoval, kubeversions, trace,
	// refdata and collect — NOT on internal/rules — and internal/rules does not depend on it either. They
	// are siblings, and neither direction is a cycle.
	//
	// So one gate covers both producers. The import is TEST-ONLY, which is what makes it free:
	// scripts/depcheck.sh walks `go list -deps`, the SHIPPED graph, and never sees a _test.go import — so
	// this adds no production coupling and violates no fence. A gate that has to be paired with a second
	// gate in another package, held together by a comment, is exactly the shape this file exists to refuse.
	for _, a := range analyzers.All() {
		for _, id := range a.FindingIDs() {
			real[id] = true
		}
	}

	// A FLOOR, BEFORE THE LOOP, BECAUSE A REGISTRY THAT HAS STOPPED REPORTING MUST NOT FAIL FOR THE WRONG
	// REASON. Emptying the analyzer registry makes every `stack.*` family below read as an invented id —
	// sixteen confusing "not a registered rule" errors ahead of the one line that explains why. Measured by
	// doing it: that is exactly what came out before this check was moved above the loop.
	//
	// 87 registered rules + 16 declared analyzer finding ids today. A floor, not an equality: adding either
	// kind must not fail this gate.
	if want := len(All()) + 16; len(real) < want {
		t.Fatalf("the two producers declare only %d ids between them, want at least %d (%d registered "+
			"rules + 16 analyzer finding ids): one registry has stopped reporting and every stack.* family "+
			"below would fail as an invented id", len(real), want, len(All()))
	}

	for _, f := range boundaries.Families {
		if len(f.Rules) == 0 {
			t.Errorf("family %q names no rule", f.Name)
		}
		if len(f.Lines) == 0 {
			t.Errorf("family %q carries no boundary", f.Name)
		}
		for _, id := range f.Rules {
			if !real[id] {
				t.Errorf("family %q names %q, which is not a registered rule", f.Name, id)
			}
		}
	}
}

// BOUNDARY TEXT CLEARS THE GLOBAL COPY POLICY. Boundaries are the one place in the product whose whole job is
// to DENY a status, so this is the case lexicon's AllowNegated exists for — and a scan that passed because it
// found nothing to negate would prove nothing about that path, which is why the probe below exists.
func TestBoundaryText_ClearsTheCopyPolicy(t *testing.T) {
	scanned := 0
	for _, f := range boundaries.Families {
		for _, line := range f.Lines {
			scanned++
			for _, v := range lexicon.Scan(line, func(lexicon.Scope) (string, bool) { return "", true }) {
				t.Errorf("family %q emits the banned %q — %s\n  line: %s", f.Name, v.Term.Text, v.Term.Why, line)
			}
		}
	}
	if scanned < 25 {
		t.Fatalf("only %d boundary line(s) were scanned; this gate is meant to cover every family", scanned)
	}

	// THE NEGATION PATH IS EXERCISED, not assumed. A banned term stated plainly must fire; the same term
	// inside a denial must not. Without both halves this test would pass on a scanner that never ran.
	var negatable lexicon.Term
	for _, term := range lexicon.Banned() {
		if term.AllowNegated && term.Scope == "" {
			negatable = term
			break
		}
	}
	if negatable.Text == "" {
		t.Fatal("no unscoped negatable term in the policy, so the negation path cannot be probed")
	}
	plain := "this reading is " + negatable.Text
	if len(lexicon.Scan(plain, func(lexicon.Scope) (string, bool) { return "", true })) == 0 {
		t.Errorf("the scanner did not fire on the bare %q, so the pass above proves nothing", negatable.Text)
	}
	denied := "this reading is not " + negatable.Text
	if v := lexicon.Scan(denied, func(lexicon.Scope) (string, bool) { return "", true }); len(v) != 0 {
		t.Errorf("the scanner fired on a denial of %q, so no boundary could ever state its own limit", negatable.Text)
	}
}

// THE FUNNIEST POSSIBLE REGRESSION, and it will happen: a drain boundary that reintroduces one of the phrases
// the drain family exists to refuse, while explaining that it refuses them.
func TestDrainBoundaries_DoNotReintroduceTheBannedPhrases(t *testing.T) {
	var drain []string
	for _, f := range boundaries.Families {
		if strings.HasPrefix(f.Name, "drain") || strings.HasPrefix(f.Name, "feasibility") {
			drain = append(drain, f.Lines...)
		}
	}
	if len(drain) == 0 {
		t.Fatal("no drain or feasibility boundaries found, so this gate measures nothing")
	}
	// TWO REFINEMENTS, BOTH LEARNED BY THIS TEST FAILING ON ITS FIRST RUN.
	//
	// A bare substring match is wrong twice over. It matched "seconds" inside `DefaultTolerationSeconds`, a
	// Kubernetes flag name the boundary has to be able to say, so the phrase must stand as a word. And it
	// matched "downtime" in "pod-recovery time is not service-downtime time" and "rotation" in "is not
	// evidence it was in rotation" — both denials, which is the entire register a boundary is written in.
	// Negation is decided by the product's own lexicon.Negated rather than by a hand-rolled prefix list,
	// because a second implementation of that judgement is a second thing to keep true.
	for _, line := range drain {
		low := strings.ToLower(line)
		for _, banned := range bannedDrainPhrases {
			for _, at := range wordOccurrences(low, banned) {
				if !lexicon.Negated(low, at) {
					t.Errorf("a drain boundary ASSERTS the banned phrase %q:\n  %s", banned, line)
				}
			}
		}
	}
}

// wordOccurrences reports every index where sub appears in s standing as a word, so a phrase named inside a
// longer identifier is not mistaken for the phrase itself.
func wordOccurrences(s, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return out
		}
		at := i + j
		before := at == 0 || !isWordChar(s[at-1])
		end := at + len(sub)
		after := end == len(s) || !isWordChar(s[end])
		if before && after {
			out = append(out, at)
		}
		i = at + 1
	}
}

func isWordChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
