package lexicon_test

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
)

// EPIC 0.1 — DIRECT TESTS FOR THE MATCHER.
//
// 160 lines, zero tests of its own, and the two subtlest pieces of logic in the package — WholeWord and
// AllowNegated — were verified only indirectly, through whatever strings the report fixtures happened to
// contain. Every consumer's gate is only as good as this matcher, so it gets asserted on its own terms.
//
// Two kinds of case below, marked as such:
//   ASSERTED  — behaviour that must hold. A failure here is a defect in the matcher.
//   PINNED    — a documented trade-off, asserted so a change to it is deliberate rather than accidental. Each
//               one carries the risk it creates for a RUNTIME consumer, where a false allow ships the claim
//               rather than merely passing a test.

// scan maps no region, so a scoped term is enforced across the whole string. That is the strict fallback and
// it is what these single-sentence cases want: none of them is a document with regions in it.
func scan(t *testing.T, text string) []lexicon.Violation {
	t.Helper()
	return lexicon.Scan(text, nil)
}

func hit(vs []lexicon.Violation, term string) bool {
	for _, v := range vs {
		if v.Term.Text == term {
			return true
		}
	}
	return false
}

// ASSERTED: WholeWord separates a verdict from a fragment of an innocent word.
func TestWholeWord_SeparatesAVerdictFromAFragment(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
		why  string
	}{
		{"the cluster is clean", true, "a bare clean is the verdict the table exists to ban"},
		{"storage cleanup levers", false, "cleanup is a lever label, not a verdict"},
		{"cleaned up 4 volumes", false, "cleaned is a different word"},
		{"unclean shutdown", false, "unclean is a different word"},
		{"clean.", true, "punctuation is not a word character, so this still stands alone"},
		{"a clean, readable report", true, "still the bare verdict"},
	} {
		got := hit(scan(t, tc.text), "clean")
		if got != tc.want {
			t.Errorf("Scan(%q) flagged clean=%v, want %v — %s", tc.text, got, tc.want, tc.why)
		}
	}
}

// ASSERTED: a denial of a status must survive. The disclaimer panel is the strongest honesty text in the
// document and it is built entirely out of banned words.
func TestAllowNegated_TheDisclaimerSurvives(t *testing.T) {
	for _, s := range []string{
		"it is not a certified audit",
		"this report is not issued by a QSA and carries no certification",
		"nothing here constitutes an attestation",
		"never notarized",
		"no outcome is guaranteed",
	} {
		if vs := scan(t, s); len(vs) > 0 {
			t.Errorf("Scan(%q) reported %d violation(s) — the gate would force the document's own denials "+
				"to be deleted or weaselled:\n  %+v", s, len(vs), vs)
		}
	}
	// And the bare claim is still caught, or the allowance has eaten the rule.
	for _, s := range []string{"a certified audit", "notarized by us", "outcomes are guaranteed"} {
		if vs := scan(t, s); len(vs) == 0 {
			t.Errorf("Scan(%q) found nothing — AllowNegated has swallowed the un-negated claim", s)
		}
	}
}

// ASSERTED: the negation window has an end. Without one, a "not" anywhere in the document would license every
// claim after it.
func TestNegationWindow_HasAnEnd(t *testing.T) {
	near := "this is not " + strings.Repeat("x", 40) + " certified"
	far := "this is not " + strings.Repeat("x", 200) + " certified"
	if vs := scan(t, near); len(vs) != 0 {
		t.Errorf("a negator 40 characters away did not license the word: %+v", vs)
	}
	if vs := scan(t, far); len(vs) == 0 {
		t.Error("a negator 200 characters away still licensed the word — the window is not bounded, so one " +
			"\"not\" would license the rest of the document")
	}
}

// ASSERTED: a negator must be a WORD, not a substring.
//
// negators contains "no " and the check is strings.Contains, so any word ending in "no" followed by a space
// licenses every banned term for the next 90 characters. "mono" is not a hypothetical in this repository: it is
// the name of a font token, it appears in prose about tabular figures, and --font-mono is written out in the
// stylesheet the report embeds. Same for "piano", "nano", "Juno", and for "nor" inside "minor"/"tenor".
//
// A test-time false allow costs a missed assertion. A RUNTIME false allow — which is what Epic 0.1 is about to
// build — ships the claim.
func TestNegators_AreWordsNotSubstrings(t *testing.T) {
	for _, tc := range []struct{ text, why string }{
		{"the mono column is clean", `"mono " contains "no "`},
		{"a minor revision is clean", `"minor " contains "nor "`},
		// "nano-second" was a third candidate and it does NOT match: the negator is "no " with a trailing
		// space, and "nano-" has a hyphen. Recorded because a wrong premise dressed as a failing test is
		// worse than no test — the two above are real words from this repository's own prose.
	} {
		if vs := scan(t, tc.text); len(vs) == 0 {
			t.Errorf("Scan(%q) found nothing — %s, so the substring match read an innocent word as a "+
				"negation and licensed the verdict", tc.text, tc.why)
		}
	}
}

// PINNED: Scan is case-sensitive and its precondition is unenforceable from inside.
//
// The doc comment says the text "must already be PLAIN — tags stripped, lowercased". A caller that forgets gets
// zero violations and a clean bill, and nothing distinguishes that from a document with no violations. For the
// test consumers this is fine — they all lowercase. For the runtime wiring it is the whole risk: the failure
// mode of the enforcement point is silence.
//
// FOUNDER QUESTION, recorded rather than decided: should Scan lowercase defensively, or should there be a
// separate entry point that refuses non-lowercase input? Making it defensive costs an allocation per scan;
// leaving it costs a silent hole at exactly the new call site.
func TestScan_IsCaseSensitiveAndCannotSayWhy(t *testing.T) {
	if vs := scan(t, "This Is A CERTIFIED Audit"); len(vs) != 0 {
		t.Skip("Scan now handles case; delete this pin and the founder question with it")
	}
	if vs := scan(t, strings.ToLower("This Is A CERTIFIED Audit")); len(vs) == 0 {
		t.Fatal("the lowercased form was not caught either, so this pin is measuring the wrong thing")
	}
}

// ASSERTED, AND IT USED TO BE THE OPPOSITE: a scope this surface never mapped is scanned DOCUMENT-WIDE, not
// skipped.
//
// This is the fix for the SEV-1 that closed this pin. The resolver was a func(Scope) string, and "" meant both
// "this document has no comparison strip" (correct to skip — the golden fixture renders none) and "I have never
// heard of that region" (a hole in the policy). The caller could not tell them apart, chose skip, and the
// desktop app — whose comparison block is `class="cmp"` and which contains the string "trend-strip" nowhere —
// had all four comparison terms dropped. Its gate ran, reported clean, and guarded nothing.
//
// The resolver now answers two questions, and the three outcomes are asserted separately below. Note the
// direction: an unmapped scope over-reports, loudly, and says so in Violation.Detail. Skipping was silent, and
// a silent gate is the failure this package exists to prevent.
func TestUnmappedScope_IsScannedDocumentWideAndNeverSkipped(t *testing.T) {
	const claim = "3 findings resolved since the last reading"

	// 1. Nil resolver: maps nothing, so every scoped term is enforced everywhere.
	vs := lexicon.Scan(claim, nil)
	if !hit(vs, "resolved") {
		t.Errorf("a nil resolver dropped a scoped term instead of enforcing it document-wide: %+v", vs)
	}
	if len(vs) > 0 && !vs[0].Unscoped {
		t.Error("the violation does not record that it came from an unmapped scope, so the diagnostic cannot " +
			"tell the reader their surface never mapped the region")
	}
	if len(vs) > 0 && vs[0].Detail() == vs[0].Term.Why {
		t.Error("Detail() says nothing about the unmapped scope, so the wiring gap is invisible in the output")
	}

	// 2. A resolver that does not know this scope: same treatment. This is exactly the desktop app's old
	//    resolver, which answered "" for every section name it did not recognise.
	unknowing := lexicon.Sections(func(lexicon.Scope) (string, bool) { return "", false })
	if !hit(lexicon.Scan(claim, unknowing), "resolved") {
		t.Error("a resolver that does not recognise the scope silently dropped the term — this is the " +
			"defect verbatim: one surface's class name in a shared table, and nothing notices")
	}

	// 3. A resolver that KNOWS the scope and says this document has no such region: honoured, because that is
	//    an answer. The golden report renders no comparison strip when there is no previous run.
	absent := lexicon.Sections(func(lexicon.Scope) (string, bool) { return "", true })
	if vs := lexicon.Scan(claim, absent); len(vs) != 0 {
		t.Errorf("a surface that states the region is absent was overruled, which makes every document "+
			"without a comparison strip unscannable: %+v", vs)
	}

	// 4. And the scoping still works in the ordinary direction, or all of the above is moot.
	mapped := lexicon.Sections(func(s lexicon.Scope) (string, bool) {
		return claim, s == lexicon.ScopeComparison
	})
	if !hit(lexicon.Scan(claim, mapped), "resolved") {
		t.Error("with the region mapped and containing the claim, the term was still not caught")
	}
	if vs := lexicon.Scan("the resolved dns name is api.internal", lexicon.Sections(
		func(lexicon.Scope) (string, bool) { return "", true })); len(vs) != 0 {
		t.Errorf("\"resolved\" was flagged outside its region, where it is ordinary prose: %+v", vs)
	}
}

// ASSERTED: Regions is a shared slicer, so no surface writes its own and reintroduces the stylesheet bug.
func TestRegions_LocateEveryOccurrenceAndTheWholeDocument(t *testing.T) {
	doc := `<style>.strip{}</style><div class="strip">one resolved</div>` +
		strings.Repeat("x", 500) + `<div class="strip">two saved</div>`

	r := lexicon.Regions{Doc: doc, Window: 40, Plain: strings.ToLower,
		Of: map[lexicon.Scope][]string{lexicon.ScopeComparison: {"strip"}, lexicon.ScopeCalendar: {}}}.Sections()
	got, mapped := r(lexicon.ScopeComparison)
	if !mapped {
		t.Fatal("a scope present in the map was reported unmapped")
	}
	// THREE occurrences of the marker, and the second and third are the two comparison blocks. A fleet
	// document carries one strip per cluster, and the previous slicer took only the first — so the copy
	// policy read cluster one and said nothing about clusters two through eleven.
	for _, want := range []string{"one resolved", "two saved"} {
		if !strings.Contains(got, want) {
			t.Errorf("the region does not contain %q — only some occurrences of the marker were sliced: %q",
				want, got)
		}
	}
	// A negator at the end of one region must not license a claim at the start of the next.
	joined := lexicon.Regions{Doc: `<div class="s">nothing was</div>` + strings.Repeat("y", 500) +
		`<div class="s">3 findings resolved</div>`, Window: 30, Plain: strings.ToLower,
		Of: map[lexicon.Scope][]string{lexicon.ScopeComparison: {"class=\"s\""}}}.Sections()
	if !hit(lexicon.Scan("", joined), "resolved") {
		// Scan is called on "" only to force the scoped path; the region is the haystack.
		t.Error("a negator at the end of one region licensed a claim in the next — the regions are joined " +
			"closer than the negation window")
	}

	// WholeDocument is an answer, not an omission.
	whole := lexicon.Regions{Doc: doc, Plain: strings.ToLower,
		Of: map[lexicon.Scope][]string{lexicon.ScopeComparison: {lexicon.WholeDocument}}}.Sections()
	if got, mapped := whole(lexicon.ScopeComparison); !mapped || !strings.Contains(got, "two saved") {
		t.Errorf("WholeDocument did not return the whole document (mapped=%v, len=%d)", mapped, len(got))
	}

	// A scope absent from the map is UNMAPPED, which is the loud case.
	if missing := lexicon.UnmappedScopes(lexicon.Regions{Doc: doc}.Sections()); len(missing) == 0 {
		t.Error("Regions with an empty map reported every scope mapped, so a surface could forget one and " +
			"UnmappedScopes would never say so")
	}
	if missing := lexicon.UnmappedScopes(r); len(missing) != 0 {
		t.Errorf("UnmappedScopes reported %v missing from a map that covers the comparison region", missing)
	}
	// NON-VACUITY for both assertions above: there is at least one scope to be missing or present.
	if len(lexicon.Scopes()) == 0 {
		t.Fatal("the table narrows no term to a scope, so nothing above tested anything")
	}
}

// ASSERTED: every term in the table is reachable by the matcher that is supposed to enforce it. A term whose
// own Text cannot be found in a sentence containing it is dead policy.
func TestEveryBannedTerm_IsReachable(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(lexicon.Banned()); n < 20 {
		t.Fatalf("the registry holds %d banned term(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	for _, term := range lexicon.Banned() {
		sentence := "the " + term.Text + " here"
		sections := lexicon.Sections(func(lexicon.Scope) (string, bool) { return sentence, true })
		if !hit(lexicon.Scan(sentence, sections), term.Text) {
			t.Errorf("the banned term %q is not found in a sentence that contains it verbatim — it is in the "+
				"table and enforced nowhere", term.Text)
		}
	}
}

// PINNED: the table bans "guaranteed" and not the stem, so "we guarantee", "a guarantee of" and "this
// guarantees" all pass.
//
// scripts/app-check.mjs carried `/\bguarantee/i` — stricter than this table — and deleting that script would
// have quietly dropped the difference, so the stem was added here and then taken back out. It fires on exactly
// one sentence of product prose, internal/rules/pss.go's WhyItMatters for the PodSecurity rule:
//
//	"PodSecurity admission is the only thing that turns securityContext hardening from a suggestion into a
//	 guarantee — without it, a single noncompliant manifest re-opens every gap the per-container checks flag."
//
// That is a claim about what a Kubernetes admission controller enforces, not about what this audit promises,
// and the two are not the same kind of statement. FOUNDER QUESTION, recorded rather than decided: ban the stem
// and reword that sentence ("into an enforced default"), or leave the narrow form and accept that a future
// "we guarantee" reaches a reader. The pin exists so whichever is chosen is chosen, not inherited.
func TestGuaranteeStem_IsNotBannedYet(t *testing.T) {
	if vs := scan(t, "we guarantee a smaller bill"); len(vs) != 0 {
		t.Skip("the stem is banned now; delete this pin and the founder question with it")
	}
	if vs := scan(t, "outcomes are guaranteed"); len(vs) == 0 {
		t.Fatal("the narrow form is not caught either, so this pin is measuring the wrong thing")
	}
}

// ASSERTED: the size of the table is written down in exactly one place, and this is it.
//
// It used to be written in prose in three files, and prose drifts: three comments said "four of the sixteen
// terms" while Banned() returned fifteen. Those counts have been removed rather than corrected, because a
// number in a comment is a second copy of a fact and this package exists to end second copies.
//
// The test remains as the tripwire. It fails on any change to the table, which is the moment to check that no
// comment you are adding quotes a count — a gate you have to remember is not a gate.
func TestBannedTable_TheCountIsWrittenDownInExactlyOnePlace(t *testing.T) {
	const documented = 23
	if got := len(lexicon.Banned()); got != documented {
		t.Errorf("the table holds %d terms and this test says %d. If you changed the table deliberately, "+
			"update this number — and while you are here, make sure the comment you wrote does not quote a "+
			"count of its own. A comment that miscounts the policy is how a reader learns the policy is not "+
			"maintained, and this one has already done it once.", got, documented)
	}
	// NON-VACUITY: a table that returned nothing would make every consumer's gate pass, and a bare count
	// assertion above would still hold if someone replaced the number with 0 to match.
	if len(lexicon.Banned()) == 0 {
		t.Fatal("the table is empty")
	}
}

// ASSERTED: A KUBERNETES IDENTIFIER IS DATA, NOT COPY.
//
// standsAlone counted only [a-zA-Z0-9] as word characters, so a hyphen read as a word boundary and the bare
// "clean" ban fired on every occurrence of a cluster named `clean-cluster`. The runtime enforcement point found
// this on its first real run — 11 hits, all of them the customer's own resource name echoed in the per-section
// identity strip — and the golden fixture could never have shown it, because its cluster is `acme-pay-prod`.
//
// This is the defining false-positive class for a gate that runs on real output: the document interpolates user
// data into prose everywhere, and user data is not our claim. `-` and `_` are identifier characters in
// Kubernetes names, labels, namespaces and image tags; treating them as prose boundaries turns the policy into
// noise, and a noisy gate gets switched off.
//
// The bare verdict is still caught, which is the half that matters.
func TestWholeWord_TreatsIdentifierPunctuationAsPartOfTheWord(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
		why  string
	}{
		{"cluster clean-cluster kind · local", false, "a cluster NAME is data"},
		{"namespace clean_room", false, "an underscore joins an identifier too"},
		{"storage clean-up levers", false, "a hyphenated label is one token"},
		{"image registry/clean-base:1.2", false, "an image reference is data"},
		{"the cluster is clean", true, "the bare verdict must still be caught"},
		{"clean.", true, "a sentence-final verdict is still a verdict"},
		{"a clean, readable report", true, "punctuation that ends a word is still a boundary"},
	} {
		got := hit(scan(t, tc.text), "clean")
		if got != tc.want {
			t.Errorf("Scan(%q) flagged clean=%v, want %v — %s", tc.text, got, tc.want, tc.why)
		}
	}
}

// ASSERTED: a region can know where it ends. Without Until, a start marker takes a fixed window and a block
// shorter than the window drags the text after it into the scope — the next section's severity badges would be
// read as the calendar's copy. With Until, the slice stops at the end marker; a document with no end marker
// falls back to the window, so the comparison strip is unchanged.
func TestRegions_StopAtTheEndMarker(t *testing.T) {
	doc := `<article class="clock-block"><p>act now</p><span data-clock-end></span></article><div class="badge">critical</div>`
	bounded := lexicon.Regions{Doc: doc, Of: map[lexicon.Scope][]string{lexicon.ScopeCalendar: {"clock-block"}},
		Until: map[lexicon.Scope]string{lexicon.ScopeCalendar: "data-clock-end"}}.Sections()
	got, mapped := bounded(lexicon.ScopeCalendar)
	if !mapped || !strings.Contains(got, "act now") || strings.Contains(got, "critical") {
		t.Fatalf("bounded region = %q, want the block's text and not the badge after it", got)
	}
	unbounded := lexicon.Regions{Doc: doc, Of: map[lexicon.Scope][]string{lexicon.ScopeCalendar: {"clock-block"}}}.Sections()
	if got, _ := unbounded(lexicon.ScopeCalendar); !strings.Contains(got, "critical") {
		t.Fatalf("non-vacuity: without an end marker the window must still reach the badge, got %q", got)
	}
	// Two blocks, each bounded: the second's text is in, the text between them is not.
	two := doc + `<i>between at risk</i><article class="clock-block"><p>urgent</p><span data-clock-end></span></article>`
	got, _ = lexicon.Regions{Doc: two, Of: map[lexicon.Scope][]string{lexicon.ScopeCalendar: {"clock-block"}},
		Until: map[lexicon.Scope]string{lexicon.ScopeCalendar: "data-clock-end"}}.Sections()(lexicon.ScopeCalendar)
	if !strings.Contains(got, "urgent") || strings.Contains(got, "between at risk") {
		t.Fatalf("two bounded regions = %q", got)
	}
}
