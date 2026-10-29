// Package lexicon is this product's copy policy, expressed as code.
//
// The document's credibility rests on never claiming a status it does not have. Some words confer such a status
// just by appearing — "notarized", "attestation", "certified" — and others quietly convert a difference between
// two readings into an outcome: "resolved", "fixed", "saved", "realized".
//
// Those words were guarded in eight different files, each with its own list, which is the failure this package
// ends: a word added to one list is unknown to the other seven, and the guard watching the comparison strip has
// nothing to say about a new appendix. One table, one scanner, used by every surface — the HTML report, the
// fleet report, and the desktop app's own markup, which no Go template renders.
//
// It is a normal package rather than a test helper on purpose. The policy is not a property of the tests; the
// tests are one consumer of it.
package lexicon

import "strings"

// Scope names a REGION OF A DOCUMENT that some bans are narrowed to. It is the policy's name for the region,
// never a surface's name for it.
//
// This distinction is the fix for a real SEV-1. The table used to hold `Section: "trend-strip"` — the CSS class
// of the HTML report's comparison strip — so one surface's class name had leaked into the shared policy. The
// desktop app's comparison block is `class="cmp"` and the string "trend-strip" appears nowhere in its 60KB of
// markup, so its resolver answered "" for a section it had never heard of, Scan read "" as "this document has
// no comparison block", and all four comparison terms were dropped. The gate ran, reported clean, and guarded
// nothing on the one surface a client watches live.
//
// A scope is therefore a QUESTION the policy asks every surface — "where do you report the difference between
// two readings?" — and each surface answers in its own vocabulary. See Sections for what happens when it does
// not answer at all.
type Scope string

// ScopeComparison is wherever a surface reports the difference between two readings.
//
// Shoalcheck reads two states minutes apart and does not watch a cluster, so it cannot know a finding was RESOLVED
// rather than merely absent, or that a dollar was SAVED rather than merely no longer in the estimate. Those
// words are legitimate elsewhere — a finding may describe a "resolved" DNS name — which is why the ban is
// scoped rather than absolute.
const ScopeComparison Scope = "comparison"

// ScopeCalendar is wherever a surface lists dated obligations — the report's "things with a clock" block.
//
// A date is a fact and urgency is the reader's: "critical", "act now", "urgent", "at risk" are opinions the date
// already implies, and a block that prints them is asserting something the reading cannot support (deadline-
// calendar spec §4.1, §5). Scoped, because "critical" is a severity this product prints everywhere else and
// "at risk" is legitimate prose in a finding's WhyItMatters.
const ScopeCalendar Scope = "calendar"

// WholeDocument is the marker a surface uses to say "this scope's region is my entire document".
//
// It is not a fallback and not an omission: it is an answer, and for some surfaces it is the honest one. The
// desktop app's theater is a live reading of a single moment with no prose in which "resolved" or "saved" could
// be innocent, so the comparison ban there covers everything — which is also the reach of the hand-rolled
// regexes it replaced.
const WholeDocument = ""

// Term is one word or phrase the product may not use as a claim.
type Term struct {
	// Text is the lowercase substring to look for.
	Text string
	// Why states the claim the word makes, so a violation teaches rather than merely forbids.
	Why string
	// Scope, when non-empty, narrows the ban to a named region of the document. Some of these words are
	// legitimate elsewhere: a finding may describe a "resolved" DNS name, and remediation prose may say a
	// request was "saved" from a retry.
	Scope Scope
	// WholeWord requires the hit to stand as its own word. It exists because the most dangerous claims are
	// short words that are also fragments of innocent ones: a bare "clean" on a chip is a verdict, while
	// "Storage cleanup" is a lever label, and a substring ban cannot tell them apart. Without this the table
	// could only reach multi-word phrases, which is exactly how a green chip reading "clean" slipped under a
	// ban on "clean audit".
	WholeWord bool

	// AllowNegated permits the word inside a negating construction, and it has to be permitted. The
	// disclaimer panel exists precisely to DENY these statuses — "not a certified audit", "not issued by a
	// QSA", "Nothing here constitutes an audit opinion" — and a gate that banned the word outright would
	// force the strongest honesty text in the document to be deleted or weaselled.
	AllowNegated bool
}

// Banned is the table. Adding a word here makes every surface's gate enforce it at once.
//
// IF YOU ADD OR REMOVE A TERM, TestBannedTable_TheCountIsWrittenDownInExactlyOnePlace fails and names every
// comment that quotes the size of this table. That is deliberate: this file's own comments have already drifted
// once, saying "four of the sixteen terms" when there were fifteen.
func Banned() []Term {
	return []Term{
		{Text: "notarized", Why: "a status conferred by a notary, which this document does not have", AllowNegated: true},
		{Text: "attestation", Why: "an attestation is issued by an accredited party; this is a reading", AllowNegated: true},
		{Text: "attested", Why: "we observed, we did not attest", AllowNegated: true},
		{Text: "certified", Why: "certification is conferred, never self-declared", AllowNegated: true},
		{Text: "certification", Why: "certification is conferred, never self-declared", AllowNegated: true},
		{Text: "clean audit", Why: "an absence of findings can come from an absence of data; there is no clean bill here"},
		{Text: "clean", WholeWord: true, AllowNegated: true,
			Why: "a verdict the reading cannot support: zero findings may mean zero problems or zero coverage"},
		{Text: "verified savings", Why: "savings are identified from a snapshot, never verified by us"},
		// The cover called its monthly figure "recoverable spend" while the headline beside it said the same figure was
		// "identified … upper bound if consolidated". An upper bound found in one snapshot is not recoverable
		// until somebody changes the cluster and the bill goes down; the word claimed the second half.
		{Text: "recoverable", WholeWord: true, AllowNegated: true,
			Why: "an upper bound identified from one snapshot; nothing is recovered until someone changes the cluster"},
		// From the second hand-rolled list, in the same script and applied to the comparison closer. The
		// table had "verified savings" and not this, so "we verified that the quota is gone" was policy
		// nowhere. Shoalcheck reads; a reading is not a verification.
		{Text: "we verified", Why: "we read a state at one moment; nothing was verified", AllowNegated: true},
		{Text: "realized savings", Why: "nothing is realized until someone changes the cluster and pays a smaller bill"},
		// NOT the stem. scripts/app-check.mjs had `/\bguarantee/i`, which is stricter than this, and moving
		// that reach into the table was tried: it fires on internal/rules/pss.go's WhyItMatters, which says
		// PodSecurity admission "turns securityContext hardening from a suggestion into a guarantee". That
		// sentence is about a KUBERNETES mechanism, not about what this audit promises, so it is arguably
		// honest — and the call is not the copy gate's to make on its own. Recorded as a pin, not decided:
		// see TestGuaranteeStem_IsNotBannedYet.
		{Text: "guaranteed", Why: "a guarantee is a promise about the future from a point-in-time reading", AllowNegated: true},
		// Also from the deleted JS list. Coverage is partial by construction — the honest CIS ceiling on a
		// managed cluster is 17 controls — so no surface may describe anything as fully compliant.
		{Text: "fully compliant", Why: "coverage is partial by construction; no run checks every control", AllowNegated: true},
		{Text: "no mutating verbs", Why: "the opt-in port-forward issues a create; the claim is zero OBJECT WRITES"},

		// Comparison vocabulary, banned in ScopeComparison only. Shoalcheck reads two states minutes apart and does
		// not watch a cluster, so it cannot know a finding was RESOLVED rather than merely absent.
		//
		// WholeWord on all four, because these are short words that live inside machinery. `toFixed` is a
		// JavaScript number formatter that appears five times in the desktop app's markup, and `prefixed`,
		// `unresolved` and `unsaved` are all words a document may legitimately contain. A gate that reports
		// `toFixed` as a dishonest claim gets switched off, which costs more than the words it was watching.
		{Text: "resolved", Scope: ScopeComparison, WholeWord: true, Why: "an absence in the second reading is not a fix"},
		{Text: "fixed", Scope: ScopeComparison, WholeWord: true, Why: "an absence in the second reading is not a fix"},
		{Text: "saved", Scope: ScopeComparison, WholeWord: true, Why: "identified is not saved"},
		{Text: "realized", Scope: ScopeComparison, WholeWord: true, Why: "identified is not realized"},

		// Urgency vocabulary, banned in ScopeCalendar only. The calendar block states dates; what a date calls
		// for is the reader's to decide, and a row that says "act now" has stopped reporting and started
		// advising. WholeWord on the single words for the same reason as above: "critical" is a severity enum
		// this product prints in every other section, and "urgent" could sit inside an identifier.
		{Text: "critical", Scope: ScopeCalendar, WholeWord: true, Why: "the date is the fact; urgency is the reader's"},
		{Text: "urgent", Scope: ScopeCalendar, WholeWord: true, Why: "the date is the fact; urgency is the reader's"},
		{Text: "act now", Scope: ScopeCalendar, Why: "the date is the fact; what to do about it is the reader's"},
		{Text: "at risk", Scope: ScopeCalendar, Why: "a date is not a risk assessment; the block states when, not what is at stake"},
		{Text: "expires soon", Scope: ScopeCalendar, Why: "\"soon\" is an opinion about a date the row already states exactly"},
	}
}

// Scopes returns every scope the table narrows a term to, in table order, without duplicates.
//
// It exists so a surface's test can assert it maps ALL of them: add a scope here and every surface fails until
// it says where that region is. Before this existed there was nothing anywhere that could notice a surface had
// never been asked.
func Scopes() []Scope {
	var out []Scope
	seen := map[Scope]bool{}
	for _, b := range Banned() {
		if b.Scope == "" || seen[b.Scope] {
			continue
		}
		seen[b.Scope] = true
		out = append(out, b.Scope)
	}
	return out
}

// Sections is what a surface knows about its OWN layout: for each Scope the policy narrows a term to, where
// that region is in this particular document.
//
// THE SECOND RETURN VALUE IS THE WHOLE REASON THIS TYPE EXISTS. Its predecessor was a func(string) string, and
// an empty string from it meant two irreconcilable things:
//
//	mapped == true, text == ""   "This document genuinely has no such region." Correct to skip — the golden
//	                             fixture has no previous run, so it renders no comparison strip at all.
//	mapped == false              "I have no idea what that region is called here." A hole in the policy, and
//	                             the caller must never treat it as an absence.
//
// The caller could not tell them apart, so it treated both as an absence and skipped. That is how the desktop
// app went unguarded: one surface's CSS class in a shared table, a resolver that did not recognise it, and
// silence. An absence must be ASSERTED, never assumed — the same rule this product applies to a denied read.
type Sections func(Scope) (text string, mapped bool)

// UnmappedScopes returns every scope in the table that sections does not map. A surface's test asserts this is
// empty; anything else means a ban has nowhere to be placed on that surface.
func UnmappedScopes(sections Sections) []Scope {
	var out []Scope
	for _, s := range Scopes() {
		if sections == nil {
			out = append(out, s)
			continue
		}
		if _, mapped := sections(s); !mapped {
			out = append(out, s)
		}
	}
	return out
}

// Regions locates scopes in one document by marker, so no surface has to write its own text slicer. Two of them
// already existed and one had a bug the other did not (see the note on the stylesheet below).
type Regions struct {
	// Doc is the document to slice: markup-bearing, so a class name in an attribute is still findable, and
	// MACHINERY-FREE, so the marker is not found first inside a stylesheet. Getting that order wrong is a
	// real bug this project shipped once: the first occurrence of `trend-strip` in a rendered report is the
	// CSS selector `.trend-strip`, hundreds of kilobytes before the markup, and slicing from there reported
	// two banned words out of CSS comments.
	Doc string
	// Window is how many bytes to take from each occurrence of a marker. Zero means 4000, which comfortably
	// covers the report's comparison strip.
	Window int
	// Plain reduces a slice of Doc to the reader text Scan requires — tags stripped, lowercased. nil means Doc
	// is already plain. It lives here so a caller cannot forget it: Scan's precondition is unenforceable from
	// inside Scan, and a caller that forgets gets a clean bill indistinguishable from a clean document.
	Plain func(string) string
	// Of maps each scope to the markers that START its region. A scope ABSENT from this map is unmapped, which
	// Scan treats as a policy hole rather than an absence. A scope mapped to {WholeDocument} means the whole
	// document is that region.
	Of map[Scope][]string
	// Until optionally names, per scope, the marker that ENDS a region: the slice from each start marker runs to
	// the first end marker after it, or Window bytes, whichever comes first. A region with no end marker is the
	// original behaviour — a fixed window — which is right for the comparison strip, whose length is bounded,
	// and wrong for a block whose length grows with the cluster: a window that overruns the block's end reads
	// the next section's severity badges as the block's own copy. The end marker must not contain the start
	// marker, or the end would start a region of its own.
	Until map[Scope]string
}

// defaultWindow covers the HTML report's comparison strip with room to spare.
const defaultWindow = 4000

// Sections builds the resolver.
func (r Regions) Sections() Sections {
	return func(s Scope) (string, bool) {
		markers, ok := r.Of[s]
		if !ok {
			return "", false
		}
		win := r.Window
		if win <= 0 {
			win = defaultWindow
		}
		var parts []string
		for _, m := range markers {
			if m == WholeDocument {
				parts = append(parts, r.Doc)
				continue
			}
			parts = append(parts, allSlicesBetween(r.Doc, m, r.Until[s], win)...)
		}
		return r.plain(strings.Join(parts, regionSeparator)), true
	}
}

func (r Regions) plain(s string) string {
	if r.Plain == nil {
		return s
	}
	return r.Plain(s)
}

// allSlicesBetween returns a window of s starting at EVERY occurrence of marker, each cut short at the first
// occurrence of until after its start when that comes before the window does. An empty until is no end marker.
//
// Every, not the first: a fleet document carries one comparison strip per cluster, and taking only the first
// meant the copy policy read cluster one and said nothing about clusters two through eleven.
//
// Written as code rather than as a regexp because RE2 caps a repeat count at 1000 and a comparison strip is
// longer than that — the third RE2 limit this project has walked into, after the missing backreference and the
// non-greedy match that leaked past nested tags.
func allSlicesBetween(s, marker, until string, window int) []string {
	if marker == "" {
		return nil
	}
	var out []string
	for i := 0; ; {
		j := strings.Index(s[i:], marker)
		if j < 0 {
			return out
		}
		at := i + j
		end := at + window
		if end > len(s) {
			end = len(s)
		}
		if until != "" {
			if k := strings.Index(s[at+len(marker):end], until); k >= 0 {
				end = at + len(marker) + k
			}
		}
		out = append(out, s[at:end])
		i = at + len(marker)
	}
}

// regionSeparator joins two disjoint regions of one document without letting a negator at the end of the first
// license a claim at the start of the second. It is longer than negationWindow and contains no negator.
var regionSeparator = strings.Repeat("| ", negationWindow)

// negators are the constructions that make a banned word a denial rather than a claim.
var negators = []string{
	"not ", "no ", "never ", "nothing ", "cannot ", "can not ", "does not ", "is not ", "are not ",
	"without ", "neither ", "nor ", "rather than ", "instead of ", "stop ", "banned", "may not ", "must not ",
}

// negationWindow is how far back a negation may sit. Deliberately generous: English puts it several clauses
// away ("It is not a certified audit and is not issued by..."), and a false ALLOW costs less than a false
// failure, which is what gets a gate loosened until it guards nothing.
const negationWindow = 90

// Negated reports whether the hit at index i sits inside a negating construction.
//
// A NEGATOR MUST BE A WORD. This used to be strings.Contains, and the negator list holds "no " and "nor " —
// so any word ending in "no" or "nor" followed by a space licensed every banned term for the next 90
// characters. "mono " contains "no "; "minor " contains "nor ". Neither is hypothetical in this product:
// --font-mono is written out in the stylesheet the report embeds, and "mono" appears in prose about tabular
// figures. `Scan("the mono column is clean")` returned no violation at all.
//
// The direction of the failure is what makes it serious. A false ALLOW is silent — the gate reports a clean
// document — and the enforcement point this package is about to gain runs on real output, where a false allow
// ships the claim instead of merely missing an assertion.
func Negated(text string, i int) bool {
	start := i - negationWindow
	if start < 0 {
		start = 0
	}
	before := text[start:i]
	for _, n := range negators {
		if containsWord(before, n) {
			return true
		}
	}
	return false
}

// containsWord reports whether n occurs in s on a word boundary.
//
// The leading boundary is always required. The trailing one is required only when the negator's own last
// character is part of a word: most of the list ends in a space, which IS the boundary, and demanding another
// one after it would reject "is not certified" — the space is consumed by the negator and the next character
// is the word being negated.
func containsWord(s, n string) bool {
	if n == "" {
		return false
	}
	trailingNeeded := isWordByte(n[len(n)-1])
	for i := 0; ; {
		j := strings.Index(s[i:], n)
		if j < 0 {
			return false
		}
		at := i + j
		i = at + len(n)
		if at > 0 && isWordByte(s[at-1]) {
			continue
		}
		if trailingNeeded {
			if end := at + len(n); end < len(s) && isWordByte(s[end]) {
				continue
			}
		}
		return true
	}
}

// isWordByte reports whether c continues a word for boundary purposes.
//
// '-' AND '_' COUNT, BECAUSE A KUBERNETES NAME IS DATA AND NOT COPY. Without them a hyphen reads as a word
// boundary, and the bare "clean" ban fired on every occurrence of a cluster named `clean-cluster` — 11 hits in
// one document, all of them the customer's own resource name echoed in the per-section identity strip. The
// runtime enforcement point found that on its first real run; the golden fixture could never have shown it,
// because its cluster is `acme-pay-prod`.
//
// This is the defining false-positive class for a gate that runs on real output: the document interpolates
// names, namespaces, labels and image references into its prose everywhere, and none of that is our claim. A
// noisy gate gets switched off, which costs more than the words it was watching.
//
// Only these two. '.' ':' '/' stay boundaries so "clean." at the end of a sentence is still a verdict and
// "registry/clean" is still reachable from its left side — a term is excluded only when an identifier
// character JOINS it to more of the same token.
func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// Violation is one un-negated use of a banned term, with enough surrounding text to find it.
type Violation struct {
	Term    Term
	Context string
	// Unscoped records that this hit came from scanning the WHOLE document because the surface did not map
	// the term's Scope. The hit is real and must be fixed; the wiring gap is also real and is reported with
	// it, because a scoped ban enforced document-wide is the strict fallback and not the ban the table wrote.
	Unscoped bool
	// Word is the maximal IDENTIFIER this hit sits inside: `clean` for a whole word, `cleanup` for a
	// fragment, `pci-certification-job` for a `certification` inside a name.
	//
	// It exists so a consumer can ask a question the term itself cannot answer — is this occurrence a name
	// the CLUSTER chose, rather than a claim this product wrote? A customer with a Deployment called `clean`
	// has that name printed into a diagram legend, and the ban is about our prose. Only report.ScanCopyForReading
	// uses it, and only to excuse a hit whose Word is exactly an object name in the reading.
	//
	// A multi-word term's Word contains the term's own space, so it can never equal a Kubernetes name. That
	// is deliberate: "clean audit" and "we verified" are sentences, never identifiers.
	Word string
}

// Detail is the sentence a consumer prints beside the word: the claim it makes, plus the wiring gap if the ban
// had nowhere to be placed. Consumers print this rather than Term.Why so the second half cannot be forgotten.
func (v Violation) Detail() string {
	if !v.Unscoped {
		return v.Term.Why
	}
	return v.Term.Why + " — and this term is scoped to the " + string(v.Term.Scope) + " region, which this " +
		"surface does not map, so the whole document was searched instead. Map the scope."
}

// Scan reports every un-negated use of a banned term in text. The text must already be PLAIN — tags stripped,
// lowercased — because what matters is what a human reads: a word can be removed from a variable name and still
// reach the reader through a template, and a source-level scan would fail on a comment explaining the ban.
//
// sections resolves a scoped term to the region it applies to. An UNMAPPED scope — including every scope when
// sections is nil — is scanned DOCUMENT-WIDE, never skipped. That direction is the whole point: skipping was
// silent, and a silent gate is the defect this package exists to prevent. Scanning wide can only over-report,
// it says so in Violation.Detail, and the fix is one line in the surface's own map.
func Scan(text string, sections Sections) []Violation {
	var out []Violation
	for _, b := range Banned() {
		haystack, unscoped := text, false
		if b.Scope != "" {
			region, mapped := "", false
			if sections != nil {
				region, mapped = sections(b.Scope)
			}
			switch {
			case !mapped:
				// The surface never said where this region is. Enforce everywhere and say why.
				unscoped = true
			case region == "":
				// The surface says this document has no such region. That is an answer, so honour it.
				continue
			default:
				haystack = region
			}
		}
		for i := 0; ; {
			j := strings.Index(haystack[i:], b.Text)
			if j < 0 {
				break
			}
			at := i + j
			if b.WholeWord && !standsAlone(haystack, at, len(b.Text)) {
				i = at + len(b.Text)
				continue
			}
			if !(b.AllowNegated && Negated(haystack, at)) {
				out = append(out, Violation{
					Term:     b,
					Context:  excerpt(haystack, at, len(b.Text)),
					Unscoped: unscoped,
					Word:     wordAt(haystack, at, len(b.Text)),
				})
			}
			i = at + len(b.Text)
		}
	}
	return out
}

// standsAlone reports whether the hit is a whole word rather than a fragment of a longer one.
func standsAlone(s string, at, n int) bool {
	if at > 0 && isWordByte(s[at-1]) {
		return false
	}
	if end := at + n; end < len(s) && isWordByte(s[end]) {
		return false
	}
	return true
}

// wordAt returns the maximal identifier around the hit — see Violation.Word.
//
// THE DOT IS PART OF A NAME AND ONLY THEN. A Kubernetes object may be called `foo.bar`, so the token has to
// be able to cross a dot; a sentence ending "…the cluster is clean." must not pick the dot up. So a dot
// extends the token only when an identifier byte is on its far side.
func wordAt(s string, at, n int) string {
	lo, hi := at, at+n
	for lo > 0 {
		switch c := s[lo-1]; {
		case isWordByte(c):
			lo--
			continue
		case c == '.' && lo >= 2 && isWordByte(s[lo-2]):
			lo -= 2
			continue
		}
		break
	}
	for hi < len(s) {
		switch c := s[hi]; {
		case isWordByte(c):
			hi++
			continue
		case c == '.' && hi+1 < len(s) && isWordByte(s[hi+1]):
			hi += 2
			continue
		}
		break
	}
	return s[lo:hi]
}

func excerpt(s string, at, n int) string {
	lo, hi := at-80, at+n+80
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
}
