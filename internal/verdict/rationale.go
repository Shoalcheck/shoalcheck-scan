package verdict

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Rationale explains why this finding leads, assembled ONLY from fields the finding already
// carries. Nothing here writes prose about a cluster: every clause is either a field, a count
// of fields, or a fixed connective.
//
// The rule is not stylistic. A generated explanation is indistinguishable, to a reader, from
// a measured one — so an invented sentence in the "start here" block is the same class of
// defect as an invented dollar, and harder to catch. TestRationale_EveryClaimTracesToASourceField
// enforces it.
//
// It also carries NO formatted currency, deliberately. This package cannot import
// internal/report (dependency direction) so any money string baked in here would be a second,
// drifting implementation of a format the report owns — the report groups thousands and drops
// cents, the theater has its own style, and the report's TestRender_NoUngroupedDollars exists to
// catch exactly that escape. The layer states facts; each surface formats them from
// Finding.DollarImpactMonthly, which every card already has.
func Rationale(r Ranked) string { return rationale(r, true) }

// RationaleWithoutWhy is Rationale for a surface that has ALREADY printed the finding's why-it-matters in
// full — the detail view, and anything built on it.
//
// The clause it drops is the one Rationale is right to carry: on a podium the reader has not seen the
// finding, and its own words are the strongest thing that can be said about why it leads. In a detail the
// reader has just read the whole field, and repeating its first sentence twenty lines later prints one
// thought twice under two headings whose whole purpose is to differ. Measured on the golden before the
// split: 22 of 137 details did exactly that.
//
// internal/rules/rbac_grants.go records the same defect one surface along, with the same remedy.
func RationaleWithoutWhy(r Ranked) string { return rationale(r, false) }

func rationale(r Ranked, includeWhy bool) string {
	f := r.Finding
	var parts []string

	// 0. The band, when the band is the reason. Under band-first ranking a medium can lead a high, and a
	// podium that does not say why reads as a broken sort. The label is TierOf's — derived from the
	// finding's pillar, severity and dollars, never written here — and it is omitted for critical, money and
	// posture, where the severity or the dollar figure beside the card already is the reason.
	t := r.Tier
	if t == tierUnset {
		t = TierOf(f)
	}
	switch t {
	case TierNow, TierNextChange, TierMonitoring, TierConditional:
		parts = append(parts, t.Label())
	}

	// 1. Reach — counted, never characterised.
	if n := len(f.AffectedResources); n > 0 {
		if ns := distinctNamespaces(f.AffectedResources); len(ns) > 1 {
			parts = append(parts, fmt.Sprintf("%d resources across %d namespaces", n, len(ns)))
		} else {
			parts = append(parts, fmt.Sprintf("%d %s", n, plural(n, "resource", "resources")))
		}
	}

	// 2. How safe it is to start with — the whole point of putting it first.
	switch r.Safety {
	case SafeNow:
		parts = append(parts, "remediation is additive and does not restart workloads")
	case NeedsReview:
		parts = append(parts, "remediation exists but restarts or reroutes — review before applying")
	case Manual:
		parts = append(parts, "no mechanical remediation — needs a person")
	}

	// 3. Effort, as the finding itself estimated it.
	switch f.EstimatedEffort {
	case types.EffortLow:
		parts = append(parts, "under 30 minutes")
	case types.EffortHigh:
		parts = append(parts, "over 4 hours")
	}

	// 4. The finding's own words on why it matters, verbatim and trimmed at a sentence — for the surfaces
	// that have not already printed the whole field. See RationaleWithoutWhy.
	if includeWhy {
		if w := firstSentence(f.WhyItMatters); w != "" {
			parts = append(parts, w)
		}
	}

	return strings.Join(parts, " · ")
}

// distinctNamespaces counts namespaces present in the affected set, ignoring cluster-scoped
// resources which carry none.
func distinctNamespaces(refs []types.ResourceRef) []string {
	seen := map[string]bool{}
	for _, r := range refs {
		if r.Namespace != "" {
			seen[r.Namespace] = true
		}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// firstSentence returns the finding's own leading sentence, unchanged. It never rewrites,
// summarises or paraphrases — the only transformation permitted is a cut.
//
// The cut must not land inside a number. An earlier version split on the first ".!?" and turned
// "the burst peaks at 1.4 vCPU per pod" into "the burst peaks at 1" on a rendered report (B-009).
// Truncated prose is a cosmetic loss; a truncated number is a changed value, and it arrived
// through the one clause of the rationale that exists to be verbatim.
//
// A terminator therefore only ends the sentence when it is followed by whitespace or the end of
// the string — which also leaves "1.2.3" and "12.5ms" intact.
// SummaryLine is why a finding matters, in its own words, as one line of at most max runes: the first
// sentence of WhyItMatters (or of Description when that is empty), cut at a word with an ellipsis when it is
// longer. It is what a "fix first" row says under its title — the finding's reason, not the ranking's.
func SummaryLine(f types.Finding, max int) string {
	s := firstSentence(f.WhyItMatters)
	if s == "" {
		s = firstSentence(f.Description)
	}
	s = strings.Join(strings.Fields(s), " ")
	if max <= 1 || utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)[:max-1]
	cut := len(r)
	for i := len(r) - 1; i > max/2; i-- {
		if unicode.IsSpace(r[i]) {
			cut = i
			break
		}
	}
	return strings.TrimRight(string(r[:cut]), " ,;:·—-") + "…"
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i, r := range s {
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		if i == 0 {
			continue
		}
		rest := s[i+utf8.RuneLen(r):]
		if rest == "" {
			// A trailing terminator is punctuation, not a boundary worth cutting at; a
			// trailing decimal point would be malformed input either way.
			break
		}
		if next, _ := utf8.DecodeRuneInString(rest); unicode.IsSpace(next) {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
