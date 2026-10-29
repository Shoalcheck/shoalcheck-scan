package history

import (
	"fmt"
	"strings"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/lexicon"
)

// Sentence is the printable form of a state. The four are the whole vocabulary of this surface; "resolved",
// "fixed", "saved" and "realized" are banned in the comparison scope and would fail
// TestTimeline_ClearsTheComparisonScope.
func (k StateKind) Sentence() string {
	switch k {
	case StatePresent:
		return "present"
	case StateAbsent:
		return "absent from this reading"
	case StateNotReadable:
		return "not readable"
	case StateRuleChanged:
		return "present under a changed rule"
	}
	return string(k)
}

// TimelineSections maps the whole text to the comparison scope: everything this surface prints is a statement
// about two or more readings. Every scope is mapped so UnmappedScopes stays empty — an unmapped scope is a hole
// in the policy, not an absence.
func TimelineSections(text string) lexicon.Sections {
	return func(s lexicon.Scope) (string, bool) {
		if s == lexicon.ScopeComparison {
			return text, true
		}
		return "", true
	}
}

// coverageNote is what the finding count on a timeline row rests on, or "" when the run read every kind it
// asked for. Only the shortfall is printed: a marker on every row is a marker nobody reads.
func coverageNote(r Reading) string {
	switch {
	case r.ReadNothing():
		return fmt.Sprintf(" · nothing could be read (%d kind(s) refused)", r.Denied)
	case r.Denied > 0:
		return fmt.Sprintf(" · %d kind(s) not read", r.Denied)
	default:
		return ""
	}
}

// Text renders the timeline for a terminal: the readings as columns in recorded order, one row per finding,
// segments separated by the break's sentence. It states how many readings were looked at and how many exist.
func (tl Timeline) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %d of %d readings kept on this machine (oldest first)\n", tl.Cluster, len(tl.Readings), tl.Kept)
	for i, r := range tl.Readings {
		label := ""
		if r.Label != "" {
			label = fmt.Sprintf("  %q", r.Label)
		}
		// THE COUNT CARRIES ITS COVERAGE. "0 findings" over a reading where no resource list succeeded is
		// the same sentence a clean cluster prints, and a column of them reads as a quiet fortnight.
		fmt.Fprintf(&b, "  [%d] %s  %d findings%s%s\n", i+1, r.At.UTC().Format(time.RFC3339), r.Findings,
			coverageNote(r), label)
	}
	for si, seg := range tl.Segments {
		if len(tl.Segments) > 1 {
			fmt.Fprintf(&b, "\nreadings %d–%d\n", seg.From+1, seg.To+1)
		} else {
			b.WriteString("\n")
		}
		for _, row := range tl.Rows {
			fmt.Fprintf(&b, "%-16s %-44s", row.FindingID, truncate(row.Title, 44))
			for k := seg.From; k <= seg.To; k++ {
				st := row.States[k]
				cell := st.Kind.Sentence()
				if st.Kind == StateRuleChanged {
					cell += " (" + st.RuleVersion + ")"
				}
				fmt.Fprintf(&b, "  [%d] %s", k+1, cell)
			}
			b.WriteString("\n")
		}
		// The reasons a cell was not readable, once each, so the table stays a table.
		seenReason := map[string]bool{}
		for _, row := range tl.Rows {
			for k := seg.From; k <= seg.To; k++ {
				if st := row.States[k]; st.Kind == StateNotReadable && !seenReason[st.Reason] {
					seenReason[st.Reason] = true
					fmt.Fprintf(&b, "  not readable in reading %d: %s\n", k+1, st.Reason)
				}
			}
		}
		if seg.BreakReason != "" && si < len(tl.Segments)-1 {
			fmt.Fprintf(&b, "\nreadings %d and %d were not compared: %s\n", seg.To+1, seg.To+2, seg.BreakReason)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
