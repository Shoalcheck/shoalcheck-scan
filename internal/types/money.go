package types

import (
	"fmt"
	"strings"
)

// USD renders a dollar figure the one way the report accepts it: grouped thousands, two decimals.
//
// THE PROPERTY IS A GATE, NOT A STYLE. TestRender_NoUngroupedDollars scans the whole rendered document
// for a "$" followed by four or more digits; a rule whose evidence prints a pool total with %.2f passes
// that gate only while the pool is small. Rule copy that carries a figure a reader could sum goes
// through here, so the figure reads the same in the evidence as in the headline.
func USD(v float64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := fmt.Sprintf("%.2f", v) // "1511.10"
	whole, cents := s[:len(s)-3], s[len(s)-3:]
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	b.WriteByte('$')
	pre := len(whole) % 3
	if pre > 0 {
		b.WriteString(whole[:pre])
		if len(whole) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(whole); i += 3 {
		b.WriteString(whole[i : i+3])
		if i+3 < len(whole) {
			b.WriteByte(',')
		}
	}
	b.WriteString(cents)
	return b.String()
}
