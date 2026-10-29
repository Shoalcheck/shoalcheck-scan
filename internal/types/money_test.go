package types

import (
	"regexp"
	"testing"
)

func TestUSD_GroupsThousandsAndKeepsCents(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0, "$0.00"}, {167.9, "$167.90"}, {999.999, "$1,000.00"}, {1511.1, "$1,511.10"},
		{2663.04, "$2,663.04"}, {1234567.891, "$1,234,567.89"}, {-2663.04, "-$2,663.04"},
	} {
		if got := USD(tc.in); got != tc.want {
			t.Errorf("USD(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestUSD_NeverPrintsFourDigitsUnbroken is the report gate's property, held at the source.
func TestUSD_NeverPrintsFourDigitsUnbroken(t *testing.T) {
	ungrouped := regexp.MustCompile(`\$[0-9]{4,}`)
	for v := 1.0; v < 1e10; v *= 1.7 {
		if s := USD(v); ungrouped.MatchString(s) {
			t.Fatalf("USD(%v) = %q would fail TestRender_NoUngroupedDollars", v, s)
		}
	}
}
