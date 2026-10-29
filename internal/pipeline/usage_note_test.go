package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// THE SENTENCE THAT QUALIFIES EVERY CONSUMPTION FIGURE MUST NOT BE MALFORMED.
//
// Measured on the shipped golden document:
//
//	Usage: metrics.k8s.io (, window instant) — 28 container series — caveats: …
//
// A leading comma and an empty first element, inside a parenthetical, on the methodology line every
// rightsizing figure in the document rests on. The cause is one format string that assumed
// UsageMethodology.Backend is always set: it is the resolved Prometheus FLAVOUR — thanos, mimir, amp, gmp,
// victoria-metrics — and is empty for every other tier, which is metrics.k8s.io and VPA. So it shipped on
// every non-Prometheus reading, and the golden is one.
//
// The parenthetical is now built from the parts that exist. A detail that is absent is not printed as an
// empty slot beside a comma — the same rule the money cells took in M-53: an absence is not a value.
func TestUsageNote_OmitsAnAbsentBackend(t *testing.T) {
	cases := []struct {
		name    string
		m       types.UsageMethodology
		series  int
		want    string
		notWant []string
	}{
		{
			name:    "no backend flavour — metrics.k8s.io, the golden's own tier",
			m:       types.UsageMethodology{Source: "metrics.k8s.io", Window: "instant"},
			series:  28,
			want:    "Usage: metrics.k8s.io (window instant) — 28 container series",
			notWant: []string{"(,", ", window instant)"},
		},
		{
			name:   "a resolved flavour is named",
			m:      types.UsageMethodology{Source: "prometheus", Backend: "thanos", Window: "7d"},
			series: 1904,
			want:   "Usage: prometheus (thanos, window 7d) — 1904 container series",
		},
		{
			name:    "no window either — nothing is printed as an empty slot",
			m:       types.UsageMethodology{Source: "vpa"},
			series:  3,
			want:    "Usage: vpa — 3 container series",
			notWant: []string{"()", "(,", "window )"},
		},
		{
			name:   "caveats travel after the parenthetical, not inside it",
			m:      types.UsageMethodology{Source: "metrics.k8s.io", Window: "instant", Caveats: []string{"an instantaneous snapshot"}},
			series: 28,
			want:   "Usage: metrics.k8s.io (window instant) — 28 container series — caveats: an instantaneous snapshot",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := usageNote(tc.m, tc.series)
			if got != tc.want {
				t.Errorf("usageNote =\n  %q\nwant\n  %q", got, tc.want)
			}
			for _, bad := range tc.notWant {
				if strings.Contains(got, bad) {
					t.Errorf("usageNote contains %q — an absent detail printed as an empty slot: %q", bad, got)
				}
			}
		})
	}
}
