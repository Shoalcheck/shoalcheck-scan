package types

import "testing"

// WHERE THE USAGE CAME FROM, IN WORDS. "metrics.k8s.io over instant" was the basis printed under a dr cluster's
// money (D50 product review): a window of "instant" is one moment, not a span anything is "over".
func TestUsageMethodology_BasisSaysWhatItRead(t *testing.T) {
	cases := []struct {
		u    *UsageMethodology
		want string
	}{
		{nil, ""},
		{&UsageMethodology{Source: "none"}, ""},
		{&UsageMethodology{Source: "prometheus", Window: "7d"}, "prometheus over 7d"},
		{&UsageMethodology{Source: "metrics.k8s.io", Window: "instant"}, "metrics.k8s.io at one moment"},
		{&UsageMethodology{Source: "vpa"}, "vpa over an unstated window"},
	}
	for _, c := range cases {
		if got := c.u.Basis(); got != c.want {
			t.Errorf("%+v: Basis() = %q, want %q", c.u, got, c.want)
		}
	}
}
