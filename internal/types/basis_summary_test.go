package types

import "testing"

// A RULE THAT READS TELEMETRY AND NO OBJECT HAS A BASIS, AND THE SUMMARY SAYS WHICH. Alerts firing and scrape
// targets down rest on the cluster's own Prometheus series and on no object kind; the summary read "basis · not
// recorded · usage from prometheus" — a recorded basis printed as a missing one, in the CLI's findings, the app,
// the terminal session and every ticket. "not recorded" is kept for the state it names: a basis with nothing in it.
func TestFindingBasis_SummaryNamesATelemetryBasis(t *testing.T) {
	for _, c := range []struct {
		b    FindingBasis
		want string
	}{
		{FindingBasis{UsageRequired: true, UsageSource: "prometheus"}, "basis · no object kind, telemetry only · usage from prometheus"},
		{FindingBasis{}, "basis · not recorded"},
		{FindingBasis{Kinds: []string{"pods"}, UsageRequired: true, UsageSource: "prometheus"}, "basis · 1 kind, all read · usage from prometheus"},
		{FindingBasis{UsageRequired: true}, "basis · not recorded · usage source not recorded"},
	} {
		if got := c.b.Summary(); got != c.want {
			t.Errorf("%+v summarises as %q, want %q", c.b, got, c.want)
		}
	}
}
