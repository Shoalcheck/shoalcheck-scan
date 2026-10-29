package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The first engine consumer of the time axis: with earlier readings supplied, the commitment finding states in
// how many of them this pool, at this size, was present — observed states, never a rate, and still not banked.
func TestCommitment_StatesPresenceAcrossEarlierReadings(t *testing.T) {
	if _, ok := pricing.SavingsPlanHourly("eu-central-1", "1yr", "m6i.xlarge"); !ok {
		t.Skip("this build carries no Savings Plan rate for eu-central-1/m6i.xlarge")
	}
	inv := onDemand(awsPool("m6i.xlarge", 3))
	base := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	pool := func(n int) []PriorPool {
		return []PriorPool{{Type: "m6i.xlarge", Capacity: types.CapacityOnDemand, Count: n}}
	}
	opts := Options{PriorReadings: []PriorReading{
		{At: base.AddDate(0, 0, 28), Pools: pool(3)}, // given newest-first on purpose: the line sorts by time
		{At: base, Pools: pool(3)},
		{At: base.AddDate(0, 0, 7), Pools: pool(2)}, // a different size is a different footprint
		{At: base.AddDate(0, 0, 14), Pools: pool(3)},
	}}
	got := CommitmentCandidate{}.Evaluate(inv, opts)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	ev := strings.Join(got[0].Evidence, "\n")
	want := "a pool of 3 m6i.xlarge on-demand nodes was present in 3 of the 4 earlier readings kept on this machine (Jul 14, 2026 – Aug 11, 2026)"
	if !strings.Contains(ev, want) {
		t.Errorf("evidence lacks %q:\n%s", want, ev)
	}
	if got[0].DollarImpactMonthly != 0 {
		t.Error("history moved the dollar — the figure stays unbanked whatever the footprint did")
	}
	// The bans are checked on the steadiness line itself: the finding's other evidence legitimately prints a
	// price difference in percent and an hourly rate per node.
	var steadiness string
	for _, e := range got[0].Evidence {
		if strings.Contains(e, "earlier reading") {
			steadiness = e
		}
	}
	for _, banned := range []string{"%", " per ", "trend", "steady", "stable", "rate of"} {
		if strings.Contains(strings.ToLower(steadiness), banned) {
			t.Errorf("the steadiness line says %q — a rate or a verdict, not an observed state", banned)
		}
	}
	// Without earlier readings the line is absent, not "0 of 0".
	none := CommitmentCandidate{}.Evaluate(inv, Options{})
	if strings.Contains(strings.Join(none[0].Evidence, "\n"), "earlier reading") {
		t.Error("a finding with no history claims something about earlier readings")
	}
}
