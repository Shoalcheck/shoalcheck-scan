package types

import "testing"

// ONE RULE, BECAUSE THREE RENDERERS ASK IT.
//
// The document, the run panel and the queue each printed "$0/mo" on a live reading of a cluster the price
// table does not cover, and each was fixed separately — which is exactly how the third was still wrong after
// the first two. The rule moved here; these are the four states it has to tell apart.
func TestDollarsAreAMeasurement(t *testing.T) {
	cost := func(b PriceBasis) Finding { return Finding{Category: CategoryCost, PriceBasis: b} }
	for _, tc := range []struct {
		name     string
		total    float64
		findings []Finding
		want     bool
		why      string
	}{
		{"a non-zero total is real whatever else failed", 412,
			[]Finding{cost(PricePriced), cost(PriceUnpriced)}, true,
			"replacing a measured dollar with \"unpriced\" discards a figure, which is the opposite defect"},
		{"zero with a finding that failed to price is an absence of knowledge", 0,
			[]Finding{cost(PriceUnpriced)}, false,
			"the live state: one cost finding, no rate for its node type, and three surfaces reading $0/mo"},
		{"zero with nothing that failed to price is an honest zero", 0,
			[]Finding{{Category: CategorySecurity, PriceBasis: PriceNotCost}}, true,
			"a reading with no cost finding has genuinely identified nothing and may say so"},
		{"zero from a cost rule that priced a true zero is still a figure", 0,
			[]Finding{cost(PricePriced)}, true,
			"the rule priced it and the price was zero; that is a measurement, not a gap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DollarsAreAMeasurement(tc.total, tc.findings); got != tc.want {
				t.Errorf("= %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}
