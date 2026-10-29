package pipeline

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A FIELD NOTHING POPULATES IS WORSE THAN NO FIELD, because a renderer reading it gets a confident-looking
// zero-value answer. This is the ratchet: every finding leaving the pipeline carries a basis.
func TestClassifyPriceBasis_EveryFindingLeavesWithOne(t *testing.T) {
	in := []types.Finding{
		{ID: "priced", Category: types.CategoryCost, DollarImpactMonthly: 42},
		{ID: "unpriceable", Category: types.CategoryCost},
		{ID: "security", Category: types.CategorySecurity},
		{ID: "reliability", Category: types.CategoryReliability},
		{ID: "already-said", Category: types.CategoryCost, PriceBasis: types.PriceNotCost},
	}
	classifyPriceBasis(in)

	want := map[string]types.PriceBasis{
		"priced":      types.PricePriced,
		"unpriceable": types.PriceUnpriced,
		"security":    types.PriceNotCost,
		"reliability": types.PriceNotCost,
		// An explicit value survives: this is the case the derivation cannot see — a cost rule that priced
		// something at a true zero, which is neither unpriced nor non-cost.
		"already-said": types.PriceNotCost,
	}
	for _, f := range in {
		if f.PriceBasis == types.PriceUnknown {
			t.Errorf("%s left the pipeline with no price basis; a renderer reading it cannot tell a security "+
				"finding from one we failed to price", f.ID)
		}
		if got := f.PriceBasis; got != want[f.ID] {
			t.Errorf("%s: basis %q, want %q", f.ID, got, want[f.ID])
		}
	}
}

// The distinction that makes the count meaningful: a security finding is not a pricing failure.
func TestClassifyPriceBasis_ASecurityFindingIsNotAPricingGap(t *testing.T) {
	in := []types.Finding{{ID: "root", Category: types.CategorySecurity}}
	classifyPriceBasis(in)
	if in[0].PriceBasis == types.PriceUnpriced {
		t.Error("a security finding was classified as unpriced, which invents a pricing coverage gap out of " +
			"a finding that never had a price")
	}
}
