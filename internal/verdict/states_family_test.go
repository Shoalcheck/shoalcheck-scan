package verdict

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/fixture/states"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
	"github.com/Shoalcheck/shoalcheck-scan/internal/view"
)

// THE CI GATE'S SELECTION FACES THE FAMILY.
//
// Selection.TotalDollars must equal the reading's own headline, and a CI job reads it with nothing else
// beside it. A zero there is the same claim as a zero on the cover, made where nobody is looking.
func TestStates_TheSelectionFacesTheWholeFamily(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(states.All()); n < 6 {
		t.Fatalf("the registry holds %d state in the family(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	for _, st := range states.All() {
		t.Run(st.Name, func(t *testing.T) {
			ar := states.Base()
			st.Build(ar)
			sel := Select(ar.Findings, 5)

			if sel.TotalDollars != ar.Summary.EstimatedSavingsUSD {
				t.Errorf("the selection totals $%.2f and the reading's headline is $%.2f: a CI job "+
					"comparing the two reads a movement nobody made", sel.TotalDollars,
					ar.Summary.EstimatedSavingsUSD)
			}
			if err := states.AssertTotal(st.Name, sel.TotalDollars, basisWord(ar)); err != nil {
				t.Errorf("%s\n  what a reader would be told wrongly: %s", err, st.Why)
			}
		})
	}
}

// basisWord is the reading's own vocabulary for what kind of number the total is, taken from the one
// projection rather than decided here.
func basisWord(ar *types.AuditReport) string {
	switch view.Of(ar).Totals.SavingsShape {
	case view.MoneyFigure:
		if len(ar.Findings) == 0 && ar.Summary.EstimatedSavingsUSD == 0 {
			return string(types.PriceNotCost)
		}
		return string(types.PricePriced)
	case view.MoneyUnpriced:
		for _, f := range ar.Findings {
			if f.PriceBasis == types.PriceUnpriced {
				return string(types.PriceUnpriced)
			}
		}
		return string(types.PriceUnknown)
	default:
		return string(types.PriceUnknown)
	}
}
