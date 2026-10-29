package pipeline

import "github.com/Shoalcheck/shoalcheck-scan/internal/types"

// classifyPriceBasis records, on every finding, WHY its dollar figure is what it is.
//
// A zero in DollarImpactMonthly means three different things — a security finding with no cost dimension, a
// cost finding whose resource could not be priced, and a cost finding genuinely worth nothing — and until this
// ran, every renderer downstream had to guess from the number alone. The cost chart guessed by dropping them
// silently, which turned "we could not price this" into "this does not exist" for 18 of 24 findings.
//
// ONE PLACE, AND AFTER THE RULES HAVE RUN. Asking each of the twenty-odd rules to set the field would give
// twenty places for it to be forgotten, and a forgotten one is indistinguishable from an honest "not-cost".
// Derived instead from two facts the rules already state: the finding's Category and its dollar figure.
//
// A rule that sets the field explicitly wins. That matters for the case this derivation cannot see — a cost
// rule that priced something at a true zero, which is neither unpriced nor non-cost — and the field is left
// alone wherever a rule has already spoken.
func classifyPriceBasis(findings []types.Finding) {
	for i := range findings {
		f := &findings[i]
		if f.PriceBasis != types.PriceUnknown {
			continue
		}
		switch {
		case f.DollarImpactMonthly > 0:
			f.PriceBasis = types.PricePriced
		case f.Category == types.CategoryCost:
			// A cost rule that produced no dollars did not find a free problem; it failed to price one.
			f.PriceBasis = types.PriceUnpriced
		default:
			f.PriceBasis = types.PriceNotCost
		}
	}
}
