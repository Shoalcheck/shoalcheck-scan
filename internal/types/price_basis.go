package types

// PriceBasis records WHY a finding's DollarImpactMonthly is what it is, because the number alone cannot say.
//
// A zero in that field means three different things — a security finding with no cost dimension, a cost finding
// whose resource could not be priced, and a cost finding genuinely worth nothing — and every renderer that read
// the number alone had to guess. The cost chart guessed by dropping them, silently, which turned "we could not
// price this" into "this does not exist".
//
// Kept as a string rather than an integer enum so a report reads honestly in a text editor and an unknown value
// from a newer writer degrades to PriceUnknown rather than to whatever zero happens to mean.
type PriceBasis string

const (
	// PriceUnknown is the zero value and the state of every report written before this field existed. It is
	// NOT a synonym for any of the others: a renderer seeing it must decline to claim either way rather than
	// assume the common case.
	PriceUnknown PriceBasis = ""

	// PricePriced: the dollar figure is a real estimate from a real rate. Only these belong in a money total.
	PricePriced PriceBasis = "priced"

	// PriceUnpriced: this finding has a cost dimension and we could not price it — no rate for the region, no
	// rate for the instance type, or no usage reading to size it from. Counted, never summed.
	PriceUnpriced PriceBasis = "unpriced"

	// PriceNotCost: this finding has no cost dimension at all. A security check is not a pricing failure, and
	// counting it as one invents a coverage gap out of a finding that never had a price to begin with.
	PriceNotCost PriceBasis = "not-cost"
)

// IsCost reports whether this basis describes a finding that belongs in the cost instruments at all.
func (p PriceBasis) IsCost() bool { return p == PricePriced || p == PriceUnpriced }

// DollarsAreAMeasurement reports whether a reading's money total may be printed as a figure.
//
// A ZERO MEANS TWO DIFFERENT THINGS AND THE NUMBER CANNOT SAY WHICH — which is this file's whole subject, one
// level up from a single finding. A non-zero total came from findings that priced, so it is real whatever
// else failed. A zero is honest ONLY when nothing failed to price: one PriceUnpriced finding makes it an
// absence of knowledge rather than an absence of savings.
//
// IT LIVES HERE BECAUSE THREE RENDERERS ASK IT. The document, the run panel and the queue each printed
// "$0/mo" on a live reading of a cluster the price table does not cover, and each was fixed separately —
// which is how the third one was still wrong after the first two. A rule three surfaces must agree on is not
// a rule any of them owns.
// DollarsAreAMeasurementForReading is the same question asked of a whole reading, which is the only place
// the COVERAGE can be seen.
//
// The findings loop below asks whether any finding failed to price. Over a reading that collected no
// resource kind at all there ARE no findings, so the loop passes vacuously and the rule answers true — the
// gate-over-an-empty-set shape, inside the rule itself. Measured by opening a total-denial reading in the
// app window: 0 findings, 0 collected kinds, 20 denied, and /api/queue answered
// {"findings":0,"dollars":0,"dollarsPriced":true}, so the header printed "$0/mo" over a cluster nothing had
// ever connected to.
//
// A reading that read nothing has no money answer of any kind. A reading that read its kinds and found
// nothing cost-bearing has a measured zero, and this must not take that away — the two are distinguished by
// whether anything was collected, not by the finding count.
func DollarsAreAMeasurementForReading(ar *AuditReport) bool {
	if ar == nil {
		return false
	}
	// THE ASYMMETRY THIS FILE IS BUILT ON, AND THE FIRST VERSION OF THIS FUNCTION BROKE IT: never invent a
	// figure that was not measured, and NEVER DISCARD ONE THE READING CARRIES. A positive total came from
	// findings that priced, so it is real whatever the coverage looks like — and the coverage question is
	// only ever about a zero. Caught by TestBuildQueue_CarriesWhetherTheReadingPriced, whose fixture is a
	// $412 reading that records no collected kinds.
	if ar.Summary.EstimatedSavingsUSD > 0 {
		return true
	}
	// A ZERO IS ONLY A MEASUREMENT OVER A READING THAT READ WHAT A COST FINDING COMES FROM. Two ways it
	// cannot have: nothing was collected at all, or something was refused — and a refused kind is exactly
	// where the missing finding would have been. This is the same claim the empty-state sentence already
	// declines to make in words: "No findings in what could be read. Some resource kinds were not read at
	// all, so nothing is claimed about them."
	//
	// Measured on the readings on this machine: `limited` collected one kind of twenty-three and reported
	// a priced zero through /api/queue, so the window's header offered "$0/mo" for a cluster it had read
	// almost none of.
	if len(ar.Methodology.CollectedKinds) == 0 || len(ar.Methodology.DeniedKinds) > 0 {
		return false
	}
	// AND A COMPLETE READ IS NOT A COMPLETE PRICING. A reading can collect every kind it asked for and
	// still have no rate for the machines it found — an uncovered region, a machine type the table does not
	// carry — and then "we looked and there is nothing to save" rests on a price table that could not price
	// the cluster. Measured on 2026-09-15 against the state family: the terminal's cost tab printed
	// "$0.00/mo identified · … · the sum of every finding's figure" over a reading carrying a node pool
	// with no rate at all. This is M-88's fleet sentence one level down: nothing priceable does not read as
	// free.
	if ar.Architecture != nil &&
		(len(ar.Architecture.UnpricedNodeTypes) > 0 || len(ar.Architecture.UnpricedStorageClasses) > 0) {
		return false
	}
	return DollarsAreAMeasurement(ar.Summary.EstimatedSavingsUSD, ar.Findings)
}

func DollarsAreAMeasurement(total float64, findings []Finding) bool {
	if total > 0 {
		return true
	}
	for i := range findings {
		if findings[i].PriceBasis == PriceUnpriced {
			return false
		}
	}
	return true
}

// SpendKind says WHAT a dollar is a dollar OF. It exists because a commitment discount does not apply to
// money in general — an EC2 Savings Plan or Reserved Instance covers compute hours and nothing else — so a
// flat multiplier on the savings total is wrong in a specific, silent way: it discounts storage, load
// balancers and control-plane fees that no compute commitment ever touched.
//
// Closed, string-valued for the same reasons PriceBasis is, and required on any finding that carries a
// non-zero DollarImpactMonthly (TestGolden_EveryDollarSaysWhatItIsADollarOf). A renderer never needs it;
// assemble needs it once, to decide which dollars a --discount reaches.
type SpendKind string

const (
	// SpendUnknown is the zero value: the finding said nothing. It is never treated as compute, so a rule
	// that forgets to declare its kind is left AT LIST — the discount is withheld from it, never applied to
	// it — and the fixture gate names the rule.
	SpendUnknown SpendKind = ""
	// SpendCompute: node or instance hours. The ONLY kind a --discount scales.
	SpendCompute SpendKind = "compute"
	// SpendStorage: provisioned GB-month. Billed at list regardless of any compute commitment.
	SpendStorage SpendKind = "storage"
	// SpendNetwork: load-balancer hours, egress, inter-zone transfer. At list.
	SpendNetwork SpendKind = "network"
	// SpendControlPlane: per-cluster hours — the ordinary fee and any support surcharge. At list.
	SpendControlPlane SpendKind = "control-plane"
)
