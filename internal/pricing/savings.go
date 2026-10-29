package pricing

// SavingsPlanHourly returns the Compute Savings Plan rate — No Upfront, Linux shared tenancy — for an AWS
// instance type in a region, for term "1yr" or "3yr". ok=false for anything the table does not carry.
//
// THE CONSERVATIVE PAIR, and why it stays conservative: the flexible Compute plan discounts less than an
// EC2 Instance plan, and the finding that reads this refuses to bank the figure at all. A rate that errs
// low keeps that would-be number an upper bound in the same direction as every other figure in the report.
func SavingsPlanHourly(region, term, instanceType string) (float64, bool) {
	byTerm, ok := awsSavingsPlanHourlyUSD[region]
	if !ok {
		return 0, false
	}
	rates, ok := byTerm[term]
	if !ok {
		return 0, false
	}
	usd, ok := rates[instanceType]
	return usd, ok && usd > 0
}
