package pricing

// Shape is an instance type's machine shape as the provider publishes it: vCPU count and memory in GiB.
//
// It is the guard that makes "a cheaper equivalent type" a defensible sentence. Equivalent means the same
// vCPU and at least the memory; without a published shape for BOTH ends, a rule can only compare names,
// and names lie — "m7i-flex.xlarge" shares a size label with "m6i.xlarge" and is not the same machine.
type Shape struct {
	VCPU   float64
	MemGiB float64
}

// NodeShape returns the published shape of an instance type, and ok=false when this build's table has none.
// AWS only today: it is the one provider whose catalogue source (ec2.shop) reports shapes beside prices.
// A false here means "do not propose this type", never "assume it matches".
func NodeShape(provider, instanceType string) (Shape, bool) {
	if normalizeProvider(provider) != "aws" {
		return Shape{}, false
	}
	s, ok := awsNodeShape[instanceType]
	return s, ok
}

// TypesInRegion lists every instance type this build prices for a provider's region, in no particular
// order. Empty for an uncovered region.
func TypesInRegion(provider, region string) []string {
	byType, ok := nodeHourlyUSD[normalizeProvider(provider)][region]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(byType))
	for t := range byType {
		out = append(out, t)
	}
	return out
}
