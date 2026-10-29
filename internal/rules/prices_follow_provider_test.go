package rules

import (
	"math"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// doubled is a PriceProvider that returns twice every figure the embedded snapshot would. It is the whole
// test: if a rule reaches a price through Options.Prices, its dollar doubles; if it still reaches the
// package-level tables, it does not — and that rule is pricing the cluster from a table the run did not
// resolve, which is the defect this file exists to keep out.
type doubled struct{ pricing.PriceProvider }

func (d doubled) NodeMonthly(p, r, t string, c types.CapacityType) (pricing.PricePoint, bool) {
	pt, ok := d.PriceProvider.NodeMonthly(p, r, t, c)
	pt.Ceiling *= 2
	pt.Floor *= 2
	return pt, ok
}
func (d doubled) StorageMonthlyPerGB(p, r, dt string) (float64, bool) {
	v, ok := d.PriceProvider.StorageMonthlyPerGB(p, r, dt)
	return v * 2, ok
}
func (d doubled) LBMonthly(p, r string) (float64, bool) {
	v, ok := d.PriceProvider.LBMonthly(p, r)
	return v * 2, ok
}
func (d doubled) VolumeMonthly(p, r, dt string, gib float64) (float64, string, bool) {
	v, b, ok := d.PriceProvider.VolumeMonthly(p, r, dt, gib)
	return v * 2, b, ok
}
func (d doubled) ExtendedSupportHourly(p string) (float64, bool) {
	v, ok := d.PriceProvider.ExtendedSupportHourly(p)
	return v * 2, ok
}

func dollarsOf(fs []types.Finding) float64 {
	var t float64
	for _, f := range fs {
		t += f.DollarImpactMonthly
	}
	return t
}

// TestEveryRuleDollarFollowsTheProvider runs each priced rule twice over the same inventory — once with the
// embedded snapshot, once with every price doubled — and expects every dollar to double. A rule whose dollar
// stands still has a second opinion about prices, and the cover and the findings would disagree.
func TestEveryRuleDollarFollowsTheProvider(t *testing.T) {
	two := doubled{pricing.Embedded()}
	w, ok := kubeversions.For("aws", "1.31")
	if !ok {
		t.Fatal("no aws/1.31 window")
	}
	gp2Inv := awsPool("m6i.xlarge", 1)
	gp2Inv.StorageClasses = append(gp2Inv.StorageClasses, awsClass("gp2", "gp2"))
	gp2Inv.PVs = append(gp2Inv.PVs, gp2PV("pv-a", "gp2", 100))
	cases := []struct {
		name string
		rule Rule
		inv  *collect.Inventory
	}{
		{"gp2-to-gp3", Gp2WhereGp3IsCheaper{}, gp2Inv},
		{"instance-generation-lag", InstanceGenerationLag{}, awsPool("t2.large", 2)},
		{"version-past-standard-support", VersionPastStandardSupport{},
			invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", day(w.StandardEnds).AddDate(0, 0, 1))},
	}
	for _, c := range cases {
		base := dollarsOf(c.rule.Evaluate(c.inv, Options{}))
		twice := dollarsOf(c.rule.Evaluate(c.inv, Options{Prices: two}))
		if base <= 0 {
			t.Fatalf("%s: the fixture produced no dollars, so this case would prove nothing", c.name)
		}
		if math.Abs(twice-2*base) > 0.01 {
			t.Errorf("%s: $%.2f at embedded prices, $%.2f with every price doubled — want $%.2f. The rule is not "+
				"reading its price through Options.Prices", c.name, base, twice, 2*base)
		}
	}
}
