package collect

import (
	"math"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type doubledPrices struct{ pricing.PriceProvider }

func (d doubledPrices) NodeMonthly(p, r, t string, c types.CapacityType) (pricing.PricePoint, bool) {
	pt, ok := d.PriceProvider.NodeMonthly(p, r, t, c)
	pt.Ceiling *= 2
	return pt, ok
}
func (d doubledPrices) LBMonthly(p, r string) (float64, bool) {
	v, ok := d.PriceProvider.LBMonthly(p, r)
	return v * 2, ok
}
func (d doubledPrices) ControlPlaneMonthly(p string) float64 {
	return 2 * d.PriceProvider.ControlPlaneMonthly(p)
}
func (d doubledPrices) VolumeMonthly(p, r, dt string, gib float64) (float64, string, bool) {
	v, b, ok := d.PriceProvider.VolumeMonthly(p, r, dt, gib)
	return v * 2, b, ok
}

// TestBuildReport_HeadlineFollowsTheProvider — the spend headline is built from the provider it was handed,
// every component of it. A component that reads the embedded table instead does not double, and the sum
// lands somewhere between 1x and 2x: that is the signature of a second price source on the page.
func TestBuildReport_HeadlineFollowsTheProvider(t *testing.T) {
	inv := twoM6iLargeEKS()
	inv.PVs = append(inv.PVs, pv("p1", "gp3", 200))
	base := BuildReport(inv, nil, "c", 0, pricing.Embedded()).Cluster
	twice := BuildReport(inv, nil, "c", 0, doubledPrices{pricing.Embedded()}).Cluster
	if base.EstimatedMonthlySpend <= 0 {
		t.Fatal("the fixture priced nothing, so this proves nothing")
	}
	if math.Abs(twice.EstimatedMonthlySpend-2*base.EstimatedMonthlySpend) > 0.01 {
		t.Errorf("spend $%.2f at embedded prices, $%.2f with every price doubled — want $%.2f; a component is "+
			"still reading the embedded table", base.EstimatedMonthlySpend, twice.EstimatedMonthlySpend, 2*base.EstimatedMonthlySpend)
	}
	if math.Abs(twice.StorageMonthlyUSD-2*base.StorageMonthlyUSD) > 0.01 {
		t.Errorf("storage $%.2f -> $%.2f, want doubled", base.StorageMonthlyUSD, twice.StorageMonthlyUSD)
	}
}
