package pricing

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func TestEmbeddedProviderNodeParity(t *testing.T) {
	p := Embedded()
	// On-demand: PricePoint.Ceiling equals the package func, source=list-estimate.
	want, ok := NodeMonthlyUSD("aws", "eu-central-1", "m6i.large", types.CapacityOnDemand)
	if !ok {
		t.Fatal("fixture: m6i.large/eu-central-1 must be priced")
	}
	pt, ok := p.NodeMonthly("aws", "eu-central-1", "m6i.large", types.CapacityOnDemand)
	if !ok || pt.Ceiling != want || pt.Source != types.CostSourceListEstimate {
		t.Errorf("NodeMonthly on-demand = %+v ok=%v, want Ceiling=%v source=list-estimate", pt, ok, want)
	}
	// Spot: same Ceiling number, source=spot-ceiling, Floor unset (no AWS spot table).
	sp, ok := p.NodeMonthly("aws", "eu-central-1", "m6i.large", types.CapacitySpot)
	if !ok || sp.Ceiling != want || sp.Source != types.CostSourceSpotCeiling || sp.Floor != 0 {
		t.Errorf("NodeMonthly spot = %+v, want Ceiling=%v source=spot-ceiling Floor=0", sp, want)
	}
	// Unpriced type → ok=false, zero point (never 0-as-price).
	if pt, ok := p.NodeMonthly("aws", "eu-central-1", "nonexistent.type", types.CapacityOnDemand); ok || pt.Ceiling != 0 {
		t.Errorf("unpriced type must be ok=false zero point, got %+v ok=%v", pt, ok)
	}
}

func TestEmbeddedProviderAsOf(t *testing.T) {
	date, source := Embedded().AsOf()
	if date != AsOf() || source != "embedded" {
		t.Errorf("AsOf() = (%q,%q), want (%q,embedded)", date, source, AsOf())
	}
}

func TestEmbeddedProviderLBAndControlPlane(t *testing.T) {
	lb, ok := Embedded().LBMonthly("aws", "eu-central-1")
	if !ok || lb <= 0 {
		t.Errorf("LBMonthly aws/eu-central-1 = %v ok=%v, want >0", lb, ok)
	}
	if cp := Embedded().ControlPlaneMonthly("aws"); cp <= 0 {
		t.Errorf("ControlPlaneMonthly aws = %v, want >0 (EKS $73/mo)", cp)
	}
	if cp := Embedded().ControlPlaneMonthly("azure"); cp != 0 {
		t.Errorf("ControlPlaneMonthly azure = %v, want 0 (free tier)", cp)
	}
}
