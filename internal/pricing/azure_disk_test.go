package pricing

import (
	"math"
	"strings"
	"testing"
)

// TestAzureDiskTiers_EveryEmittedTierHasASize is the gate that lets azureTierGiB be a constant. The
// generator reads tier CODES off the Retail API; if Azure ever publishes one the ladder does not know, this
// fails the build with the code named, instead of AzureDiskTier skipping it and rounding a disk into the
// next tier up — or, worse, pricing it at nothing.
func TestAzureDiskTiers_EveryEmittedTierHasASize(t *testing.T) {
	var unknown []string
	regions := 0
	for region, byType := range azureDiskTierMonthlyUSD {
		regions++
		for dtype, tiers := range byType {
			for code := range tiers {
				if _, ok := azureTierGiB[tierNumber(code)]; !ok {
					unknown = append(unknown, region+"/"+dtype+"/"+code)
				}
			}
		}
	}
	if regions < 20 {
		t.Fatalf("only %d regions carry disk tiers — the generator's disk fetch regressed", regions)
	}
	if len(unknown) > 0 {
		t.Errorf("%d tier code(s) in the generated table have no size in azureTierGiB — add them, with the "+
			"published capacity, before this build ships: %v", len(unknown), unknown)
	}
}

// TestAzureDiskTier_RoundsTheWayTheInvoiceDoes.
func TestAzureDiskTier_RoundsTheWayTheInvoiceDoes(t *testing.T) {
	for _, c := range []struct {
		gib  float64
		want string
	}{
		{1, "P1"}, {4, "P1"}, {5, "P2"}, {100, "P10"}, {128, "P10"}, {129, "P15"}, {1024, "P30"}, {1025, "P40"}, {32767, "P80"},
	} {
		tier, usd, ok := AzureDiskTier("westeurope", "Premium_LRS", c.gib)
		if !ok || tier != c.want || usd <= 0 {
			t.Errorf("%.0f GiB Premium_LRS -> %q $%.2f ok=%v, want tier %s", c.gib, tier, usd, ok, c.want)
		}
	}
	if _, _, ok := AzureDiskTier("westeurope", "Premium_LRS", 32768); ok {
		t.Error("a request above the largest published tier priced — it must be unpriced, never priced as P80")
	}
	if _, _, ok := AzureDiskTier("neverlandcentral", "Premium_LRS", 100); ok {
		t.Error("an uncovered region priced a disk")
	}
	if _, _, ok := AzureDiskTier("westeurope", "UltraSSD_LRS", 100); ok {
		t.Error("a disk type the table does not carry priced")
	}
}

// TestVolumeMonthly_OneEntryPointTwoBillingModels — AWS is per GB, Azure is a tier, and the basis says which.
func TestVolumeMonthly_OneEntryPointTwoBillingModels(t *testing.T) {
	usd, basis, ok := VolumeMonthly("aws", "eu-central-1", "gp3", 100)
	perGB, _ := StorageMonthlyPerGB("aws", "eu-central-1", "gp3")
	if !ok || math.Abs(usd-100*perGB) > 1e-9 || !strings.Contains(basis, "per GB") {
		t.Errorf("aws gp3 100GiB -> $%.4f %q ok=%v, want 100×%.4f and a per-GB basis", usd, basis, ok, perGB)
	}
	usd, basis, ok = VolumeMonthly("azure", "westeurope", "Premium_LRS", 100)
	_, p10, _ := AzureDiskTier("westeurope", "Premium_LRS", 100)
	if !ok || usd != p10 || !strings.Contains(basis, "P10") || !strings.Contains(basis, "128 GiB") {
		t.Errorf("azure Premium_LRS 100GiB -> $%.2f %q ok=%v, want the P10 price and a basis naming P10 / 128 GiB", usd, basis, ok)
	}
	// The pre-fix approximation, for the record: 100 GiB × the old per-GB rate was $13.50; the invoice says P10.
	if usd < 13.5 {
		t.Errorf("the P10 tier price $%.2f is below the old per-GB approximation for 100 GiB ($13.50) — the direction "+
			"of the correction is wrong, which means the tier table is not what it claims", usd)
	}
	if _, _, ok := VolumeMonthly("gcp", "us-central1", "pd-ssd", 100); ok {
		t.Error("GCP storage is not modelled and must be unpriced")
	}
}
