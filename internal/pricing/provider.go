package pricing

import "github.com/Shoalcheck/shoalcheck-scan/internal/types"

// PricePoint is a node's monthly price. Spot is structurally a RANGE, never a
// point: Ceiling is the on-demand list (the honest upper bound, always set when
// ok); Floor is a published list-spot meter where one exists (Azure), else 0 —
// NEVER a fabricated multiplier.
type PricePoint struct {
	Ceiling float64          // on-demand list (upper bound) — always set when ok
	Floor   float64          // list-spot meter where the cloud publishes one; else 0
	Source  types.CostSource // list-estimate | spot-ceiling
}

// PriceProvider is the seam every cost call routes through. The package-level
// funcs are the embedded default (Embedded()); Resolve may swap in a
// cache/live-backed provider under --refresh-pricing.
type PriceProvider interface {
	NodeMonthly(provider, region, instanceType string, capacity types.CapacityType) (PricePoint, bool)
	StorageMonthlyPerGB(provider, region, diskType string) (float64, bool)
	EgressPerGB(provider, region string) (float64, bool)
	LBMonthly(provider, region string) (float64, bool)
	ControlPlaneMonthly(provider string) float64
	AsOf() (date string, source string) // "2026-06" + "embedded"|"cache"|"live"

	// THE SIX THAT WERE MISSING. Until 2026-09-02 these existed only as package-level functions over the
	// embedded tables, so a bundle could refresh the headline and never a rule's dollar — the cover and
	// the findings would price the same machine from two tables. A rule may only reach a price through
	// this interface; TestEveryRuleDollarFollowsTheProvider is the guard.
	VolumeMonthly(provider, region, diskType string, gib float64) (monthlyUSD float64, basis string, ok bool)
	AzureDiskTier(region, diskType string, gib float64) (tier string, monthlyUSD float64, ok bool)
	ExtendedSupportHourly(provider string) (float64, bool)
	NodeShape(provider, instanceType string) (Shape, bool)
	TypesInRegion(provider, region string) []string
	RegionCovered(provider, region string) bool
	// SavingsPlanHourly is AWS-only today; other providers answer ok=false.
	SavingsPlanHourly(region, term, instanceType string) (float64, bool)
}

// embeddedProvider is the thin PriceProvider over the compiled-in tables.
type embeddedProvider struct{}

// Embedded returns the offline default PriceProvider (the tables_gen.go snapshot).
func Embedded() PriceProvider { return embeddedProvider{} }

func (embeddedProvider) NodeMonthly(provider, region, instanceType string, capacity types.CapacityType) (PricePoint, bool) {
	usd, ok := NodeMonthlyUSD(provider, region, instanceType, capacity)
	if !ok {
		return PricePoint{}, false
	}
	src := types.CostSourceListEstimate
	if capacity == types.CapacitySpot {
		src = types.CostSourceSpotCeiling
	}
	// Floor stays 0: the embedded table has no list-spot meter (AWS real spot
	// needs auth). The spot number is the on-demand list treated as a ceiling.
	return PricePoint{Ceiling: usd, Source: src}, true
}

func (embeddedProvider) StorageMonthlyPerGB(provider, region, diskType string) (float64, bool) {
	return StorageMonthlyPerGB(provider, region, diskType)
}

func (embeddedProvider) EgressPerGB(provider, region string) (float64, bool) {
	return EgressPerGB(provider, region)
}

func (embeddedProvider) LBMonthly(provider, region string) (float64, bool) {
	return LBMonthlyUSD(provider, region)
}

func (embeddedProvider) ControlPlaneMonthly(provider string) float64 {
	return ControlPlaneMonthlyUSD(provider)
}

func (embeddedProvider) AsOf() (string, string) { return AsOf(), "embedded" }
func (embeddedProvider) VolumeMonthly(provider, region, diskType string, gib float64) (float64, string, bool) {
	return VolumeMonthly(provider, region, diskType, gib)
}
func (embeddedProvider) AzureDiskTier(region, diskType string, gib float64) (string, float64, bool) {
	return AzureDiskTier(region, diskType, gib)
}
func (embeddedProvider) ExtendedSupportHourly(provider string) (float64, bool) {
	return ExtendedSupportHourly(provider)
}
func (embeddedProvider) NodeShape(provider, instanceType string) (Shape, bool) {
	return NodeShape(provider, instanceType)
}
func (embeddedProvider) TypesInRegion(provider, region string) []string {
	return TypesInRegion(provider, region)
}
func (embeddedProvider) RegionCovered(provider, region string) bool {
	return RegionCovered(provider, region)
}
func (embeddedProvider) SavingsPlanHourly(region, term, instanceType string) (float64, bool) {
	return SavingsPlanHourly(region, term, instanceType)
}
