package pricing

import (
	"encoding/json"
	"fmt"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// bundle.go — A REFERENCE-DATA BUNDLE'S PRICE PAYLOAD, AS A PriceProvider.
//
// This is what makes a refresh mean something. Without it `shoalcheck update` downloads, verifies and caches an
// artifact no audit ever reads, and a fetch that cannot affect an answer is theatre.
//
// THE PAYLOAD MIRRORS tables_gen.go's SHAPE, not a new convention: map[provider]map[region]map[type] for node
// hourly rates, and the same for the smaller tables. scripts/update-pricing.py already reads the vendor APIs
// and emits exactly these maps at publish time, so the bundle carries what the generator produces rather than
// a second format somebody has to keep in step.
//
// EMBEDDED FALLBACK WITHIN THE PROVIDER, per key. A bundle that carries one region must not make every other
// instance type unpriced — that would turn a refresh into a coverage regression, and the report would
// honestly but uselessly call most of the fleet unpriced. So a lookup the bundle cannot answer falls through
// to the compiled-in table, and the only thing the bundle overrides is what it actually contains.
//
// WHAT IT DOES NOT DO: interpret a signature. internal/refdata verifies; this file parses. A package that both
// verified signatures and parsed price tables would make a parser bug a trust-boundary bug.

// bundlePayload is the pricing dataset's own bytes inside a bundle.
type bundlePayload struct {
	// Version is the dataset's stamp, e.g. "2026-08". It is what AsOf reports and what the sixth comparison
	// gate compares.
	Version string `json:"version"`
	// NodeHourlyUSD is provider → region → instanceType → hourly rate.
	NodeHourlyUSD map[string]map[string]map[string]float64 `json:"nodeHourlyUSD"`
	// The smaller tables, all optional: a bundle that carries only node rates is valid, and every absent
	// table falls through to the embedded one.
	LBHourlyUSD           map[string]map[string]float64 `json:"lbHourlyUSD,omitempty"`
	ControlPlaneHourlyUSD map[string]float64            `json:"controlPlaneHourlyUSD,omitempty"`
	StorageGBMonthUSD     map[string]map[string]float64 `json:"storageGBMonthUSD,omitempty"`

	// The tables added in the 2026-08-31 coverage work. A payload that lacks one falls back to the embedded
	// snapshot FOR THAT TABLE, and the fallback is visible: the provider's AsOf still names the bundle, so a
	// mixed state is not silent — TestBundle_StatesWhichTablesItCarries prints it.
	EbsGBMonthUSD            map[string]map[string]float64            `json:"ebsGBMonthUSD,omitempty"`            // region → volumeType → $/GB-mo
	AzureDiskTierMonthlyUSD  map[string]map[string]map[string]float64 `json:"azureDiskTierMonthlyUSD,omitempty"`  // region → diskType → tier → $/mo
	ExtendedSupportHourlyUSD map[string]float64                       `json:"extendedSupportHourlyUSD,omitempty"` // provider → $/h surcharge
	AwsSavingsPlanHourlyUSD  map[string]map[string]map[string]float64 `json:"awsSavingsPlanHourlyUSD,omitempty"`  // region → term → type → $/h
	AwsNodeShape             map[string]struct {
		VCPU   float64 `json:"vcpu"`
		MemGiB float64 `json:"memGiB"`
	} `json:"awsNodeShape,omitempty"`
}

// bundleProvider prices from a bundle, falling through to the embedded tables per lookup.
type bundleProvider struct {
	p      bundlePayload
	source string
}

// FromBundle parses a pricing payload into a PriceProvider.
//
// A parse failure is an ERROR AND NOT A SILENT FALLBACK. The caller decides what to do, and the resolver's
// choice — keep the embedded table and surface a note — is visible in the report rather than swallowed. An
// operator who ran `shoalcheck update`, saw it succeed, and got unchanged figures has been told nothing.
func FromBundle(payload []byte, source string) (PriceProvider, error) {
	var p bundlePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("the bundle's pricing payload is not readable by this binary: %w", err)
	}
	if p.Version == "" {
		return nil, fmt.Errorf("the bundle's pricing payload carries no version")
	}
	if len(p.NodeHourlyUSD) == 0 {
		// A payload with no node rates would report a cache source and price every node from the embedded
		// table. Refusing is honest: there is nothing here to prefer.
		return nil, fmt.Errorf("the bundle's pricing payload carries no node rates")
	}
	return bundleProvider{p: p, source: source}, nil
}

func (b bundleProvider) AsOf() (string, string) { return b.p.Version, b.source }

// Carries reports which of the newer tables this bundle brought, so a run can say "prices from the
// bundle; Azure disk tiers from the embedded snapshot" instead of one word for a mixed state.
func (b bundleProvider) Carries() map[string]bool {
	return map[string]bool{
		"ebs":              len(b.p.EbsGBMonthUSD) > 0,
		"azure-disk-tiers": len(b.p.AzureDiskTierMonthlyUSD) > 0,
		"extended-support": len(b.p.ExtendedSupportHourlyUSD) > 0,
		"aws-shapes":       len(b.p.AwsNodeShape) > 0,
		"savings-plans":    len(b.p.AwsSavingsPlanHourlyUSD) > 0,
	}
}

func (b bundleProvider) VolumeMonthly(provider, region, diskType string, gib float64) (float64, string, bool) {
	if gib <= 0 {
		return 0, "", false
	}
	switch normalizeProvider(provider) {
	case "azure":
		if len(b.p.AzureDiskTierMonthlyUSD) > 0 {
			tier, usd, ok := azureDiskTierFrom(b.p.AzureDiskTierMonthlyUSD, region, diskType, gib)
			if !ok {
				return 0, "", false
			}
			return usd, azureTierBasis(tier), true
		}
	case "aws":
		if len(b.p.EbsGBMonthUSD) > 0 {
			if byType, ok := b.p.EbsGBMonthUSD[region]; ok {
				if perGB, ok := byType[diskType]; ok {
					return gib * perGB, "per GB-month at list × provisioned GiB", true
				}
			}
			return 0, "", false
		}
	}
	return Embedded().VolumeMonthly(provider, region, diskType, gib)
}

func (b bundleProvider) AzureDiskTier(region, diskType string, gib float64) (string, float64, bool) {
	if len(b.p.AzureDiskTierMonthlyUSD) > 0 {
		return azureDiskTierFrom(b.p.AzureDiskTierMonthlyUSD, region, diskType, gib)
	}
	return Embedded().AzureDiskTier(region, diskType, gib)
}

func (b bundleProvider) ExtendedSupportHourly(provider string) (float64, bool) {
	if len(b.p.ExtendedSupportHourlyUSD) > 0 {
		usd, ok := b.p.ExtendedSupportHourlyUSD[normalizeProvider(provider)]
		return usd, ok && usd > 0
	}
	return Embedded().ExtendedSupportHourly(provider)
}

func (b bundleProvider) NodeShape(provider, instanceType string) (Shape, bool) {
	if normalizeProvider(provider) == "aws" && len(b.p.AwsNodeShape) > 0 {
		s, ok := b.p.AwsNodeShape[instanceType]
		return Shape{VCPU: s.VCPU, MemGiB: s.MemGiB}, ok
	}
	return Embedded().NodeShape(provider, instanceType)
}

func (b bundleProvider) TypesInRegion(provider, region string) []string {
	if byType, ok := b.p.NodeHourlyUSD[normalizeProvider(provider)][region]; ok {
		out := make([]string, 0, len(byType))
		for t := range byType {
			out = append(out, t)
		}
		return out
	}
	return nil
}

func (b bundleProvider) SavingsPlanHourly(region, term, instanceType string) (float64, bool) {
	if len(b.p.AwsSavingsPlanHourlyUSD) > 0 {
		usd, ok := b.p.AwsSavingsPlanHourlyUSD[region][term][instanceType]
		return usd, ok && usd > 0
	}
	return Embedded().SavingsPlanHourly(region, term, instanceType)
}

func (b bundleProvider) RegionCovered(provider, region string) bool {
	regions, ok := b.p.NodeHourlyUSD[normalizeProvider(provider)]
	if !ok {
		return false
	}
	_, ok = regions[region]
	return ok
}

func (b bundleProvider) NodeMonthly(provider, region, instanceType string, capacity types.CapacityType) (PricePoint, bool) {
	if regions, ok := b.p.NodeHourlyUSD[normalizeProvider(provider)]; ok {
		if byType, ok := regions[region]; ok {
			if hourly, ok := byType[instanceType]; ok && hourly > 0 {
				// SPOT IS NOT IN THE BUNDLE, so the point carries the on-demand ceiling and no floor — the
				// same honest shape the embedded provider produces when the cloud publishes no spot meter.
				// Inventing a floor from a multiplier is the fabricated-discount defect this project already
				// paid for once.
				return PricePoint{Ceiling: hourly * HoursPerMonth, Source: types.CostSourceListEstimate}, true
			}
		}
	}
	return Embedded().NodeMonthly(provider, region, instanceType, capacity)
}

func (b bundleProvider) LBMonthly(provider, region string) (float64, bool) {
	if regions, ok := b.p.LBHourlyUSD[normalizeProvider(provider)]; ok {
		if hourly, ok := regions[region]; ok && hourly > 0 {
			return hourly * HoursPerMonth, true
		}
	}
	return Embedded().LBMonthly(provider, region)
}

func (b bundleProvider) ControlPlaneMonthly(provider string) float64 {
	if hourly, ok := b.p.ControlPlaneHourlyUSD[normalizeProvider(provider)]; ok && hourly > 0 {
		return hourly * HoursPerMonth
	}
	return Embedded().ControlPlaneMonthly(provider)
}

func (b bundleProvider) StorageMonthlyPerGB(provider, region, diskType string) (float64, bool) {
	// AWS EBS lives in its own table since 2026-08-31 (see StorageMonthlyPerGB in pricing.go); a bundle that
	// carries it answers from it, and one that does not falls through to the embedded EBS table below.
	if normalizeProvider(provider) == "aws" && len(b.p.EbsGBMonthUSD) > 0 {
		if byType, ok := b.p.EbsGBMonthUSD[region]; ok {
			usd, ok := byType[diskType]
			return usd, ok
		}
		return 0, false
	}
	if regions, ok := b.p.StorageGBMonthUSD[normalizeProvider(provider)]; ok {
		if v, ok := regions[region]; ok && v > 0 {
			return v, true
		}
	}
	return Embedded().StorageMonthlyPerGB(provider, region, diskType)
}

func (b bundleProvider) EgressPerGB(provider, region string) (float64, bool) {
	// Egress is not carried in a bundle yet. Falling through is correct and the absence is not hidden: the
	// dataset's version stamp is about what it contains.
	return Embedded().EgressPerGB(provider, region)
}
