package pricing

import (
	"sort"
	"strconv"
)

// azureTierGiB is the capacity of each Azure managed-disk tier CODE (the number after P, E or S), in GiB.
//
// THIS IS THE ONE CONSTANT IN THE PRICING PACKAGE THAT IS NOT GENERATED, and it is here because the Retail
// Prices API publishes a tier's PRICE under its code and never its SIZE. The ladder is part of the SKU
// definition — P10 has been 128 GiB since the P-series existed, and P/E/S share one numeric ladder — so it
// changes on the timescale of a product redesign, not a price sheet. What protects it is not a refresh but a
// gate: TestAzureDiskTiers_EveryEmittedTierHasASize fails the build the day the generator emits a tier code
// this map does not know, so a new tier (a P90) becomes a loud build failure rather than a disk priced at 0.
//
// Source: Azure managed-disk pricing pages (Premium SSD / Standard SSD / Standard HDD), sizes column,
// read 2026-09-02. P80/E80/S80 are 32,767 GiB — one GiB short of 32 TiB — as published.
var azureTierGiB = map[int]float64{
	1: 4, 2: 8, 3: 16, 4: 32, 6: 64, 10: 128, 15: 256, 20: 512,
	30: 1024, 40: 2048, 50: 4096, 60: 8192, 70: 16384, 80: 32767,
}

// AzureDiskTier resolves a requested capacity to the tier Azure would bill it as, for a region and disk
// type, and returns that tier's code and monthly price. ok=false when the region or type is not in the
// table, or when the request exceeds the largest published tier — an over-size disk is unpriced, never
// priced as the largest tier.
//
// THE ROUNDING IS THE POINT. Azure bills the SMALLEST tier whose capacity is at least the request: a 100 GiB
// claim is a P10 (128 GiB) and pays the P10 price; a 129 GiB claim is a P15 (256 GiB). Pricing per GB, as
// this package did until 2026-09-02, under-reported every small disk and mis-shaped every large one.
func AzureDiskTier(region, diskType string, gib float64) (tier string, monthlyUSD float64, ok bool) {
	return azureDiskTierFrom(azureDiskTierMonthlyUSD, region, diskType, gib)
}

// azureTierBasis is the sentence VolumeMonthly attaches to an Azure figure, in one place so the embedded and
// bundle providers say it the same way.
func azureTierBasis(tier string) string {
	return "azure tier " + tier + " (" + strconv.FormatFloat(azureTierGiB[tierNumber(tier)], 'f', 0, 64) +
		" GiB) — Azure bills the smallest tier that holds the request, not the GiB requested"
}

// azureDiskTierFrom is the rounding over ANY tier table — the embedded one or a bundle's.
func azureDiskTierFrom(table map[string]map[string]map[string]float64, region, diskType string, gib float64) (tier string, monthlyUSD float64, ok bool) {
	byType, ok := table[region]
	if !ok {
		return "", 0, false
	}
	tiers, ok := byType[diskType]
	if !ok || gib <= 0 {
		return "", 0, false
	}
	// Smallest tier that holds the request. Codes are sorted numerically so "P10" comes after "P6".
	codes := make([]string, 0, len(tiers))
	for c := range tiers {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return tierNumber(codes[i]) < tierNumber(codes[j]) })
	for _, c := range codes {
		size, known := azureTierGiB[tierNumber(c)]
		if !known {
			continue // the gate makes this unreachable in a shipped build; skipping is the safe direction
		}
		if size >= gib {
			return c, tiers[c], true
		}
	}
	return "", 0, false
}

func tierNumber(code string) int {
	if len(code) < 2 {
		return -1
	}
	n, err := strconv.Atoi(code[1:])
	if err != nil {
		return -1
	}
	return n
}

// VolumeMonthly is THE ONE ENTRY POINT for pricing a single volume, used by the storage headline and by
// every rule that prices a PersistentVolume — so the two can never disagree about what a disk costs.
//
// It hides the fact that clouds bill storage differently: AWS EBS is a per-GB-month rate times the
// provisioned GiB; Azure managed disks are a fixed tier. The returned basis names which, so a caller can
// say it in evidence — "priced as an Azure P10 (128 GiB) tier" is a different sentence from "100 GiB at
// $0.0952/GB-month", and a reader who sees the wrong one has been told something false about their bill.
//
// ok=false is the honest state for anything the tables cannot describe: an unknown class, an uncovered
// region, a GCP disk (not modelled), a request above Azure's largest tier.
func VolumeMonthly(provider, region, diskType string, gib float64) (monthlyUSD float64, basis string, ok bool) {
	if gib <= 0 {
		return 0, "", false
	}
	switch normalizeProvider(provider) {
	case "azure":
		tier, usd, ok := AzureDiskTier(region, diskType, gib)
		if !ok {
			return 0, "", false
		}
		return usd, azureTierBasis(tier), true
	default:
		perGB, ok := StorageMonthlyPerGB(provider, region, diskType)
		if !ok {
			return 0, "", false
		}
		return gib * perGB, "per GB-month at list × provisioned GiB", true
	}
}
