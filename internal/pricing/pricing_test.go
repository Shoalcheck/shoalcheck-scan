package pricing

import (
	"math"
	"regexp"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Cross-checked fetched hourly rates, hardcoded so the ±30% plausibility band
// becomes a real unit guard (a dropped/double ×730 blows the band immediately).
// Update if the table is regenerated and a rate moved materially.
const (
	// AWS: m6i.large eu-central-1 (ec2.shop, cross-checked vs aws.amazon.com).
	fetchedM6iLargeEUCentral1Hourly = 0.115
	// Azure: Standard_D4lds_v5 westus3 (Azure Retail Prices API, Linux on-demand).
	fetchedD4ldsV5Westus3Hourly = 0.192
	// GCP: e2-standard-4 us-central1 (Compute Engine on-demand list; ≈$97.84/mo).
	fetchedE2Standard4USCentral1Hourly = 0.134
)

func TestNodeMonthlyUSD_KnownTypePlausible_AWS(t *testing.T) {
	got, ok := NodeMonthlyUSD("aws", "eu-central-1", "m6i.large", types.CapacityUnknown)
	if !ok {
		t.Fatalf("m6i.large in eu-central-1 should be known")
	}
	want := fetchedM6iLargeEUCentral1Hourly * HoursPerMonth
	// ±30% tolerance: loose enough to survive a price tweak between table
	// regenerations, tight enough to catch a unit mistake (those are ≥730× off).
	lo, hi := want*0.70, want*1.30
	if got < lo || got > hi {
		t.Errorf("NodeMonthlyUSD(aws, eu-central-1, m6i.large) = %.2f, want within [%.2f, %.2f] (≈%.2f)", got, lo, hi, want)
	}
}

func TestNodeMonthlyUSD_KnownTypePlausible_Azure(t *testing.T) {
	got, ok := NodeMonthlyUSD("azure", "westus3", "Standard_D4lds_v5", types.CapacityUnknown)
	if !ok {
		t.Fatalf("Standard_D4lds_v5 in westus3 should be known")
	}
	want := fetchedD4ldsV5Westus3Hourly * HoursPerMonth
	lo, hi := want*0.70, want*1.30
	if got < lo || got > hi {
		t.Errorf("NodeMonthlyUSD(azure, westus3, Standard_D4lds_v5) = %.2f, want within [%.2f, %.2f] (≈%.2f)", got, lo, hi, want)
	}
}

func TestNodeMonthlyUSD_KnownTypePlausible_GCP(t *testing.T) {
	got, ok := NodeMonthlyUSD("gcp", "us-central1", "e2-standard-4", types.CapacityUnknown)
	if !ok {
		t.Fatalf("e2-standard-4 in us-central1 should be known")
	}
	want := fetchedE2Standard4USCentral1Hourly * HoursPerMonth
	lo, hi := want*0.70, want*1.30
	if got < lo || got > hi {
		t.Errorf("NodeMonthlyUSD(gcp, us-central1, e2-standard-4) = %.2f, want within [%.2f, %.2f] (≈%.2f)", got, lo, hi, want)
	}
}

// TestNodeMonthlyUSD_ProviderNormalization: the k8s provider tags must resolve
// to the same price as the canonical cloud names.
func TestNodeMonthlyUSD_ProviderNormalization(t *testing.T) {
	cases := []struct{ alias, canonical, region, itype string }{
		{"eks", "aws", "eu-central-1", "m6i.large"},
		{"aks", "azure", "westus3", "Standard_D4lds_v5"},
		{"gke", "gcp", "us-central1", "e2-standard-4"},
		{"AWS", "aws", "eu-central-1", "m6i.large"}, // case-insensitive
	}
	for _, c := range cases {
		a, aok := NodeMonthlyUSD(c.alias, c.region, c.itype, types.CapacityUnknown)
		b, bok := NodeMonthlyUSD(c.canonical, c.region, c.itype, types.CapacityUnknown)
		if !aok || !bok || a != b {
			t.Errorf("NodeMonthlyUSD(%q,...)=(%.2f,%v) != NodeMonthlyUSD(%q,...)=(%.2f,%v)",
				c.alias, a, aok, c.canonical, b, bok)
		}
	}
}

func TestNodeMonthlyUSD_UnknownType(t *testing.T) {
	got, ok := NodeMonthlyUSD("aws", "eu-central-1", "totally.bogus", types.CapacityUnknown)
	if ok {
		t.Errorf("unknown instance type should return ok=false, got usd=%.2f", got)
	}
	if got != 0 {
		t.Errorf("unknown instance type should return usd=0, got %.2f", got)
	}
	// An Azure type queried under the wrong provider must also miss.
	if _, ok := NodeMonthlyUSD("aws", "westus3", "Standard_D4lds_v5", types.CapacityUnknown); ok {
		t.Errorf("Azure type under provider=aws should return ok=false")
	}
}

func TestNodeMonthlyUSD_UnknownProvider(t *testing.T) {
	if got, ok := NodeMonthlyUSD("digitalocean", "nyc1", "s-4vcpu-8gb", types.CapacityUnknown); ok || got != 0 {
		t.Errorf("unknown provider should return (0,false), got (%.2f,%v)", got, ok)
	}
}

func TestNodeMonthlyUSD_UnknownRegion(t *testing.T) {
	got, ok := NodeMonthlyUSD("aws", "mars-west-1", "m6i.large", types.CapacityUnknown)
	if ok {
		t.Errorf("unknown region should return ok=false, got usd=%.2f", got)
	}
	if got != 0 {
		t.Errorf("unknown region should return usd=0, got %.2f", got)
	}
}

func TestNodeMonthlyUSD_M6iLargeAllFourRegions(t *testing.T) {
	regions := []string{"eu-central-1", "eu-north-1", "eu-west-1", "us-east-1"}
	for _, r := range regions {
		usd, ok := NodeMonthlyUSD("aws", r, "m6i.large", types.CapacityUnknown)
		if !ok {
			t.Errorf("m6i.large should be present in region %q", r)
			continue
		}
		if usd <= 0 {
			t.Errorf("m6i.large in %q should have a positive price, got %.2f", r, usd)
		}
	}
}

func TestAsOf_Format(t *testing.T) {
	re := regexp.MustCompile(`^\d{4}-\d{2}$`)
	if got := AsOf(); !re.MatchString(got) {
		t.Errorf("AsOf() = %q, want match of ^\\d{4}-\\d{2}$", got)
	}
}

func TestHoursPerMonth(t *testing.T) {
	if HoursPerMonth != 730 {
		t.Errorf("HoursPerMonth = %d, want 730", HoursPerMonth)
	}
}

func TestNLBMonthlyUSD(t *testing.T) {
	usd, ok := NLBMonthlyUSD("eu-central-1")
	if !ok {
		t.Fatalf("NLB price for eu-central-1 should be known")
	}
	// hourly * 730; sanity-bound a single idle NLB at well under $100/mo.
	if usd <= 0 || usd > 100 {
		t.Errorf("NLBMonthlyUSD(eu-central-1) = %.2f, want a plausible (0, 100] base price", usd)
	}
	if _, ok := NLBMonthlyUSD("mars-west-1"); ok {
		t.Errorf("unknown region should return ok=false for NLBMonthlyUSD")
	}
}

func TestEBSGp3MonthlyUSDPerGB(t *testing.T) {
	usd, ok := EBSGp3MonthlyUSDPerGB("eu-central-1")
	if !ok {
		t.Fatalf("EBS gp3 price for eu-central-1 should be known")
	}
	// gp3 GB-month is cents-per-GB; guard the unit (a ×730 slip would explode it).
	if usd <= 0 || usd > 1 {
		t.Errorf("EBSGp3MonthlyUSDPerGB(eu-central-1) = %.4f, want a plausible (0, 1] $/GB-mo", usd)
	}
	if _, ok := EBSGp3MonthlyUSDPerGB("mars-west-1"); ok {
		t.Errorf("unknown region should return ok=false for EBSGp3MonthlyUSDPerGB")
	}
}

func TestEKSControlPlaneMonthlyUSD(t *testing.T) {
	got := EKSControlPlaneMonthlyUSD()
	want := 0.10 * HoursPerMonth // $73/cluster-mo
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("EKSControlPlaneMonthlyUSD() = %.2f, want %.2f", got, want)
	}
}

func TestLBMonthlyUSD_AllProviders(t *testing.T) {
	// AWS: per-region NLB base; Azure/GCP: flat base resolved via the "*" key
	// regardless of the region passed.
	cases := []struct {
		provider, region string
		wantOK           bool
	}{
		{"aws", "eu-central-1", true},
		{"eks", "us-east-1", true},    // alias
		{"azure", "westus3", true},    // flat "*" base
		{"aks", "anywhere-1", true},   // flat base ignores region
		{"gcp", "us-central1", true},  // flat "*" base
		{"gke", "europe-west1", true}, // flat base
		{"aws", "mars-west-1", false}, // unknown AWS region
		{"onprem", "dc-1", false},     // no LB price table
		{"unknown", "x", false},
	}
	for _, c := range cases {
		usd, ok := LBMonthlyUSD(c.provider, c.region)
		if ok != c.wantOK {
			t.Errorf("LBMonthlyUSD(%q,%q) ok=%v, want %v", c.provider, c.region, ok, c.wantOK)
			continue
		}
		if ok && (usd <= 0 || usd > 100) {
			t.Errorf("LBMonthlyUSD(%q,%q)=%.2f, want plausible (0,100] base", c.provider, c.region, usd)
		}
	}
}

// TestRegionCovered guards the single biggest credibility risk in the output:
// an AKS/GKE cluster in a region the node tables don't cover would otherwise
// price its compute to $0. RegionCovered must report that truthfully so the
// run path can suppress a misleading headline.
func TestRegionCovered(t *testing.T) {
	cases := []struct {
		provider, region string
		want             bool
	}{
		// Covered: dense AWS EU + the canonical Azure/GCP regions in the tables.
		{"aws", "eu-central-1", true},
		{"eks", "eu-central-1", true}, // k8s tag normalizes
		{"AWS", "eu-central-1", true}, // case-insensitive
		{"azure", "westus3", true},
		{"aks", "westus3", true},
		{"gcp", "us-central1", true},
		{"gke", "us-central1", true},

		// THE LANDMINE, CLOSED FOR AZURE ON 2026-08-31. This block held francecentral, uksouth and
		// germanywestcentral as the documented uncovered set: real regions a customer runs in that
		// priced compute to $0. The generator moved from four hand-listed Azure regions to all 69 the
		// Retail API sells, and all three became covered — so they are asserted as COVERED here, which
		// is the assertion that would fail if the region list ever silently narrowed again.
		{"azure", "francecentral", true},
		{"aks", "francecentral", true},
		{"aks", "uksouth", true},
		{"aks", "germanywestcentral", true},

		// GCP IS STILL THE LANDMINE, and its shape is different: Google publishes no free structured
		// price endpoint (verified 2026-08-31 — the Billing Catalog API answers 403 without a key, the
		// legacy price list is 404), so GCP is a hand-verified table of three regions and everything
		// outside it honestly reports uncovered. This does not close without an API key.
		{"gke", "europe-west3", false},
		{"gcp", "europe-west3", false},

		// Unknown provider / region / empties never claim coverage.
		{"aws", "mars-west-1", false},
		{"digitalocean", "nyc1", false},
		{"aws", "", false},
		{"", "eu-central-1", false},
	}
	for _, c := range cases {
		if got := RegionCovered(c.provider, c.region); got != c.want {
			t.Errorf("RegionCovered(%q,%q) = %v, want %v", c.provider, c.region, got, c.want)
		}
	}
}

// TestCoveredRegions returns a sorted, non-empty region list for each cloud and
// nothing for an unknown provider — the seam an operator uses to footnote or
// extend the tables before a paid run.
func TestCoveredRegions(t *testing.T) {
	for _, prov := range []string{"aws", "azure", "gcp"} {
		regions := CoveredRegions(prov)
		if len(regions) == 0 {
			t.Errorf("CoveredRegions(%q) is empty, want at least one region", prov)
			continue
		}
		for i := 1; i < len(regions); i++ {
			if regions[i-1] > regions[i] {
				t.Errorf("CoveredRegions(%q) not sorted: %v", prov, regions)
				break
			}
		}
		// Every returned region must round-trip through RegionCovered.
		for _, r := range regions {
			if !RegionCovered(prov, r) {
				t.Errorf("CoveredRegions(%q) returned %q but RegionCovered says false", prov, r)
			}
		}
	}
	// k8s tag normalizes to the same list as the cloud name.
	if a, b := CoveredRegions("eks"), CoveredRegions("aws"); len(a) != len(b) {
		t.Errorf("CoveredRegions(eks)=%d != CoveredRegions(aws)=%d", len(a), len(b))
	}
	if got := CoveredRegions("digitalocean"); len(got) != 0 {
		t.Errorf("CoveredRegions(unknown) = %v, want empty", got)
	}
}

func TestControlPlaneMonthlyUSD_PerProvider(t *testing.T) {
	const wantHourly10 = 0.10 * HoursPerMonth // $73/mo
	// AWS (EKS) and GCP (GKE) charge $0.10/h; AKS free tier is $0.
	if got := ControlPlaneMonthlyUSD("aws"); math.Abs(got-wantHourly10) > 1e-9 {
		t.Errorf("ControlPlaneMonthlyUSD(aws) = %.2f, want %.2f", got, wantHourly10)
	}
	if got := ControlPlaneMonthlyUSD("gcp"); math.Abs(got-wantHourly10) > 1e-9 {
		t.Errorf("ControlPlaneMonthlyUSD(gcp) = %.2f, want %.2f", got, wantHourly10)
	}
	if got := ControlPlaneMonthlyUSD("azure"); got != 0 {
		t.Errorf("ControlPlaneMonthlyUSD(azure) = %.2f, want 0 (free tier)", got)
	}
	// Aliases normalize.
	if got := ControlPlaneMonthlyUSD("eks"); math.Abs(got-wantHourly10) > 1e-9 {
		t.Errorf("ControlPlaneMonthlyUSD(eks) = %.2f, want %.2f", got, wantHourly10)
	}
	// Unknown provider → 0 (honest "no modelled fee").
	if got := ControlPlaneMonthlyUSD("onprem"); got != 0 {
		t.Errorf("ControlPlaneMonthlyUSD(onprem) = %.2f, want 0", got)
	}
}
