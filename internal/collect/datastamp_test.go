package collect

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// SPEC §10 test 2 — TestMethodology_NamesTheVersionAndTheSource. THE SPEC SAYS THIS FAILS TODAY, and it does.
//
// PriceProvider.AsOf() returns (date, source) and has since it was written, but pricingMethodologyNote does
// not take the provider: it calls the PACKAGE-LEVEL pricing.AsOf() four times. So a report prints the
// embedded table's date and NEVER the source, and would keep printing the embedded date even if a cache- or
// bundle-backed provider were injected. That is the whole of §4 property 6 missing for the one dataset that
// exists.
//
// Non-vacuity: the two providers below must produce DIFFERENT sentences. With the hardcoded call, both
// produce the embedded date and the assertion passes for the wrong reason — which is exactly the defect.
func TestMethodology_NamesTheVersionAndTheSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		date    string
		source  string
		mustSay []string
	}{
		{"embedded", pricing.AsOf(), "embedded", []string{pricing.AsOf(), "embedded"}},
		{"a bundle", "2026-08", "bundle", []string{"2026-08", "bundle"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pricingMethodologyNote("eks", 0, true, stubProvider{stubAsOf{date: tc.date, source: tc.source}})
			for _, want := range tc.mustSay {
				if !strings.Contains(got, want) {
					t.Errorf("the methodology sentence does not name %q:\n  %s", want, got)
				}
			}
		})
	}

	// NON-VACUITY, stated as its own assertion rather than left implicit: two different providers must not
	// produce the same sentence. A note that ignores its provider passes every per-case assertion above
	// whenever the stub happens to match the embedded table.
	embedded := pricingMethodologyNote("eks", 0, true, stubProvider{stubAsOf{date: pricing.AsOf(), source: "embedded"}})
	bundled := pricingMethodologyNote("eks", 0, true, stubProvider{stubAsOf{date: "2026-08", source: "bundle"}})
	if embedded == bundled {
		t.Errorf("both providers produced the same sentence, so the note is not reading the provider:\n  %s", embedded)
	}
}

// SPEC §10 test 3 — the report half. Every dataset in the registry is stamped on RunBasis.
func TestDataVersions_ThePricingStampReachesTheReport(t *testing.T) {
	inv := &Inventory{}
	inv.Meta.Collected = []string{"nodes"}
	ar := BuildReport(inv, nil, "acme", 0, stubProvider{stubAsOf{date: "2026-08", source: "bundle"}})

	if ar.Methodology.RunBasis == nil {
		t.Fatal("no RunBasis, so nothing can be stamped")
	}
	dv := ar.Methodology.RunBasis.DataVersions
	if len(dv) == 0 {
		t.Fatal("RunBasis.DataVersions is empty — no dataset was stamped")
	}
	got, ok := dv["pricing"]
	if !ok {
		t.Fatalf("no pricing stamp; DataVersions holds %v", dv)
	}
	if got.Version != "2026-08" || got.Source != "bundle" {
		t.Errorf("pricing stamp = %+v, want {2026-08 bundle} — the stamp is hardcoded to the embedded table", got)
	}

	// NON-VACUITY: the embedded provider must stamp the EMBEDDED pair, or a stamp that echoes whatever it is
	// handed would pass the assertion above while being unable to tell the two apart.
	arEmbedded := BuildReport(inv, nil, "acme", 0, pricing.Embedded())
	e := arEmbedded.Methodology.RunBasis.DataVersions["pricing"]
	if e.Source != "embedded" {
		t.Errorf("the embedded provider stamped source %q", e.Source)
	}
	if e.Version != pricing.AsOf() {
		t.Errorf("the embedded provider stamped version %q, want %q", e.Version, pricing.AsOf())
	}
	if e == got {
		t.Error("the two providers produced identical stamps")
	}
	// The source vocabulary is closed; a stamp outside it is unfalsifiable prose in a report.
	for name, v := range dv {
		if !types.DataSourceValid(v.Source) {
			t.Errorf("dataset %q carries source %q, which is not in the closed set", name, v.Source)
		}
	}
}

// stubAsOf is a PriceProvider whose only interesting method is AsOf. Every other method returns "not
// priced", which is honest for a stub: a test about stamping must not depend on a fake price.
type stubAsOf struct{ date, source string }

func (s stubAsOf) AsOf() (string, string) { return s.date, s.source }

type stubProvider struct{ stubAsOf }

func (stubProvider) NodeMonthly(string, string, string, types.CapacityType) (pricing.PricePoint, bool) {
	return pricing.PricePoint{}, false
}
func (stubProvider) StorageMonthlyPerGB(string, string, string) (float64, bool) { return 0, false }
func (stubProvider) EgressPerGB(string, string) (float64, bool)                 { return 0, false }
func (stubProvider) LBMonthly(string, string) (float64, bool)                   { return 0, false }
func (stubProvider) ControlPlaneMonthly(string) float64                         { return 0 }

// The six accessors added to pricing.PriceProvider on 2026-09-02, delegated to the embedded snapshot: this
// double only stands in for AsOf, and a double that had to grow with every price accessor would be a second
// provider to keep honest.
func (stubProvider) VolumeMonthly(p, r, dt string, gib float64) (float64, string, bool) {
	return pricing.Embedded().VolumeMonthly(p, r, dt, gib)
}
func (stubProvider) AzureDiskTier(r, dt string, gib float64) (string, float64, bool) {
	return pricing.Embedded().AzureDiskTier(r, dt, gib)
}
func (stubProvider) ExtendedSupportHourly(p string) (float64, bool) {
	return pricing.Embedded().ExtendedSupportHourly(p)
}
func (stubProvider) NodeShape(p, t string) (pricing.Shape, bool) {
	return pricing.Embedded().NodeShape(p, t)
}
func (stubProvider) TypesInRegion(p, r string) []string {
	return pricing.Embedded().TypesInRegion(p, r)
}
func (stubProvider) RegionCovered(p, r string) bool { return pricing.Embedded().RegionCovered(p, r) }

// The six accessors added to pricing.PriceProvider on 2026-09-02, delegated to the embedded snapshot: this
// double stands in for one method, and a double that had to grow with every price accessor would be a second
// provider to keep honest.
func (s stubAsOf) VolumeMonthly(p, r, dt string, gib float64) (float64, string, bool) {
	return pricing.Embedded().VolumeMonthly(p, r, dt, gib)
}
func (s stubAsOf) AzureDiskTier(r, dt string, gib float64) (string, float64, bool) {
	return pricing.Embedded().AzureDiskTier(r, dt, gib)
}
func (s stubAsOf) ExtendedSupportHourly(p string) (float64, bool) {
	return pricing.Embedded().ExtendedSupportHourly(p)
}
func (s stubAsOf) NodeShape(p, t string) (pricing.Shape, bool) {
	return pricing.Embedded().NodeShape(p, t)
}
func (s stubAsOf) TypesInRegion(p, r string) []string { return pricing.Embedded().TypesInRegion(p, r) }
func (s stubAsOf) RegionCovered(p, r string) bool     { return pricing.Embedded().RegionCovered(p, r) }
func (stubProvider) SavingsPlanHourly(r, term, t string) (float64, bool) {
	return pricing.Embedded().SavingsPlanHourly(r, term, t)
}
func (s stubAsOf) SavingsPlanHourly(r, term, t string) (float64, bool) {
	return pricing.Embedded().SavingsPlanHourly(r, term, t)
}
