package pipeline

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// SPEC §4 P4 — THE EMBEDDED FALLBACK IS WHAT MAKES THE TOOL AUTONOMOUS.
//
// No cache, no bundle, no network ⇒ a correct, honestly-stamped report. The product is not autonomous because
// it can fetch; it is autonomous because the compiled-in snapshot produces a correct stamped report with no
// network at all, and fetching is a convenience on top of that. If the fallback ever stops being correct, a
// fetch is not a mitigation.
//
// Asserted against a value read out of the embedded table, not against "non-zero" — the spec is explicit about
// that, because "non-zero" passes for a provider returning anything.
func TestEmbeddedFallback_StampsEmbeddedAndPricesFromTheEmbeddedTable(t *testing.T) {
	stamp := refdata.Stamp(pricing.Embedded())
	pv, ok := stamp["pricing"]
	if !ok {
		t.Fatal("the embedded provider produced no pricing stamp")
	}
	if pv.Source != string(refdata.SourceEmbedded) {
		t.Errorf("source = %q, want embedded", pv.Source)
	}
	// THE VALUE, not a shape. pricing.AsOf() is the embedded table's own stamp; a resolver that invented a
	// date would pass a regex and fail this.
	if pv.Version != pricing.AsOf() {
		t.Errorf("version = %q, want the embedded table's own %q", pv.Version, pricing.AsOf())
	}
	if !types.DataSourceValid(pv.Source) {
		t.Errorf("the embedded stamp's source %q is not in the closed set", pv.Source)
	}

	// NON-VACUITY: a different provider must produce a different stamp, or Stamp echoes a constant.
	other := refdata.Stamp(fixedAsOf{"2026-08", "bundle"})
	if other["pricing"] == pv {
		t.Error("Stamp returned the same pair for two different providers")
	}
	// And the zero PriceConfig still resolves to embedded — resolve_test.go asserts this too, and it is what
	// stops a resolver that returns the newest thing it can find.
	if _, src := pricing.Resolve(pricing.PriceConfig{}).AsOf(); src != "embedded" {
		t.Errorf("the zero PriceConfig resolved to source %q, want embedded", src)
	}
}

type fixedAsOf struct{ date, source string }

func (f fixedAsOf) AsOf() (string, string) { return f.date, f.source }
func (fixedAsOf) NodeMonthly(string, string, string, types.CapacityType) (pricing.PricePoint, bool) {
	return pricing.PricePoint{}, false
}
func (fixedAsOf) StorageMonthlyPerGB(string, string, string) (float64, bool) { return 0, false }
func (fixedAsOf) EgressPerGB(string, string) (float64, bool)                 { return 0, false }
func (fixedAsOf) LBMonthly(string, string) (float64, bool)                   { return 0, false }
func (fixedAsOf) ControlPlaneMonthly(string) float64                         { return 0 }

// The six accessors added to pricing.PriceProvider on 2026-09-02, delegated to the embedded snapshot: this
// double stands in for one method, and a double that had to grow with every price accessor would be a second
// provider to keep honest.
func (f fixedAsOf) VolumeMonthly(p, r, dt string, gib float64) (float64, string, bool) {
	return pricing.Embedded().VolumeMonthly(p, r, dt, gib)
}
func (f fixedAsOf) AzureDiskTier(r, dt string, gib float64) (string, float64, bool) {
	return pricing.Embedded().AzureDiskTier(r, dt, gib)
}
func (f fixedAsOf) ExtendedSupportHourly(p string) (float64, bool) {
	return pricing.Embedded().ExtendedSupportHourly(p)
}
func (f fixedAsOf) NodeShape(p, t string) (pricing.Shape, bool) {
	return pricing.Embedded().NodeShape(p, t)
}
func (f fixedAsOf) TypesInRegion(p, r string) []string { return pricing.Embedded().TypesInRegion(p, r) }
func (f fixedAsOf) RegionCovered(p, r string) bool     { return pricing.Embedded().RegionCovered(p, r) }
func (f fixedAsOf) SavingsPlanHourly(r, term, t string) (float64, bool) {
	return pricing.Embedded().SavingsPlanHourly(r, term, t)
}
