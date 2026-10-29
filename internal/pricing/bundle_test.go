package pricing

import (
	"encoding/json"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// SPEC §10 test 1 — TestResolve_CacheAndLiveLegsExist, the cache half.
//
// Without this, a verified bundle changes nothing about a report: `shoalcheck update` would download, verify and
// cache an artifact that no audit ever reads. A fetch that cannot affect an answer is theatre, and the
// resolver's own doc comment has promised these legs since it was written ("in this phase the cache and live
// legs are not yet implemented").
//
// Non-vacuity: the DEFAULT PriceConfig{} must still resolve to "embedded". resolve_test.go asserts that
// already and must keep passing — a resolver that returns the newest thing it can find would fail it.
func TestResolve_TheCacheLegReadsTheBundleAndTheDefaultStaysEmbedded(t *testing.T) {
	payload := mustTablePayload(t, "2026-08", map[string]float64{"m6i.xlarge": 1.234})

	p, notes := ResolveWithNotes(PriceConfig{CachedBundle: payload})
	date, source := p.AsOf()
	if source != "cache" {
		t.Errorf("source = %q, want cache", source)
	}
	if date != "2026-08" {
		t.Errorf("date = %q, want the bundle's own 2026-08", date)
	}
	_ = notes

	// THE PRICE MUST COME FROM THE BUNDLE, not from the embedded table. A provider that reports a cache
	// source and prices from the snapshot is the worst of both: the report names a table it did not use.
	got, ok := p.NodeMonthly("aws", "eu-central-1", "m6i.xlarge", types.CapacityOnDemand)
	if !ok {
		t.Fatal("the bundle's own instance type did not price")
	}
	wantMonthly := 1.234 * 730
	if diff := got.Ceiling - wantMonthly; diff > 0.01 || diff < -0.01 {
		t.Errorf("m6i.xlarge priced at %.2f, want %.2f from the bundle", got.Ceiling, wantMonthly)
	}

	// EMBEDDED FALLBACK WITHIN A CACHED PROVIDER. A bundle carrying one region must not make every other
	// instance type unpriced — that would turn a refresh into a coverage regression, and the report would
	// honestly but uselessly report most of the fleet as unpriced.
	if _, ok := p.NodeMonthly("aws", "eu-central-1", "m6i.large", types.CapacityOnDemand); !ok {
		t.Error("an instance type the bundle omits stopped pricing entirely — a refresh must not shrink coverage")
	}

	// NON-VACUITY: the zero config still resolves to embedded.
	if _, src := Resolve(PriceConfig{}).AsOf(); src != "embedded" {
		t.Errorf("the zero PriceConfig resolved to %q — the resolver returns the newest thing it can find", src)
	}
	// And the two providers must disagree about the price, or "from the bundle" is unfalsifiable.
	e, _ := Embedded().NodeMonthly("aws", "eu-central-1", "m6i.xlarge", types.CapacityOnDemand)
	if e.Ceiling == got.Ceiling {
		t.Errorf("the bundle and the embedded table price m6i.xlarge identically (%.2f); the fixture cannot "+
			"tell them apart", e.Ceiling)
	}
}

// A BUNDLE THIS BINARY CANNOT PARSE IS A REFUSAL, NOT A SILENT FALLBACK. Falling back to embedded and
// reporting "embedded" would be honest about the source and silent about the failure — the operator ran
// `shoalcheck update`, it succeeded, and their data did not move.
func TestResolve_AnUnparseableBundleIsSurfacedNotSwallowed(t *testing.T) {
	p, notes := ResolveWithNotes(PriceConfig{CachedBundle: []byte(`{"this":"is not a price table payload"`)})
	_, source := p.AsOf()
	if source != "embedded" {
		t.Errorf("source = %q — an unparseable bundle must leave the embedded table in place", source)
	}
	joined := ""
	for _, n := range notes {
		joined += n + "\n"
	}
	if joined == "" {
		t.Fatal("an unparseable cached bundle produced no note at all, so the report would say nothing")
	}
	if !contains(joined, "could not") && !contains(joined, "cache") {
		t.Errorf("the note does not say the cache was unusable:\n%s", joined)
	}
}

func mustTablePayload(t *testing.T, version string, awsEUCentral1 map[string]float64) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		Version string                                   `json:"version"`
		Nodes   map[string]map[string]map[string]float64 `json:"nodeHourlyUSD"`
	}{
		Version: version,
		Nodes:   map[string]map[string]map[string]float64{"aws": {"eu-central-1": awsEUCentral1}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
