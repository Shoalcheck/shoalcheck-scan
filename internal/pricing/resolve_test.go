package pricing

import "testing"

func TestResolveDefaultEmbedded(t *testing.T) {
	// --refresh-pricing OFF (default) ⇒ deterministic embedded provider.
	p := Resolve(PriceConfig{})
	date, source := p.AsOf()
	if source != "embedded" || date != AsOf() {
		t.Errorf("default Resolve AsOf = (%q,%q), want (%q,embedded)", date, source, AsOf())
	}
}

func TestResolveGCPLiveWithoutKeyFallsBackEmbedded(t *testing.T) {
	// Live requested but GCP has no key ⇒ embedded + a surfaced note, no fabrication.
	cfg := PriceConfig{RefreshLive: true} // GCPAPIKey empty
	p, notes := ResolveWithNotes(cfg)
	if _, source := p.AsOf(); source != "embedded" {
		t.Errorf("GCP-without-key must fall back to embedded, got source=%q", source)
	}
	found := false
	for _, n := range notes {
		if contains(n, "GCP") {
			found = true
		}
	}
	if !found {
		t.Errorf("must surface a GCP-fallback note, got %v", notes)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
