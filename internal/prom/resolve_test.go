package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func probeServer(t *testing.T, present bool) *httptest.Server {
	t.Helper()
	payload := usageVector()
	if present {
		payload = usageVector(ser{map[string]string{}, "7"})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}))
}

// TestResolvePreConnectedClientWins asserts a pre-connected client (the app
// auto-connect path) is used as Tier-1 and beats a present VPA.
func TestResolvePreConnectedClientWins(t *testing.T) {
	srv := probeServer(t, true)
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	p := ResolveUsageProvider(context.Background(), UsageConfig{
		PrometheusClient: c,
		VPALister:        fakeVPA{},
	})
	if got := p.Methodology().Source; got != "prometheus" {
		t.Errorf("source = %q, want prometheus (pre-connected client beats present VPA)", got)
	}
}

// TestResolvePreConnectedEmptyFallsThrough asserts a reachable-but-empty
// pre-connected client falls through to a lower tier (no fake near-zero usage).
func TestResolvePreConnectedEmptyFallsThrough(t *testing.T) {
	srv := probeServer(t, false) // reachable but empty
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	p := ResolveUsageProvider(context.Background(), UsageConfig{
		PrometheusClient: c,
		VPALister:        fakeVPA{out: map[string]ContainerUsage{}},
	})
	if got := p.Methodology().Source; got != "vpa" {
		t.Errorf("source = %q, want vpa (empty pre-connected client falls through)", got)
	}
}

func TestResolveTier1URLBeatsVPA(t *testing.T) {
	srv := probeServer(t, true)
	defer srv.Close()
	p := ResolveUsageProvider(context.Background(), UsageConfig{
		PrometheusURL: srv.URL,
		VPALister:     fakeVPA{},
	})
	if got := p.Methodology().Source; got != "prometheus" {
		t.Errorf("source = %q, want prometheus (explicit URL beats present VPA)", got)
	}
}

func TestResolveTier1EmptyProbeFallsToVPA(t *testing.T) {
	srv := probeServer(t, false) // reachable but GMP-curated-empty
	defer srv.Close()
	p := ResolveUsageProvider(context.Background(), UsageConfig{
		PrometheusURL: srv.URL,
		VPALister:     fakeVPA{out: map[string]ContainerUsage{}},
	})
	if got := p.Methodology().Source; got != "vpa" {
		t.Errorf("source = %q, want vpa (empty probe falls through, no fake near-zero)", got)
	}
}

func TestResolveTier3MetricsOnly(t *testing.T) {
	p := ResolveUsageProvider(context.Background(), UsageConfig{
		MetricsLister: fakeMetrics{out: map[string]ContainerUsage{}},
	})
	if got := p.Methodology().Source; got != "metrics.k8s.io" {
		t.Errorf("source = %q, want metrics.k8s.io", got)
	}
}

func TestResolveTier4None(t *testing.T) {
	p := ResolveUsageProvider(context.Background(), UsageConfig{})
	m := p.Methodology()
	if m.Source != "none" || m.Confidence != UsageConfidenceNone {
		t.Errorf("empty config must resolve to none, got %+v", m)
	}
}
