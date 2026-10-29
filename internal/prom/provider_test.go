package prom

import (
	"context"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type fakeVPA struct{ out map[string]ContainerUsage }

func (f fakeVPA) ListTargets(context.Context) (map[string]ContainerUsage, error) { return f.out, nil }

type fakeMetrics struct{ out map[string]ContainerUsage }

func (f fakeMetrics) ListSnapshot(context.Context) (map[string]ContainerUsage, error) {
	return f.out, nil
}

func TestVPAProvider(t *testing.T) {
	want := map[string]ContainerUsage{"api/api-1/app": {Namespace: "api", Pod: "api-1", Container: "app", CPUCoresP95: 0.4}}
	var p UsageProvider = newVPAProvider(fakeVPA{out: want})
	got, err := p.Usage(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("vpa Usage = (%v,%v)", got, err)
	}
	m := p.Methodology()
	if m.Source != "vpa" || m.Confidence != UsageConfidenceLow || m.Window != "" {
		t.Errorf("vpa methodology = %+v, want source=vpa confidence=low window=''", m)
	}
}

func TestMetricsProvider(t *testing.T) {
	want := map[string]ContainerUsage{"api/api-1/app": {Namespace: "api", Pod: "api-1", Container: "app", CPUCoresP95: 0.2}}
	var p UsageProvider = newMetricsProvider(fakeMetrics{out: want})
	got, err := p.Usage(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("metrics Usage = (%v,%v)", got, err)
	}
	m := p.Methodology()
	if m.Source != "metrics.k8s.io" || m.Confidence != UsageConfidenceLow || m.Window != "instant" {
		t.Errorf("metrics methodology = %+v, want source=metrics.k8s.io confidence=low window=instant", m)
	}
}

func TestNoneProvider(t *testing.T) {
	var p UsageProvider = noneProvider{}
	u, err := p.Usage(context.Background())
	if err != nil {
		t.Fatalf("noneProvider.Usage: %v", err)
	}
	if u != nil {
		t.Errorf("noneProvider must return nil map (no data), got %v", u)
	}
	m := p.Methodology()
	if m.Source != "none" || m.Confidence != types.UsageConfidenceNone {
		t.Errorf("noneProvider methodology = %+v, want source=none confidence=none", m)
	}
}
