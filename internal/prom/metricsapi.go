package prom

import "context"

// metricsProvider is the Tier-3 UsageProvider: metrics.k8s.io is an
// instantaneous snapshot (Window "instant"), so Confidence is low and no p95
// claim is implied.
type metricsProvider struct{ l MetricsLister }

func newMetricsProvider(l MetricsLister) *metricsProvider { return &metricsProvider{l: l} }

func (p *metricsProvider) Usage(ctx context.Context) (map[string]ContainerUsage, error) {
	return p.l.ListSnapshot(ctx)
}

func (p *metricsProvider) Methodology() UsageMethodology {
	return UsageMethodology{
		Source:     "metrics.k8s.io",
		Confidence: UsageConfidenceLow,
		Window:     "instant",
		Caveats:    []string{"metrics.k8s.io is an instantaneous snapshot — not a windowed p95"},
	}
}
