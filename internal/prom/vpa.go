package prom

import "context"

// vpaProvider is the Tier-2 UsageProvider: VPA target recommendations are
// candidate-only, so Confidence is low and Window is "" (not a measured p95).
type vpaProvider struct{ l VPALister }

func newVPAProvider(l VPALister) *vpaProvider { return &vpaProvider{l: l} }

func (p *vpaProvider) Usage(ctx context.Context) (map[string]ContainerUsage, error) {
	return p.l.ListTargets(ctx)
}

func (p *vpaProvider) Methodology() UsageMethodology {
	return UsageMethodology{
		Source:     "vpa",
		Confidence: UsageConfidenceLow,
		Caveats:    []string{"VPA recommendations are candidate targets, not measured p95 — no defensible $ derived"},
	}
}
