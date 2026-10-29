package prom

import (
	"context"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// UsageConfidence / UsageMethodology are the canonical structs from package
// types, aliased here so prom callers don't import types directly for them and
// there is exactly ONE definition (no drift).
type UsageConfidence = types.UsageConfidence
type UsageMethodology = types.UsageMethodology

const (
	UsageConfidenceHigh = types.UsageConfidenceHigh
	UsageConfidenceLow  = types.UsageConfidenceLow
	UsageConfidenceNone = types.UsageConfidenceNone
)

// UsageProvider returns per-container usage keyed "ns/pod/container".
// CONTRACT (preserve absent-vs-zero, usage.go:29-31): a container MISSING from
// the map means "no data" — callers (rightsizing.go maxP95) must never
// substitute 0; a present container with a 0 field means "that dimension
// unobserved". Tiers 2/3 set candidate-only methodology so no defensible $ is
// derived from them.
type UsageProvider interface {
	Usage(ctx context.Context) (map[string]ContainerUsage, error)
	Methodology() UsageMethodology
}

// VPALister is the types-only Tier-2 access seam. The concrete VPA-CRD client
// is wired by cmd/shoalcheck (proprietary); the OSS tree only knows this shape.
// It returns per-container target recommendations keyed "ns/pod/container".
type VPALister interface {
	ListTargets(ctx context.Context) (map[string]ContainerUsage, error)
}

// MetricsLister is the types-only Tier-3 access seam over metrics.k8s.io. It
// returns an instantaneous per-container snapshot keyed "ns/pod/container".
type MetricsLister interface {
	ListSnapshot(ctx context.Context) (map[string]ContainerUsage, error)
}

// noneProvider is Tier 4: no usage source. Usage returns a nil map (NOT an
// empty one populated with zeros) so rightsizing no-ops honestly.
type noneProvider struct{}

func (noneProvider) Usage(context.Context) (map[string]ContainerUsage, error) {
	return nil, nil
}

func (noneProvider) Methodology() UsageMethodology {
	return UsageMethodology{Source: "none", Confidence: UsageConfidenceNone}
}
