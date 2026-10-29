package prom

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

// UsageConfig is the resolved input — endpoint + auth + opportunistic CRD/REST
// access. Built by cmd/shoalcheck from flags/env; pipeline passes it through.
type UsageConfig struct {
	PrometheusURL string           // explicit --prometheus-url (Tier 1)
	Auth          PromAuth         // pluggable auth axis
	Backend       string           // resolved flavour hint ("thanos"/"mimir"/...); "" → "prometheus"
	Services      []corev1.Service // reserved for autodiscovery hint (Detect); not auto-connected
	VPALister     VPALister        // nil unless autoscaling.k8s.io VPA CRD present
	MetricsLister MetricsLister    // nil unless metrics.k8s.io reachable

	// PrometheusClient is a PRE-CONNECTED Tier-1 client supplied by the desktop
	// app's auto-connect path (API-server service-proxy or in-process
	// port-forward). When non-nil it takes priority over PrometheusURL — the app
	// already built and Pinged the transport, so the resolver reuses it instead of
	// dialing a URL. The same honesty rule applies: reachable-but-empty falls
	// THROUGH to a lower tier rather than emitting a fake near-zero usage map.
	PrometheusClient *Client

	// ClientOptions are applied to any Client this resolver BUILDS. It exists for the request recorder:
	// tier1Client used to call NewClient with no options, so the usage queries — the ones that produce every
	// dollar figure in the report — were the one Prometheus leg nobody counted, and the displayed total was a
	// fraction presented as a total. A pre-connected PrometheusClient is already wired by its builder and is
	// not touched here.
	ClientOptions []Option
}

// ResolveUsageProvider picks exactly ONE provider in strict order:
//
//	Tier 1: PrometheusURL set AND the presence probe finds container/KSM series.
//	        Reachable-but-empty (GMP curated subset) falls THROUGH — never a fake
//	        near-zero usage map.
//	Tier 2: VPALister non-nil.
//	Tier 3: MetricsLister non-nil.
//	Tier 4: noneProvider{} — rightsizing no-ops, methodology says "none".
//
// It never errors: an unreachable explicit URL is the pipeline's fatal concern
// (it Pings first); here a probe failure simply falls through to the next tier.
func ResolveUsageProvider(ctx context.Context, cfg UsageConfig) UsageProvider {
	// A pre-connected client (app auto-connect: service-proxy / port-forward)
	// takes priority over a URL — the transport is already built and Pinged.
	if c := tier1Client(cfg); c != nil {
		backend := cfg.Backend
		if backend == "" {
			backend = "prometheus"
		}
		if ok, err := hasContainerMetrics(ctx, c); err == nil && ok {
			// Probe how far the series actually reach while we are already talking to
			// this backend, so Methodology() can report the real window instead of the
			// window the queries ask for. A failed probe returns known=false and makes
			// no claim; an empty probe returns known=true and is the short-history case.
			cov, covKnown := c.HistoryCoverage(ctx)
			return newPromProvider(c, backend, nil, cov, covKnown)
		}
		// Reachable but no usable series (or probe failed): fall through to a
		// lower tier rather than emit a near-zero usage map.
	}
	if cfg.VPALister != nil {
		return newVPAProvider(cfg.VPALister)
	}
	if cfg.MetricsLister != nil {
		return newMetricsProvider(cfg.MetricsLister)
	}
	return noneProvider{}
}

// tier1Client returns the Tier-1 client to probe: a pre-connected client (app
// auto-connect) wins over building one from PrometheusURL. Returns nil when
// neither is supplied so the resolver falls to the next tier.
func tier1Client(cfg UsageConfig) *Client {
	if cfg.PrometheusClient != nil {
		return cfg.PrometheusClient
	}
	if cfg.PrometheusURL != "" {
		return NewClient(cfg.PrometheusURL, cfg.Auth, cfg.ClientOptions...)
	}
	return nil
}
