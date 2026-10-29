package prom

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// provenance.go — B-145. "A PROMETHEUS ANSWERED" IS NOT "THIS CLUSTER'S PROMETHEUS ANSWERED".
//
// The four usage queries in usage.go carry `{container!="",container!="POD"}` and NO cluster selector, and
// the results are keyed on `namespace/pod/container`. Against a Thanos, Mimir, Grafana Cloud, AMP, GMP or
// any federated endpoint holding more than one cluster, that key is not unique — and prod and staging in
// one Thanos have identical namespace names BY DESIGN. Two clusters with a `payments/postgres-0/postgres`
// produce one map entry and the last vector merged wins.
//
// That usage feeds rightsizing, which feeds the headline dollars. So the failure mode is a confident
// savings figure computed from a different cluster's consumption, silently. It is worse than absence,
// because absence is honest and a wrong number is not.
//
// The product already KNOWS this can happen: resolve.go carries a Backend field that names thanos and
// mimir, and queries them unqualified anyway.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE TIERS, AND WHY 1b IS THE DEFECT
//
//	Tier 0    a kubeconfig, read-only            — the object graph. Needs no proof.
//	Tier 1a   + a source PROVEN to be this cluster's   — usage-derived claims are sound
//	Tier 1b   + a source reachable but UNPROVEN        — nothing. Today this is indistinguishable from 1a.
//
// Every topology that puts metrics outside the audited cluster lands in 1b and is reported as 1a.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT COUNTS AS PROOF, AND WHY THE OBVIOUS CHECKS DO NOT
//
//	THE NAMESPACE-SET CHECK IS A NEGATIVE SCREEN ONLY. It can prove a source is wrong and never that it
//	is right: prod and staging share namespace names, so the set is a subset and the check passes on
//	exactly the topology it was meant to catch. A source with `namespace` relabelled returns no namespace
//	label at all — an empty set is a subset, so it passes while usage is unusable. And retention gaps make
//	a correctly scoped source return a proper subset, which also passes.
//
//	A CLUSTER LABEL IS NOT AVAILABLE ON THE COMMONEST INSTALL. Requiring `cluster` to be present and
//	single-valued would withhold usage on every plain in-cluster kube-prometheus-stack, which is both the
//	most common topology and entirely correct. A check that fires on the correct case is not a check.
//
//	SO THE PROOF IS TWO PARTS, AND BOTH ARE NEEDED:
//
//	  CONTAINMENT — a pod UID from the audited cluster is found in `kube_pod_info`. A UID is globally
//	  unique, so a match proves the source holds THIS cluster's data. This is the identifier §6c.2 names.
//
//	  EXCLUSIVITY — the number of pods the source currently sees is close to the number this reading
//	  collected. kube-state-metrics exports LIVE objects only, so history does not inflate this count; a
//	  source holding twelve clusters reports roughly twelve times the pods. This is what makes the proof
//	  work on a plain Prometheus, where there is no cluster label to inspect.
//
//	Both hold → proven. Either fails, or kube-state-metrics is absent → UNPROVEN, and every usage-derived
//	figure is withheld WITH THE REASON NAMED. That is Tier 1b working correctly rather than a gap.

// Tier is what a metrics source has been proven to be, never what it appears to be.
type Tier string

const (
	// TierNone — no metrics source resolved at all.
	TierNone Tier = "none"
	// TierUnproven — a source answered, and nothing establishes it is this cluster's. Tier 1b.
	TierUnproven Tier = "unproven"
	// TierProven — the source holds this cluster's data and shows no sign of holding others. Tier 1a.
	TierProven Tier = "proven"
)

// Provenance is the verdict, and it carries its own reasoning because the reason is what reaches the
// methodology section when a figure is withheld. "Prometheus resolved" is not the fact worth printing;
// "resolved and proven to be this cluster's, by this check" is.
type Provenance struct {
	Tier Tier
	// Method names the check that decided it, so a reader can reproduce the decision.
	Method string
	// Detail is the specific finding, in the source's own numbers.
	Detail string
	// PodsCollected and PodsInSource are the exclusivity measurement, kept as numbers so the report can
	// state them rather than paraphrase them. Zero when the check could not run.
	PodsCollected, PodsInSource int
}

// Proven reports whether usage-derived claims may rest on this source.
func (p Provenance) Proven() bool { return p.Tier == TierProven }

// exclusivityTolerance is how much larger the source's live-pod count may be than the audited cluster's
// before the source is treated as holding more than this cluster.
//
// 1.25 rather than 1.0 because the two counts are taken seconds apart against a moving cluster, and because
// kube-state-metrics and the API server disagree briefly during a rollout. It is deliberately far below the
// 2.0 that a two-cluster source would produce: the check has to separate "same cluster, moving" from
// "another cluster is in here", and those differ by a factor, not by a percentage.
const exclusivityTolerance = 1.25

// queryPodInfoCount counts the pods kube-state-metrics currently exports. Instant, not ranged: KSM exports
// live objects only, so this is "pods that exist now" and cannot be inflated by retention.
const queryPodInfoCount = `count(kube_pod_info)`

// ProveCluster decides the access tier for this source.
//
// podUIDs are the UIDs of pods collected from the audited cluster — the caller passes them because this
// package must not reach into internal/collect. podsCollected is how many pods the reading saw.
func (c *Client) ProveCluster(ctx context.Context, podUIDs []string, podsCollected int) Provenance {
	if len(podUIDs) == 0 || podsCollected == 0 {
		return Provenance{
			Tier:   TierUnproven,
			Method: "none available",
			Detail: "no pods were collected from the audited cluster, so there is no identifier to match " +
				"against the metrics source",
		}
	}

	// CONTAINMENT. A bounded sample of UIDs, not all of them: a cluster can hold tens of thousands of pods
	// and the matcher would exceed any sane URL length. One match is proof, so a sample is sufficient —
	// and sampling is stated rather than silent.
	const sampleSize = 40
	sample := append([]string(nil), podUIDs...)
	sort.Strings(sample) // deterministic sample, so two runs against one cluster ask the same question
	if len(sample) > sampleSize {
		sample = sample[:sampleSize]
	}
	q := fmt.Sprintf(`count(kube_pod_info{uid=~"%s"})`, strings.Join(sample, "|"))
	got, err := c.Query(ctx, q)
	if err != nil {
		return Provenance{
			Tier:          TierUnproven,
			Method:        "kube_pod_info uid match",
			Detail:        fmt.Sprintf("the source could not answer the identity query: %v", err),
			PodsCollected: podsCollected,
		}
	}
	matched := 0
	for _, s := range got {
		matched += int(s.Value)
	}
	if matched == 0 {
		return Provenance{
			Tier:   TierUnproven,
			Method: "kube_pod_info uid match",
			Detail: fmt.Sprintf("none of %d sampled pod UIDs from this cluster appears in the source's "+
				"kube_pod_info; either kube-state-metrics is absent, or the source holds a different "+
				"cluster's data", len(sample)),
			PodsCollected: podsCollected,
		}
	}

	// EXCLUSIVITY.
	cnt, err := c.Query(ctx, queryPodInfoCount)
	if err != nil || len(cnt) == 0 {
		return Provenance{
			Tier:   TierUnproven,
			Method: "kube_pod_info live count",
			Detail: "the source holds this cluster's data, but its total live-pod count could not be " +
				"read, so whether it holds other clusters as well is unknown",
			PodsCollected: podsCollected,
		}
	}
	inSource := int(cnt[0].Value)
	if float64(inSource) > float64(podsCollected)*exclusivityTolerance {
		return Provenance{
			Tier:   TierUnproven,
			Method: "kube_pod_info live count",
			Detail: fmt.Sprintf("the source reports %d live pods and this reading collected %d — more "+
				"than the %.2fx tolerance, so the source holds data beyond this cluster and an unqualified "+
				"query cannot be attributed to it", inSource, podsCollected, exclusivityTolerance),
			PodsCollected: podsCollected,
			PodsInSource:  inSource,
		}
	}

	return Provenance{
		Tier:   TierProven,
		Method: "kube_pod_info uid match + live count",
		Detail: fmt.Sprintf("%d of %d sampled pod UIDs from this cluster were found in the source, and it "+
			"reports %d live pods against the %d this reading collected",
			matched, len(sample), inSource, podsCollected),
		PodsCollected: podsCollected,
		PodsInSource:  inSource,
	}
}

// ClusterProver is implemented by usage providers whose data source sits OUTSIDE the audited cluster and
// can therefore be pointed at a different one.
//
// THE INTERFACE IS THE HONEST PART OF THIS DESIGN. promProvider implements it; the VPA and metrics.k8s.io
// providers deliberately do not, and that is not an omission — both are in-cluster APIs reached through the
// same kubeconfig the audit authenticated with, so there is no topology in which they answer for a
// different cluster. The set of sources that need proving is exactly the set that can be wrong.
type ClusterProver interface {
	ProveCluster(ctx context.Context, podUIDs []string, podsCollected int) Provenance
}

// ProveCluster on the Tier-1 provider delegates to its own client, so the endpoint that is proven is the
// endpoint the numbers came from. Proving a different client would establish nothing about the figures.
func (p *promProvider) ProveCluster(ctx context.Context, podUIDs []string, podsCollected int) Provenance {
	return p.c.ProveCluster(ctx, podUIDs, podsCollected)
}
