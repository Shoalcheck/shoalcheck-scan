package verdict

import "github.com/Shoalcheck/shoalcheck-scan/internal/types"

// Tier is the band a finding is ranked in before anything else about it is weighed. Severity, money,
// actionability and breadth still order findings — but only WITHIN a tier.
//
// WHY THERE ARE BANDS AT ALL, measured on an 839-finding reading of a production cluster (2026-09-08). Under
// severity-first ranking the first row of `shoalcheck findings` was "ClusterRole system:prometheus permits the
// nodes/proxy subresource" — how Prometheus scrapes a kubelet, which every platform engineer already knows —
// while "No ready address is published for shop/orders-api-v3" — a Service whose EndpointSlices held
// no ready entry at the moment of the reading, which is a reference fact and not an outage claim — sat
// seventh, and the Deployment behind it, 0 of 1 replicas ready, sat twenty-first
// because its rule says medium. Severity answers "how bad would this be"; a reader opening the list first
// asks "what is wrong right now, and what will stop me next". Those are different questions, and the
// product already has the vocabulary for the second one: the pillars.
//
// SO THE BANDS ARE THE PILLARS, NOT A NEW TABLE. internal/rules/pillars.go assigns every rule a pillar by
// what its claim is — Ground Truth rests on a status a controller published, Change Preflight is arithmetic
// about an operation that has not happened yet — and requires an explicit entry for every rule. A second
// rule-ID table here would be a hand-maintained copy of that registry, the defect class this project has
// found repeatedly. Order approved by the founder 2026-10-16: broken now, then what stops the next change,
// then money, then everything else.
type Tier int

const (
	// tierUnset is the zero value — a Ranked built without a ranking — so that nothing reads as critical
	// because nobody set it.
	tierUnset Tier = iota
	// TierCritical: a critical finding leads whatever it is about. The bands reorder what severity
	// confused; they never bury a critical hole under a medium that happens to be present-tense.
	TierCritical
	// TierNow: Ground Truth — a controller published, at the moment of the reading, that this is wrong.
	TierNow
	// TierNextChange: Change Preflight — what will stop a drain, a zone loss, a rollout or an upgrade.
	TierNextChange
	// TierMonitoring: Observability — what the cluster's own reporting would not tell you.
	TierMonitoring
	// TierMoney: defensible dollars at or above the knee where a platform lead starts caring.
	TierMoney
	// TierPosture: everything else — spec-level hardening and hygiene, ordered by severity within.
	TierPosture
	// TierConditional: a finding whose own text says it may not apply. Its own band rather than the floor
	// of posture, because sunk inside posture it put mediums under an info and the SEV column read as a
	// broken sort; under its own name the order explains itself.
	TierConditional

	tierCount
)

// TierOf is the band f is ranked in.
//
// TWO THINGS ARE CHECKED BEFORE CRITICAL, on purpose.
//   - A HEDGED finding is conditional whatever else it carries. Priority has always refused to let a finding
//     whose own text says it may not apply lead; a band above everything else would let it lead its band,
//     and a band can be the first thing on the screen. A hedged critical included —
//     TestPriority_HedgeIsAbsolute caught that order reversed.
//   - An INFO note is posture. An informational note is never the thing a client should do first, and ,000 on it
//     does not change what it is — TestPriority_InfoNeverLeads caught the money band admitting one.
func TierOf(f types.Finding) Tier {
	if mayNotApply(f) {
		return TierConditional
	}
	if f.Severity == types.SeverityInfo {
		return TierPosture
	}
	if f.Severity == types.SeverityCritical {
		return TierCritical
	}
	switch f.Pillar {
	case types.PillarGroundTruth:
		return TierNow
	case types.PillarChangePreflight:
		return TierNextChange
	case types.PillarObservability:
		return TierMonitoring
	}
	if f.DollarImpactMonthly >= dollarKnee {
		return TierMoney
	}
	return TierPosture
}

// Label is the tier's name as a reader sees it, in the column that explains why a medium sits above a high.
func (t Tier) Label() string {
	switch t {
	case TierCritical:
		return "critical"
	case TierNow:
		return "true now"
	case TierNextChange:
		return "next change"
	case TierMonitoring:
		return "monitoring"
	case TierMoney:
		return "money"
	case TierConditional:
		return "conditional"
	case TierPosture:
		return "posture"
	}
	return ""
}

// tierWeight lifts a score into its band. Every within-band term together stays under 600 (severity 500,
// money 40, actionability 37, breadth 10) and hedging subtracts at most 400, so a gap of 1000 means no
// combination of them can carry a finding across a band boundary.
func tierWeight(t Tier) float64 {
	return float64(tierCount-1-t) * 1000
}
