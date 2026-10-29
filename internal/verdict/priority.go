package verdict

import (
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Priority scores how much a finding deserves to lead. Higher wins.
//
// ─────────────────────────────────────────────────────────────────────────────────────
// TODO: this weighting is the one piece of this package that is a claim about people
// rather than about data — what actually hurts a platform lead, and what they will act on
// this week. It is a first guess, to be tuned against real readers.
//
// A baseline ships rather than a stub so `make ci` stays green and the lens is usable
// today. Override the weights freely: the acceptance test
// (TestPriority_IdleHogOutranksBlanketNetworkPolicyFindings) pins the one outcome that is
// not negotiable, and the rest is judgement.
//
// The signals available, all already on types.Finding:
//
//	Severity              critical | high | medium | low | info
//	DollarImpactMonthly   defensible monthly cost, 0 when the rule has no cost model
//	EstimatedEffort       low (<30min) | medium (<4h) | high (>4h)
//	Confidence            problem-certainty ONLY — never safety (see safety.go)
//	len(AffectedResources) blast radius, after collapsing
//	Category              cost | reliability | security | config | compliance
//	safety                SafeNow | NeedsReview | Manual
//	collapsedFrom         how many findings of this rule folded together
//
// Questions worth deciding deliberately, because each changes the product's character:
//   - Does $500/mo of waste outrank a critical security finding worth $0? No — a critical leads
//     every band. Below critical the BANDS come first (tier.go, proposed 2026-10-16 for the
//     first screen and the founder's to retune): true now, next change, monitoring, money at or
//     above the knee, posture. Severity and money order findings within a band.
//   - Should a wide-but-cheap finding (60 workloads, no dollars) beat a narrow expensive
//     one? My baseline gives breadth only a small nudge.
//   - Does "easy to fix" deserve weight of its own, or is that just a tiebreak? My baseline
//     treats low effort plus SafeNow as a genuine bonus, because a finding nobody can act
//     on this week is worth less than one they can.
//
// ─────────────────────────────────────────────────────────────────────────────────────
func Priority(f types.Finding, safety SafetyClass, collapsedFrom int) float64 {
	// Severity dominates. A critical security hole worth $0 outranks $500/mo of waste,
	// because the audit's credibility dies the moment it tells a client to chase savings
	// while a hole is open.
	score := float64(severityRank(f.Severity)) * 100

	// Money orders findings WITHIN a severity band. Compressed hard (log-ish via a cap) so a
	// single huge number cannot vault a low-severity finding over a high-severity one.
	if d := f.DollarImpactMonthly; d > 0 {
		score += 40 * dollarWeight(d)
	}

	// Actionability. A finding the team can safely apply in under half an hour is worth more
	// than an equally important one that needs a planning meeting — not because it matters
	// more, but because "start here" has to mean something.
	switch safety {
	case SafeNow:
		score += 25
	case NeedsReview:
		score += 8
	}
	switch f.EstimatedEffort {
	case types.EffortLow:
		score += 12
	case types.EffortMedium:
		score += 4
	}

	// Blast radius, as a nudge only. Breadth is evidence that something is systemic, but a
	// blanket observation repeated across sixty namespaces is not sixty times as urgent.
	score += breadthWeight(collapsedFrom, len(f.AffectedResources))

	// Problem-certainty scales the whole thing: a finding the rule is unsure about should not
	// lead, whatever else it has going for it. Confidence is used HERE, for certainty — never
	// for safety.
	if c := f.Confidence; c > 0 && c < 1 {
		score *= 0.6 + 0.4*c
	}

	// A finding whose own text says it may not apply can never lead, regardless of score.
	// Honest to report, dishonest to put first.
	if mayNotApply(f) {
		score -= 400
	}

	// The band comes last and is added, not multiplied: everything above orders findings WITHIN a band, and the
	// band decides which group a reader sees first. See tier.go for why the bands are the pillars.
	score += tierWeight(TierOf(f))
	return score
}

// dollarWeight compresses monthly impact into 0..1 with sharply diminishing returns, so the
// difference between $50 and $500 matters and the difference between $5,000 and $50,000 does
// not reorder anything on its own.
// dollarKnee is where a platform lead starts caring: a few hundred a month. It is the midpoint of dollarWeight
// and the floor of TierMoney, so "money that matters" means one thing in both places.
const dollarKnee = 250.0

func dollarWeight(usd float64) float64 {
	return usd / (usd + dollarKnee)
}

// breadthWeight rewards systemic findings mildly and saturates fast.
func breadthWeight(collapsedFrom, affected int) float64 {
	n := collapsedFrom
	if affected > n {
		n = affected
	}
	switch {
	case n >= 20:
		return 10
	case n >= 5:
		return 6
	case n >= 2:
		return 3
	}
	return 0
}
