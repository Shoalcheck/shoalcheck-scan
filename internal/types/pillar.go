package types

// Pillar is which of the product's two headline claims a finding belongs to, and it is a TENSE rather than a
// category.
//
// The report already organises findings on two axes — document function (overview, methodology, appendix) and
// finding category (security, reliability, observability…). The pillars are a third, and the distinction is
// what the finding's claim is ABOUT IN TIME:
//
//	Ground Truth      present — what is true right now that no dashboard shows you
//	Change Preflight  future  — what will stop you when you try to change this cluster
//
// The assignment test is the property that makes the distinction real: WE READ status, NOT spec. A Ground
// Truth finding rests on what a controller published — an EndpointSlice entry, status.disruptionsAllowed,
// status.lastSuccessfulTime. A Change Preflight finding is arithmetic over the snapshot about an operation
// that has not happened yet.
//
// A finding is assigned by WHAT ITS CLAIM IS, never by what its claim could imply. Two rules about
// availability under disruption — single-replica-no-pdb and no-anti-affinity — deliberately carry no pillar,
// because their claims are present-tense spec facts and moving them would mean rewording an existing claim.
//
// THE PILLARS ARE A LENS, NOT A PARTITION. Every finding stays in the report and in its category section;
// Summary.TotalFindings and EstimatedSavingsUSD are unchanged, which validate.go enforces. A pillar shows a
// SUBSET and has to say so, which is why the renderer prints each pillar's coverage rather than a bare count.
type Pillar string

const (
	// PillarNone is the zero value and it has to be CHOSEN, not defaulted into. A rule nobody classified
	// would otherwise land here silently, and "not part of either of this product's headline claims" is a
	// real editorial statement to make by forgetting. internal/rules requires an explicit entry per rule.
	PillarNone Pillar = ""

	PillarGroundTruth     Pillar = "ground-truth"
	PillarChangePreflight Pillar = "change-preflight"
	// PillarObservability is the third claim: whether the cluster's own reporting would tell you. A monitoring
	// stack is the one component that cannot report its own gaps — the thing that would raise the alarm IS the
	// thing that failed — and nothing in the surveyed field audits it. Every finding here is a STRUCTURAL fact
	// about the configuration (a selector that matches nothing, a route to a receiver that does not exist),
	// never a claim that an alert failed to fire, which is not visible from a snapshot.
	PillarObservability Pillar = "observability"
)

// Label is the pillar's name as a reader sees it. Kept on the type so the report, the fleet document and any
// future surface cannot word it three different ways — the same reason FindingBasis.Summary lives on its type.
func (p Pillar) Label() string {
	switch p {
	case PillarGroundTruth:
		return "Ground Truth"
	case PillarChangePreflight:
		return "Change Preflight"
	case PillarObservability:
		return "Monitoring Coverage"
	default:
		return ""
	}
}

// Question is what the pillar answers, in the reader's own terms. Printed under the section heading, because a
// section named "Ground Truth" with no question under it is a label rather than a claim.
func (p Pillar) Question() string {
	switch p {
	case PillarGroundTruth:
		return "What is true in this cluster right now that no dashboard shows you?"
	case PillarChangePreflight:
		return "What will stop you when you try to change this cluster?"
	case PillarObservability:
		return "If this went wrong, would your monitoring tell you?"
	default:
		return ""
	}
}
