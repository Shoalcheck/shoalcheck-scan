package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// WHICH KIND A VALUE GETS WHEN TWO SITES COULD CLAIM IT — the question M-59 left open, measured.
//
// gatherIdentifiers maps a value to a token once: `if _, ok := m[val]; !ok`. The first site to reach a
// value decides its KIND, and the kind is hashed into the token (`token()` hashes prefix|value), so the
// winner decides the string every surface of a redacted reading will carry for that object.
//
// THIS IS NOT HYPOTHETICAL AND IT IS NOT RARE. Measured on testdata/golden/sample-audit.json: 12 values are
// both an affected resource and a node — every node in the reading — 8 are both an affected resource and an
// RBAC subject, and 5 are both an affected resource and a namespace. Findings are walked before
// Architecture, so `res` wins all twenty-five, which is the LEAST specific of the kinds available.
//
// NOTHING IS FALSE ABOUT THAT — a node is a resource, a ServiceAccount is a resource — and nothing parses
// the prefix: it is a hint to a human reading a document whose names have been removed. So the labelling
// stays as it is, and the reason it stays is written down here rather than left as an open question that
// gets re-proposed.
//
// WHAT WOULD BE A DEFECT IS THE ORDER CHANGING BY ACCIDENT. Reordering gatherIdentifiers — moving the
// Architecture walk above the findings walk, say — silently changes the token for every one of those
// twenty-five values, and a token IS the identity of an object across two redacted readings: the comparison
// verbs, the fleet switcher and a reader following one workload between two documents all key on it. This
// pins the decision so that a reorder is a decision somebody took.
func TestHarvest_AValueClaimedByTwoSitesTakesTheFirstDeterministically(t *testing.T) {
	// The fixture must be able to produce the state: one string that two sites both reach.
	const shared = "ip-10-0-1-a"

	ar := sampleReport()
	ar.Findings = append(ar.Findings, types.Finding{
		ID: "f-node", RuleID: "k8s.node.drain-blocked", RuleVersion: "1.0.0",
		Title: "A node that cannot be drained", Description: "A node that cannot be drained.",
		WhyItMatters: "Recorded by the harvest-kind gate.",
		Severity:     types.SeverityMedium, Category: types.CategoryReliability,
		Confidence: 0.9, EstimatedEffort: types.EffortLow,
		PriceBasis:        types.PriceNotCost,
		Evidence:          []string{"one node, named twice in one reading"},
		AffectedResources: []types.ResourceRef{{Kind: "Node", Name: shared}},
	})
	if ar.Architecture == nil {
		ar.Architecture = &types.Architecture{}
	}
	ar.Architecture.AZs = append(ar.Architecture.AZs, types.AZ{
		Name:  "eu-central-1z",
		Nodes: []types.NodeRef{{Name: shared}},
	})
	ar.Summary = types.DeriveSummary(ar.Findings)

	idents := gatherIdentifiers(ar)
	got, ok := idents[shared]
	if !ok {
		t.Fatalf("%q was reachable from two harvest sites and was not harvested at all; this test can no "+
			"longer see the state it is about", shared)
	}

	// THE FIRST SITE WINS, and the first site is the findings walk. `res`, not `node`: the least specific
	// of the two, on every node name in every reading this product has produced.
	if !strings.HasPrefix(got, "res-") {
		t.Errorf("a value reachable from the findings walk and from the node walk was tokenised as %q. "+
			"The findings walk runs first, so it takes the value; if that order changed on purpose, this "+
			"test is where the new decision is written down — and every token for the twenty-five "+
			"two-claimant values in the reference reading changes with it, which is the identity two "+
			"redacted readings are compared by.", got)
	}

	// ONE VALUE, ONE TOKEN, EVERYWHERE. This is the property the first-writer rule exists to keep, and it
	// is what makes the kind a labelling question rather than a correctness one.
	red := Report(ar)
	b, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), shared) {
		t.Errorf("%q survived redaction somewhere in the document", shared)
	}
	if n := strings.Count(string(b), got); n < 2 {
		t.Errorf("the token %q appears %d time(s): the value was reached from two sites, so a redacted "+
			"reading that carries it once has lost one of them", got, n)
	}

	// AND IT IS THE SAME TOKEN ON A SECOND RUN. TestReport_Deterministic already compares two redactions of
	// the sample; it could not see this state, because nothing in that fixture is claimed twice.
	again := gatherIdentifiers(ar)
	if again[shared] != got {
		t.Errorf("the same reading harvested twice gave %q then %q", got, again[shared])
	}
}
