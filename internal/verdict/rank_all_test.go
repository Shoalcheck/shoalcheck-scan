package verdict

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Every finding appears exactly once; the podium's leaders come first and keep their class; the folded-away
// findings follow in report order.
func TestRankAll_EveryFindingOnceLeadersFirst(t *testing.T) {
	mk := func(id, rule string, sev types.Severity, usd float64) types.Finding {
		return types.Finding{ID: id, RuleID: rule, Title: id, Severity: sev, Category: types.CategoryCost, Confidence: 1,
			DollarImpactMonthly: usd, EstimatedEffort: types.EffortLow, Evidence: []string{"e"},
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: id}}}
	}
	fs := []types.Finding{
		mk("a", "r.1", types.SeverityLow, 0), mk("b", "r.1", types.SeverityLow, 0), mk("c", "r.1", types.SeverityLow, 0),
		mk("d", "r.2", types.SeverityHigh, 400), mk("e", "r.3", types.SeverityMedium, 20),
	}
	got := RankAll(fs, nil)
	if len(got) != len(fs) {
		t.Fatalf("%d ranked for %d findings", len(got), len(fs))
	}
	seen := map[string]int{}
	for _, r := range got {
		seen[r.Finding.ID]++
		if r.Safety == "" {
			t.Errorf("%s carries no safety class", r.Finding.ID)
		}
	}
	for _, f := range fs {
		if seen[f.ID] != 1 {
			t.Errorf("%s appears %d time(s)", f.ID, seen[f.ID])
		}
	}
	if got[0].Finding.ID != "d" {
		t.Errorf("the $400 high finding is not first: %s", got[0].Finding.ID)
	}
	if RankAll(nil, nil) != nil {
		t.Error("no findings ranks to something")
	}
}

// EVERY FINDING IS ITSELF, and for a while the leaders were not.
//
// SelectWith collapses near-duplicates for the PODIUM: the group's leader carries the union of every
// member's AffectedResources and the sum of their dollars, which is the right presentation for "three
// namespaces have no NetworkPolicy" on a cover. RankAll handed that mutated leader straight through as if it
// were the individual finding, under the leader's own id — and three surfaces printed it: `shoalcheck findings`
// in all five formats, the app's queue, and the terminal session.
//
// Measured on the real 839-finding AKS reading: `shoalcheck findings -o md` printed id f-05aeb1166a71 with
// **110 affected resources**, and that id in the reading's own JSON has **one**. A colleague who looks the
// id up gets a different fact; a SARIF alert fingerprinted on it carries 109 resources the finding never
// named; and the safety class was computed over 110 targets, which is why applying it was refused.
//
// The collapse stays where it belongs — inside the podium. A ranking function returns an ORDER.
func TestRankAll_ALeaderIsStillItsOwnFinding(t *testing.T) {
	mk := func(id string, refs ...string) types.Finding {
		f := types.Finding{ID: id, RuleID: "k8s.workload.single-replica-no-pdb", Title: id,
			Severity: types.SeverityHigh, Category: types.CategoryReliability, Confidence: 1,
			DollarImpactMonthly: 100, EstimatedEffort: types.EffortLow, Evidence: []string{"e"}}
		for _, r := range refs {
			f.AffectedResources = append(f.AffectedResources, types.ResourceRef{Kind: "Deployment", Namespace: "ns", Name: r})
		}
		return f
	}
	fs := []types.Finding{mk("a", "w1"), mk("b", "w2"), mk("c", "w3"), mk("d", "w4")}
	byID := map[string]types.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	for _, r := range RankAll(fs, nil) {
		orig, ok := byID[r.Finding.ID]
		if !ok {
			t.Fatalf("ranked an id that is not in the reading: %s", r.Finding.ID)
		}
		if len(r.Finding.AffectedResources) != len(orig.AffectedResources) {
			t.Errorf("%s carries %d affected resource(s); the finding of that id has %d — a reader who "+
				"looks the id up gets a different fact", r.Finding.ID,
				len(r.Finding.AffectedResources), len(orig.AffectedResources))
		}
		if r.Finding.DollarImpactMonthly != orig.DollarImpactMonthly {
			t.Errorf("%s carries $%.2f; the finding of that id carries $%.2f", r.Finding.ID,
				r.Finding.DollarImpactMonthly, orig.DollarImpactMonthly)
		}
	}
	// AND THE COLLAPSE IS STILL REPORTED, because how many findings share a rule is real information the
	// queue and the terminal both print. It is a count beside the row, never a mutation of it.
	var top *Ranked
	for _, r := range RankAll(fs, nil) {
		if r.CollapsedFrom > 1 {
			r := r
			top = &r
			break
		}
	}
	if top == nil {
		t.Fatal("four findings of one rule collapsed into no group, so this test proves nothing about the collapse")
	}
	if top.CollapsedFrom != 4 {
		t.Errorf("the leader stands for %d findings, want 4", top.CollapsedFrom)
	}
}

// THE RECONCILIATION, which is the sharpest measurement of the same defect.
//
// A collapsed leader carried the SUM of its group's dollars and its members still appeared individually
// below it, so the money was counted twice. On the real AKS reading the Markdown export's rows summed to
// $7,587 against a reading whose total is $4,457.76 — a 70% overstatement, in the column a buyer reads
// first, in a file they paste into a tracker.
//
// The property is exact and needs no fixture: a ranking is a permutation, so the dollars over the ranking
// equal the dollars over the reading.
func TestRankAll_TheMoneyIsThereadingsMoney(t *testing.T) {
	mk := func(id, rule string, usd float64) types.Finding {
		return types.Finding{ID: id, RuleID: rule, Title: id, Severity: types.SeverityHigh,
			Category: types.CategoryCost, Confidence: 1, DollarImpactMonthly: usd,
			EstimatedEffort: types.EffortLow, Evidence: []string{"e"},
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: id}}}
	}
	fs := []types.Finding{
		mk("a", "r.1", 100), mk("b", "r.1", 200), mk("c", "r.1", 300),
		mk("d", "r.2", 400), mk("e", "r.2", 50), mk("f", "r.3", 7),
	}
	var want, got float64
	for _, f := range fs {
		want += f.DollarImpactMonthly
	}
	for _, r := range RankAll(fs, nil) {
		got += r.Finding.DollarImpactMonthly
	}
	if got != want {
		t.Errorf("the ranking carries $%.2f over a reading of $%.2f — a reader summing the rows gets a "+
			"number the reading does not claim", got, want)
	}
}

// THE FOLDED FINDINGS FOLLOW THE LEADERS RULE BY RULE, not in report order. Every rule's leader comes first;
// after them, each rule's other findings in the leaders' order, by their own priority within the rule, every
// one carrying its rule's band and marked Folded. Before, the tail was report order, so on the AKS production
// reading the severity column restarted at row 42 with no mark of where or why.
func TestRankAll_TheFoldedFindingsFollowTheLeadersRuleByRule(t *testing.T) {
	mk := func(id, rule string, sev types.Severity) types.Finding {
		return types.Finding{ID: id, RuleID: rule, Title: id, Severity: sev, Category: types.CategorySecurity,
			Confidence: 1, Evidence: []string{"e"},
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "ns", Name: id}}}
	}
	fs := []types.Finding{
		mk("c2", "r.c", types.SeverityLow), mk("c1", "r.c", types.SeverityLow),
		mk("b1", "r.b", types.SeverityMedium),
		mk("a2", "r.a", types.SeverityLow), mk("a1", "r.a", types.SeverityHigh), mk("a3", "r.a", types.SeverityMedium),
	}
	got := RankAll(fs, nil)
	var order []string
	for _, r := range got {
		order = append(order, r.Finding.ID)
	}
	// c2 leads r.c: among equals the leader is the first in reading order, which for a real reading is
	// SortByPriority's total order.
	want := []string{"a1", "b1", "c2", "a3", "a2", "c1"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v: leaders, then each rule's others in the leaders' order", order, want)
		}
	}
	for i, r := range got {
		if r.Folded != (i >= 3) {
			t.Errorf("%s Folded=%v at position %d", r.Finding.ID, r.Folded, i)
		}
	}
	for _, r := range got[3:5] {
		if r.Tier != got[0].Tier {
			t.Errorf("%s is in band %q and its rule's leader in %q: a finding is ranked with its rule",
				r.Finding.ID, r.Tier.Label(), got[0].Tier.Label())
		}
	}
}
