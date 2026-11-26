package pipeline

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ONE NODE'S BILL IS COUNTED ONCE (ENG-08). A $200/mo node: rightsizing reclaims a quarter of it ($50), and the
// pool's generation lag says a newer type is $40 cheaper. Added, the headline said $90; the lag is saved only on
// the three quarters that stay, so it counts $30 and the two together $80. A second node with three findings that
// would sum past its price is scaled to the price. Switched off (no reconcile), the sum is the double count.
func TestReconcileSpend_ANodesBillIsCountedOnce(t *testing.T) {
	findings := []types.Finding{
		{ID: "rs", RuleID: rightsizingRule, Title: "Right-size web", DollarImpactMonthly: 50, SpendKind: types.SpendCompute,
			SpendNodes: []types.SpendShare{{Node: "n1", USD: 50}}},
		{ID: "gen", RuleID: "k8s.cost.instance-generation-lag", Title: "Newer type", DollarImpactMonthly: 80, SpendKind: types.SpendCompute,
			SpendNodes: []types.SpendShare{{Node: "n1", USD: 40}, {Node: "n2", USD: 40}}},
		{ID: "a", RuleID: "x", Title: "A", DollarImpactMonthly: 90, SpendNodes: []types.SpendShare{{Node: "n3", USD: 90}}},
		{ID: "b", RuleID: "y", Title: "B", DollarImpactMonthly: 60, SpendNodes: []types.SpendShare{{Node: "n3", USD: 60}}},
	}
	reconcileSpend(findings, map[string]float64{"n1": 200, "n2": 200, "n3": 100})
	want := map[string]float64{"rs": 50, "gen": 30 + 40, "a": 60, "b": 40}
	for _, f := range findings {
		if math.Abs(f.DollarImpactMonthly-want[f.ID]) > 0.001 {
			t.Errorf("%s: $%.2f, want $%.2f", f.ID, f.DollarImpactMonthly, want[f.ID])
		}
	}
	if ev := strings.Join(findings[1].Evidence, "\n"); !strings.Contains(ev, `counted once: $10.00/mo of this figure prices the same nodes as "Right-size web"`) {
		t.Errorf("the generation finding must say what was counted once and with what:\n%s", ev)
	}
	if len(findings[0].Evidence) != 0 {
		t.Errorf("the rightsizing figure did not move and must not say it did: %v", findings[0].Evidence)
	}
	n3 := 0.0
	for _, f := range findings[2:] {
		n3 += f.DollarImpactMonthly
	}
	if math.Abs(n3-100) > 0.001 {
		t.Errorf("node n3's findings add up to $%.2f of a $100 node", n3)
	}
}

// Validate refuses a reading whose compute findings claim more than the compute bill, and one whose declared node
// shares do not add up to the dollar.
func TestValidate_SavingsNeverExceedTheBill(t *testing.T) {
	ar := &types.AuditReport{Cluster: types.ClusterInfo{EstimatedMonthlySpend: 100},
		Findings: []types.Finding{{ID: "f", RuleID: "r", Title: "t", Severity: types.SeverityLow, Category: types.CategoryCost,
			EstimatedEffort: types.EffortLow, DollarImpactMonthly: 150, Evidence: []string{"e"}, SpendKind: types.SpendCompute,
			SpendNodes: []types.SpendShare{{Node: "n", USD: 140}}}}}
	ar.Summary = types.DeriveSummary(ar.Findings)
	err := ar.Validate()
	if err == nil {
		t.Fatal("a reading whose compute findings claim more than the compute bill validated")
	}
	all := err.Error()
	if !strings.Contains(all, "savings integrity: compute findings claim $150.00/mo of a $100.00/mo compute bill") ||
		!strings.Contains(all, "spendNodes sum to 140.00 but dollarImpactMonthly is 150.00") {
		t.Fatalf("validation did not refuse the double count:\n%s", all)
	}
}

// ONE RULE'S PANIC IS ONE RULE'S FAILURE (ENG-23). There was no recover in the engine: a nil dereference in one rule
// on an object nobody had imagined ended the reading and every other rule's findings with it.
func TestIsolated_APanicIsARuleFailureNotTheEndOfTheReading(t *testing.T) {
	fs, f := isolated("k8s.test.panics", func() []types.Finding { var m map[string]*int; return []types.Finding{{ID: fmt.Sprint(*m["x"])}} })
	if fs != nil || f == nil || f.Rule != "k8s.test.panics" || !strings.Contains(f.Error, "nil pointer") {
		t.Fatalf("a panicking rule gave findings %v and failure %+v", fs, f)
	}
	fs, f = isolated("k8s.test.fine", func() []types.Finding { return []types.Finding{{ID: "a"}} })
	if len(fs) != 1 || f != nil {
		t.Fatalf("a rule that ran gave %v, failure %+v", fs, f)
	}
}
