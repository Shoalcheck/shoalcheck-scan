package pipeline

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A FINDING THAT RESTS ON NO USAGE MUST NOT NAME A USAGE SOURCE.
//
// FOUND BY DRIVING shoalcheck-mcp AND READING WHAT A MODEL RECEIVES. `explain_finding` on an RBAC grant came
// back with `"basis": {"kinds": […], "usageSource": "prometheus", "requests": […]}` — on
// `k8s.rbac.dangerous-grant`, a rule with no usage dimension whatsoever.
//
// Measured across a real 192-finding reading: **186 findings carried `usageSource: "prometheus"` with
// `usageRequired: false`.** Only 4 genuinely require usage.
//
// WHY IT MATTERS MORE ON THAT SURFACE THAN ON THE PAGE. `FindingBasis.Summary()` guards the usage clause
// behind `UsageRequired`, so the prose a person reads is correct. The MCP payload serialises the STRUCT,
// and `usageRequired: false` is dropped by omitempty — so a model sees a bare `usageSource: "prometheus"`
// and can only conclude the finding rests on Prometheus data. Asked "which findings depend on metrics?", it
// would answer 186 instead of 4.
//
// THE FIELDS ARE DEFINED AS A PAIR, in their own doc: "UsageRequired marks a finding that exists only where
// Prometheus usage was resolved; UsageSource names what supplied it. TOGETHER they say why a rightsizing
// figure is present at all." One without the other is not a partial statement — it is a different one.
//
// So the source is stamped only where something required it. The data becomes honest at the producer and
// every surface inherits that, rather than each renderer having to remember the guard — which is the same
// argument M-53 made about the money cell and M-58 about the analyzer ids.
func TestFindingBasis_NamesAUsageSourceOnlyWhereUsageIsRequired(t *testing.T) {
	ar := &types.AuditReport{
		Methodology: types.Methodology{
			CollectedKinds: []string{"pods", "nodes", "clusterroles", "clusterrolebindings", "roles", "rolebindings"},
			RunBasis:       &types.RunBasis{UsageSource: "prometheus"},
		},
		Findings: []types.Finding{
			{ID: "f-rbac", RuleID: "k8s.rbac.dangerous-grant"},
			{ID: "f-cost", RuleID: "k8s.cost.overprovisioned-resources"},
		},
	}
	attachFindingBasis(ar, false)

	byID := map[string]*types.FindingBasis{}
	for i := range ar.Findings {
		byID[ar.Findings[i].ID] = ar.Findings[i].Basis
	}
	rbac, cost := byID["f-rbac"], byID["f-cost"]
	if rbac == nil || cost == nil {
		t.Fatal("attachFindingBasis left a finding with no basis, so this test measures nothing")
	}
	// The premise: these two rules must genuinely differ in whether they read usage, or the assertions
	// below prove nothing about the guard.
	if rbac.UsageRequired {
		t.Fatal("k8s.rbac.dangerous-grant now declares a usage dependency; pick another rule that does not")
	}
	if !cost.UsageRequired {
		t.Fatal("k8s.cost.overprovisioned-resources no longer declares a usage dependency; this test needs " +
			"one rule of each kind or it is measuring a single case twice")
	}

	if rbac.UsageSource != "" {
		t.Errorf("an RBAC finding names usageSource %q while usageRequired is false. On the agent surface "+
			"usageRequired is dropped by omitempty, so a model sees a bare source and concludes the finding "+
			"rests on Prometheus data. The two fields are defined as a pair — one without the other is a "+
			"different statement, not a partial one.", rbac.UsageSource)
	}
	if cost.UsageSource != "prometheus" {
		t.Errorf("a rightsizing finding does rest on usage and its basis names no source (%q) — the reader "+
			"is then told a figure exists and not what supplied it", cost.UsageSource)
	}
}
