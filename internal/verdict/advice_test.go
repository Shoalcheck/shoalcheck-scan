package verdict

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A REMEDY THAT NEEDS A PERSON IS NOT A PROBLEM THAT MAY NOT APPLY. The final review found the reading's only
// critical — a ServiceAccount bound to cluster-admin, whose own text says "the grant itself is a fact" — ranked
// "conditional", below every low and info, because its least-privilege manifest carries a placeholder. A
// placeholder rightly keeps a remedy from being called safe; it says nothing about whether the problem is real.
func TestTierOf_APlaceholderRemedyIsNotAProblemThatMayNotApply(t *testing.T) {
	certain := types.Finding{ID: "f-1", RuleID: "k8s.rbac.cluster-admin-serviceaccount", Severity: types.SeverityCritical,
		Description:     "The grant itself is a fact.",
		RemediationYAML: "# fill the rules below (placeholder)\nkind: ClusterRole\n"}
	if got := TierOf(certain); got != TierCritical {
		t.Errorf("a certain critical with a placeholder remedy is ranked %q", got.Label())
	}
	if got := ClassifyWith(certain, nil); got == SafeNow {
		t.Error("a placeholder remedy was called safe to apply")
	}
	maybe := certain
	maybe.Description = "This may not apply where the CNI ignores policy."
	if got := TierOf(maybe); got != TierConditional {
		t.Errorf("a finding that says it may not apply is ranked %q", got.Label())
	}
}

// THE PODIUM NAMES AN OBJECT ONCE. Two of three cards were one PodDisruptionBudget — "blocks node drains" and
// "the drain of a node is blocked by" it — so the third thing worth doing never reached the screen. A candidate
// whose subject a higher card already names gives its place to the next one; it stays in the queue.
func TestSelect_ThePodiumNamesAnObjectOnce(t *testing.T) {
	pdb := types.ResourceRef{Kind: "PodDisruptionBudget", Namespace: "shop", Name: "zero"}
	fs := []types.Finding{
		{ID: "f-a", RuleID: "k8s.reliability.pdb-blocks-drains", Severity: types.SeverityMedium, Pillar: types.PillarChangePreflight,
			AffectedResources: []types.ResourceRef{pdb, {Kind: "Deployment", Namespace: "shop", Name: "api"}}},
		{ID: "f-b", RuleID: "k8s.reliability.node-drain-budget", Severity: types.SeverityMedium, Pillar: types.PillarChangePreflight,
			AffectedResources: []types.ResourceRef{{Kind: "Node", Name: "n1"}, pdb}},
		{ID: "f-c", RuleID: "k8s.workload.no-probes", Severity: types.SeverityHigh,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "shop", Name: "web"}}},
		{ID: "f-d", RuleID: "k8s.workload.mutable-image-tags", Severity: types.SeverityMedium,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "shop", Name: "cart"}}},
	}
	sel := SelectWith(fs, 3, nil)
	seen := map[string]bool{}
	for _, r := range sel.Top {
		seen[r.Finding.ID] = true
	}
	if seen["f-a"] && seen["f-b"] {
		t.Errorf("the podium names the same PodDisruptionBudget twice: %v", seen)
	}
	if len(sel.Top) != 3 {
		t.Errorf("%d cards, want 3 — the place a repeat gave up goes to the next finding", len(sel.Top))
	}
	if sel.RestCount+countStood(sel.Top) != len(fs) {
		t.Errorf("the podium and the rest stand for %d findings, the reading has %d", sel.RestCount+countStood(sel.Top), len(fs))
	}
}

func countStood(top []Ranked) int {
	n := 0
	for _, r := range top {
		n += r.CollapsedFrom
	}
	return n
}

// THE SAFEST PLACE TO BEGIN NEVER MULTIPLIES A RISK. "Scale deployment/privileged-pod to 2 replicas" was offered as
// safe to apply: additive, yes — and it doubles a workload carrying its own high host-access finding.
func TestStartHere_NeverScalesUpAWorkloadWithAHighSecurityFinding(t *testing.T) {
	priv := types.ResourceRef{Kind: "Deployment", Namespace: "shop", Name: "privileged"}
	plain := types.ResourceRef{Kind: "Deployment", Namespace: "shop", Name: "plain"}
	scale := func(id string, ref types.ResourceRef) types.Finding {
		return types.Finding{ID: id, RuleID: "k8s.workload.single-replica-no-pdb", Severity: types.SeverityMedium,
			AffectedResources: []types.ResourceRef{ref}, EstimatedEffort: types.EffortLow,
			RemediationCommand: "kubectl -n shop scale deployment/" + ref.Name + " --replicas=2"}
	}
	fs := []types.Finding{
		scale("f-1", priv),
		{ID: "f-2", RuleID: "k8s.workload.privileged-host-access", Severity: types.SeverityHigh,
			Category: types.CategorySecurity, AffectedResources: []types.ResourceRef{priv}},
	}
	replicas := ReplicaLookup(func(ref types.ResourceRef) (int, bool) { return 1, true })
	if sel := SelectWith(fs, 3, replicas); sel.StartHere != nil && sel.StartHere.Finding.ID == "f-1" {
		t.Error("scaling up a workload with a high security finding was offered as the safest place to begin")
	}
	fs = append(fs, scale("f-3", plain))
	if sel := SelectWith(fs, 3, replicas); sel.StartHere == nil || sel.StartHere.Finding.ID != "f-3" {
		t.Errorf("the plain workload's scale-up should be the safest start; got %+v", sel.StartHere)
	}
}
