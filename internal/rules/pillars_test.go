package rules

import (
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A RULE NOBODY CLASSIFIED MUST FAIL THE BUILD, NOT DEFAULT TO "NEITHER".
//
// types.PillarNone is the zero value of a map lookup, so without this test a new rule lands silently outside
// both of the product's headline claims — and "this finding is part of neither Ground Truth nor Change
// Preflight" is a real editorial statement, not an absence. Making it by forgetting is the failure mode.
func TestEveryRuleDeclaresAPillar(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	table := PillarByRule()
	if len(All()) == 0 {
		t.Fatal("the registry is empty, so this assertion would pass having checked nothing")
	}
	var missing []string
	for _, r := range All() {
		if _, ok := table[r.ID()]; !ok {
			missing = append(missing, r.ID())
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d registered rule(s) declare no pillar. PillarNone is a valid answer and has to be WRITTEN, "+
			"because a missing entry and a deliberate abstention are different statements:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	// And the reverse: an entry for a rule that no longer exists is a stale declaration that will mislead
	// the next reader about the shape of the set.
	live := map[string]bool{}
	for _, r := range All() {
		live[r.ID()] = true
	}
	var orphaned []string
	for id := range table {
		if !live[id] {
			orphaned = append(orphaned, id)
		}
	}
	sort.Strings(orphaned)
	if len(orphaned) > 0 {
		t.Errorf("%d pillar entr(ies) name a rule that is not registered:\n  %s",
			len(orphaned), strings.Join(orphaned, "\n  "))
	}
}

// THE SHAPE OF THE SET IS THE POINT, so it is pinned. A silent reassignment — a rule quietly moved from
// Ground Truth to neither — would change what the document leads with, and nothing else in the suite reads
// the distribution.
func TestPillarAssignment_IsStableAndExplicit(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	counts := map[types.Pillar]int{}
	for _, r := range All() {
		counts[PillarByRule()[r.ID()]]++
	}
	for _, p := range []types.Pillar{types.PillarGroundTruth, types.PillarChangePreflight} {
		if counts[p] == 0 {
			t.Fatalf("pillar %q has no members, so every assertion about it below would be vacuous", p)
		}
	}
	// Raise or lower these deliberately. A diff here is a change to what the report leads with.
	//
	// GROUND TRUTH RAISED 7 -> 9, AND THE REASON IS THE INTERESTING PART. Five self-contradiction
	// rules shipped and only TWO joined a pillar: pdb-selects-no-pods reads the disruption
	// controller's status.expectedPods and quota-below-committed reads the quota controller's
	// status.used against its status.hard. The other three read spec on both sides and abstain — see
	// the block in pillars.go and TestPillarAbstentions_AreDeliberate.
	// CHANGE PREFLIGHT RAISED 9 -> 12 (2026-08-29): the B-5 resilience half — zone-pinned-volume,
	// zone-loss-feasibility and node-loss-feasibility. All three answer "what will stop your next change"
	// where the change is losing a node or a zone, which is the same question the rest of the drain family
	// asks at a narrower blast radius. None is Ground Truth: the constraint was always there and the operator
	// declared it, and what is new is the arithmetic over it.
	// GROUND TRUTH RAISED 9 -> 12 (2026-08-29): Sweep 3's spec-versus-status family — condition-unchanged,
	// daemonset-misscheduled and pvc-below-request. This is the largest single addition the pillar has taken
	// and it is the pillar's own definition arriving: "what a controller published that no dashboard shows".
	//
	// ONE WRINKLE, RECORDED RATHER THAN SMOOTHED. Q1's demotion criterion is per-RULE and observability is
	// per-FACT, and condition-unchanged is the first rule where those disagree. Sweep 0 marked node
	// conditions OBSERVABLE-ELSEWHERE=yes and Sweep 3 marked the stuck-condition rule no, and both are
	// right about their own subject: kube-state-metrics exports the node condition, and no dashboard is
	// showing that it last changed six weeks ago. A rule spanning both kinds of fact cannot be cleanly
	// demoted by a per-rule flag. Nothing acts on this today — the demotion mechanism is not built — and
	// the note is here so the build that does it inherits the problem rather than discovering it.
	// CHANGE PREFLIGHT RAISED 12 -> 13 (2026-08-29): autoscaler-floor-below-budget, from Sweep 4. Its
	// sibling rwo-volume-shared abstains, and the two together are this table's assignment test working:
	// one makes a claim about a future operation in its title, the other does not.
	const (
		// GROUND TRUTH 12 -> 14 (2026-08-29): the two oblique routes, each reading something a kubelet
		// published about itself and nothing else reports.
		// GROUND TRUTH 14 -> 15 (2026-08-30): pod-not-ready, which reads what a kubelet published about
		// a pod it is running.
		// GROUND TRUTH 15 -> 17, CHANGE PREFLIGHT 13 -> 14 (2026-08-30): Phase 1's last rows.
		// GROUND TRUTH 17 -> 18, CHANGE PREFLIGHT 14 -> 16 (2026-08-30): Upgrade Preflight, and the family
		// splitting across both pillars is the point rather than an untidiness — assigning all three to
		// Change Preflight because the epic is named "Upgrade Preflight" would be the epic deciding the
		// pillar. crd-conversion-webhook-unbacked claims a published EndpointSlice state, which is true of
		// the cluster today and would be true if nobody ever upgraded.
		wantGroundTruth = 18
		// CHANGE PREFLIGHT 16 -> 17 (2026-10-19): NodeDrainUnmanaged, kubectl drain's own refusal.
		wantChangePreflight = 17
	)
	if counts[types.PillarGroundTruth] != wantGroundTruth {
		t.Errorf("Ground Truth has %d rules, expected %d — a rule moved into or out of the pillar the "+
			"document leads with", counts[types.PillarGroundTruth], wantGroundTruth)
	}
	if counts[types.PillarChangePreflight] != wantChangePreflight {
		t.Errorf("Change Preflight has %d rules, expected %d", counts[types.PillarChangePreflight],
			wantChangePreflight)
	}
	t.Logf("pillars: %d Ground Truth, %d Change Preflight, %d neither (of %d rules)",
		counts[types.PillarGroundTruth], counts[types.PillarChangePreflight], counts[types.PillarNone], len(All()))
}

// THE TWO ABSTENTIONS ARE ASSERTED, because they are the entries most likely to be "tidied up" by someone who
// sees a reliability rule about disruption sitting outside Change Preflight and assumes it was an oversight.
// It is not: their claims are present-tense spec facts, and moving them would require rewording an existing
// claim, which needs founder approval.
func TestPillarAbstentions_AreDeliberate(t *testing.T) {
	table := PillarByRule()
	for _, id := range []string{"k8s.workload.single-replica-no-pdb", "k8s.workload.no-anti-affinity"} {
		got, ok := table[id]
		if !ok {
			t.Fatalf("%s has no entry, so this test cannot tell a deliberate abstention from an omission", id)
		}
		if got != types.PillarNone {
			t.Errorf("%s was assigned to %q. Its claim is a present-tense spec fact; assigning it to a "+
				"pillar about a future operation is only honest if the WORDING changes first, and that "+
				"needs sign-off. See pillars.go.", id, got)
		}
	}
}
