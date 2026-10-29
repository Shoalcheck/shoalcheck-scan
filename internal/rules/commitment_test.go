package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

// TestCommitment_TheFigureIsDisclosedAndNeverBanked is the design in one assertion: the evidence names the
// would-be monthly figure and the two conditions; DollarImpactMonthly stays zero.
func TestCommitment_TheFigureIsDisclosedAndNeverBanked(t *testing.T) {
	if _, ok := pricing.SavingsPlanHourly("eu-central-1", "1yr", "m6i.xlarge"); !ok {
		t.Skip("this build carries no Savings Plan rate for eu-central-1/m6i.xlarge")
	}
	// awsPool carries no capacity label, and on AWS an absent label is CapacityUnknown, never on-demand;
	// the rule must stay silent on it — an unknown capacity is not evidence of anything.
	if got := (CommitmentCandidate{}).Evaluate(awsPool("m6i.xlarge", 3), Options{}); len(got) != 0 {
		t.Fatalf("an unlabeled AWS pool produced %d finding(s); unknown capacity must be silent", len(got))
	}
	inv := onDemand(awsPool("m6i.xlarge", 3))
	got := CommitmentCandidate{}.Evaluate(inv, Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding for one on-demand pool, got %d", len(got))
	}
	f := got[0]
	if f.DollarImpactMonthly != 0 {
		t.Errorf("DollarImpactMonthly = %.2f, want 0 — a commitment on a snapshot is a bet, not a saving", f.DollarImpactMonthly)
	}
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{"1yr No Upfront", "3yr No Upfront", "NOT BANKED", "billing-account fact", "past readings"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q", want)
		}
	}
}

// onDemand marks every node the way an EKS managed node group does.
func onDemand(inv *collect.Inventory) *collect.Inventory {
	for i := range inv.Nodes {
		inv.Nodes[i].Labels["eks.amazonaws.com/capacityType"] = "ON_DEMAND"
	}
	return inv
}

// TestCommitment_SpotPoolsAndOtherCloudsAreSilent.
func TestCommitment_SpotPoolsAndOtherCloudsAreSilent(t *testing.T) {
	spot := awsPool("m6i.xlarge", 2)
	for i := range spot.Nodes {
		spot.Nodes[i].Labels["eks.amazonaws.com/capacityType"] = "SPOT"
	}
	if got := (CommitmentCandidate{}).Evaluate(spot, Options{}); len(got) != 0 {
		t.Errorf("a spot pool produced %d finding(s); it is already discounted", len(got))
	}
	az := &collect.Inventory{Nodes: []corev1.Node{poolNode("n1", "westeurope", "Standard_D4s_v5", "4", "16Gi")}}
	az.Nodes[0].Spec.ProviderID = "azure:///sub/x"
	if got := (CommitmentCandidate{}).Evaluate(az, Options{}); len(got) != 0 {
		t.Errorf("an Azure pool produced %d finding(s); the rate table is AWS-only", len(got))
	}
}
