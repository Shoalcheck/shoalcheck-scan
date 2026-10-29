package collect

import (
	"math"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func priced(id string, kind types.SpendKind, usd float64) types.Finding {
	return types.Finding{ID: id, RuleID: "r." + id, Category: types.CategoryCost, Severity: types.SeverityLow,
		DollarImpactMonthly: usd, PriceBasis: types.PricePriced, SpendKind: kind}
}

// TestBuildReport_DiscountReachesComputeSavingsAndOnlyThose is the whole defect in one assertion.
//
// Before 2026-09-02, --discount scaled the spend headline and never the savings, so the two numbers a
// reader compares first were denominated differently on the same page. The fix is not "scale the savings
// too": a Savings Plan covers instance hours, so only COMPUTE-denominated savings move. Storage, network
// and control-plane figures are list either way.
func TestBuildReport_DiscountReachesComputeSavingsAndOnlyThose(t *testing.T) {
	findings := []types.Finding{
		priced("compute", types.SpendCompute, 100),
		priced("storage", types.SpendStorage, 100),
		priced("network", types.SpendNetwork, 100),
		priced("cp", types.SpendControlPlane, 100),
	}
	ar := BuildReport(twoM6iLargeEKS(), findings, "c", 0.5, pricing.Embedded())

	// 100×0.5 + 100 + 100 + 100. Not 400 (the pre-fix number) and not 200 (a flat multiplier).
	if got, want := ar.Summary.EstimatedSavingsUSD, 350.0; math.Abs(got-want) > 0.01 {
		t.Errorf("EstimatedSavingsUSD = %.2f, want %.2f — 400 means the discount never reached the savings, "+
			"200 means it reached meters no compute commitment covers", got, want)
	}
	byID := map[string]float64{}
	for _, f := range ar.Findings {
		byID[f.ID] = f.DollarImpactMonthly
	}
	if byID["compute"] != 50 || byID["storage"] != 100 || byID["network"] != 100 || byID["cp"] != 100 {
		t.Errorf("per-finding dollars after a 50%% compute discount = %v, want compute:50 and the rest untouched", byID)
	}
}

// TestBuildReport_DiscountDoesNotChangeTheSavingsToSpendRatioForCompute is the property the defect broke.
// A cluster whose only dollars are compute keeps the same savings/spend ratio at any discount, because
// both are denominated in the same instance hours.
func TestBuildReport_DiscountDoesNotChangeTheSavingsToSpendRatioForCompute(t *testing.T) {
	// Over the NODE HOURS, which is what both figures are denominated in: the control-plane fee stays at list
	// under any discount (TestBuildReport_DiscountLeavesControlPlaneAndLoadBalancersAtList), so it is taken out
	// of the denominator rather than letting it move the ratio.
	ratio := func(d float64) float64 {
		ar := BuildReport(twoM6iLargeEKS(), []types.Finding{priced("rs", types.SpendCompute, 40)}, "c", d, pricing.Embedded())
		return ar.Summary.EstimatedSavingsUSD / (ar.Cluster.EstimatedMonthlySpend - pricing.EKSControlPlaneMonthlyUSD())
	}
	r0, r9 := ratio(0), ratio(0.9)
	if math.Abs(r0-r9) > 1e-6 {
		t.Errorf("savings/spend = %.4f at no discount and %.4f at 90%% — the ratio moved, so one of the two "+
			"numbers was scaled and the other was not (before the fix, at 0.9 the savings could EXCEED the spend)", r0, r9)
	}
}

// TestBuildReport_StorageStaysAtListUnderADiscount. The second half of the defect: the storage headline
// was multiplied by (1-discount), applying a compute commitment to GB-months.
func TestBuildReport_StorageStaysAtListUnderADiscount(t *testing.T) {
	inv := twoM6iLargeEKS()
	inv.PVs = []corev1.PersistentVolume{pv("p1", "gp3", 200)}
	list := BuildReport(inv, nil, "c", 0, pricing.Embedded())
	disc := BuildReport(inv, nil, "c", 0.5, pricing.Embedded())

	if list.Cluster.StorageMonthlyUSD <= 0 {
		t.Fatal("fixture priced no storage, so this test cannot see whether the discount reached it")
	}
	if math.Abs(list.Cluster.StorageMonthlyUSD-disc.Cluster.StorageMonthlyUSD) > 0.01 {
		t.Errorf("storage headline %.2f at list became %.2f under a 50%% COMPUTE discount — no Savings Plan "+
			"covers a GB-month", list.Cluster.StorageMonthlyUSD, disc.Cluster.StorageMonthlyUSD)
	}
	// spend = node hours×0.5 + control plane + storage: the fee and the storage both stay at list.
	cp := pricing.EKSControlPlaneMonthlyUSD()
	nodes := list.Cluster.EstimatedMonthlySpend - list.Cluster.StorageMonthlyUSD - cp
	wantDisc := nodes*0.5 + cp + list.Cluster.StorageMonthlyUSD
	if math.Abs(disc.Cluster.EstimatedMonthlySpend-wantDisc) > 0.01 {
		t.Errorf("discounted spend = %.2f, want compute/2 + storage = %.2f", disc.Cluster.EstimatedMonthlySpend, wantDisc)
	}
}

// TestBuildReport_AnUndeclaredKindIsLeftAtList. The safe direction: a rule that forgot SpendKind has its
// discount WITHHELD, never applied — and a fixture gate names it, so this state is loud rather than silent.
func TestBuildReport_AnUndeclaredKindIsLeftAtList(t *testing.T) {
	f := priced("forgot", types.SpendUnknown, 100)
	ar := BuildReport(twoM6iLargeEKS(), []types.Finding{f}, "c", 0.5, pricing.Embedded())
	if ar.Findings[0].DollarImpactMonthly != 100 {
		t.Errorf("a finding with no SpendKind was scaled to %.2f — the discount must be withheld from an "+
			"undeclared meter, not applied to it", ar.Findings[0].DollarImpactMonthly)
	}
}

// THE CONTROL PLANE AND THE LOAD BALANCERS STAY AT LIST, AS THE HELP SAYS.
//
// `--discount 0.3` on the mesh testbed stated a monthly spend of $358.72: 0.7 × $512.46, every dollar of it
// discounted — the EKS control-plane fee and the NLB base among them — while the flag's help, and the methodology
// note beside the figure, both say "storage, load balancers and control plane stay at list". estimateMonthlySpend
// returned compute and fees as one sum, and the discount was applied to the sum.
func TestBuildReport_DiscountLeavesControlPlaneAndLoadBalancersAtList(t *testing.T) {
	inv := twoM6iLargeEKS()
	inv.Services = []corev1.Service{{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}}
	per, _ := pricing.NodeMonthlyUSD("eks", "eu-central-1", "m6i.large", types.CapacityUnknown)
	lb, _ := pricing.Embedded().LBMonthly("eks", "eu-central-1")
	want := 0.7*2*per + pricing.EKSControlPlaneMonthlyUSD() + lb
	got := BuildReport(inv, nil, "c", 0.3, pricing.Embedded()).Cluster.EstimatedMonthlySpend
	if math.Abs(got-want) > 0.01 {
		t.Errorf("spend at a 30%% compute discount = %.2f, want %.2f (nodes at 70%%, control plane %.2f and load "+
			"balancer %.2f at list)", got, want, pricing.EKSControlPlaneMonthlyUSD(), lb)
	}
}

// A DISCOUNTED FINDING SAYS SO BESIDE ITS ARITHMETIC.
//
// The rightsizing finding on the mesh testbed carried $33.84 after a 30% discount, while its own evidence still
// ended "-> memory-bound up to $48.34/mo" — two figures for one finding, side by side, and nothing joining them.
// The rules price at list and the discount is applied afterwards, so the evidence gains the line that reconciles
// the two.
func TestBuildReport_ADiscountedFindingReconcilesItsEvidence(t *testing.T) {
	f := priced("rs", types.SpendCompute, 48.34)
	f.Evidence = []string{"$ model: … -> memory-bound up to $48.34/mo"}
	ar := BuildReport(twoM6iLargeEKS(), []types.Finding{f, priced("st", types.SpendStorage, 10)}, "c", 0.3, pricing.Embedded())
	for _, g := range ar.Findings {
		switch g.ID {
		case "rs":
			last := g.Evidence[len(g.Evidence)-1]
			if !strings.Contains(last, "$33.84") || !strings.Contains(last, "30%") || !strings.Contains(last, "list") {
				t.Errorf("the discounted finding's evidence does not reconcile its figure: %q", last)
			}
		case "st":
			if strings.Contains(strings.Join(g.Evidence, " "), "discount") {
				t.Error("a storage finding, which the discount does not reach, was annotated as discounted")
			}
		}
	}
}
