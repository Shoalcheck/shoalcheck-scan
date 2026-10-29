package rules

import (
	"math"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

func awsPool(itype string, n int) *collect.Inventory {
	inv := &collect.Inventory{}
	for i := 0; i < n; i++ {
		node := poolNode("n"+string(rune('a'+i)), "eu-central-1", itype, "4", "16Gi")
		node.Spec.ProviderID = "aws:///eu-central-1a/i-0" + string(rune('a'+i))
		node.Status.NodeInfo.Architecture = "amd64"
		inv.Nodes = append(inv.Nodes, node)
	}
	return inv
}

func monthly(t *testing.T, itype string) float64 {
	t.Helper()
	m, ok := pricing.NodeMonthlyUSD("aws", "eu-central-1", itype, "on-demand")
	if !ok {
		t.Fatalf("this build prices no %s in eu-central-1", itype)
	}
	return m
}

// TestGenerationLag_TheFigureIsTheDeltaTimesTheNodes — the over-claim this pins is reporting the current
// pool's whole bill as recoverable. t2 -> t3 is a same-class, newer-generation case in every region.
func TestGenerationLag_TheFigureIsTheDeltaTimesTheNodes(t *testing.T) {
	got := InstanceGenerationLag{}.Evaluate(awsPool("t2.large", 3), Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding for a t2.large pool, got %d", len(got))
	}
	want := (monthly(t, "t2.large") - monthly(t, "t3.large")) * 3
	if math.Abs(got[0].DollarImpactMonthly-want) > 0.01 {
		t.Errorf("DollarImpactMonthly = %.2f, want the DIFFERENCE x 3 nodes = %.2f (a figure near %.2f means the "+
			"pool's whole cost was claimed)", got[0].DollarImpactMonthly, want, monthly(t, "t2.large")*3)
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "t3.large") {
		t.Error("the evidence does not name the proposed type")
	}
}

// TestGenerationLag_GravitonIsNeverInTheFigure. m6i.xlarge has an AMD equivalent (bankable) and a cheaper
// Graviton one (not). The dollar must come from the x86 option; the arm64 number is evidence only.
func TestGenerationLag_GravitonIsNeverInTheFigure(t *testing.T) {
	got := InstanceGenerationLag{}.Evaluate(awsPool("m6i.xlarge", 2), Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	cur := monthly(t, "m6i.xlarge")
	amd := monthly(t, "m6a.xlarge")
	if amd >= cur {
		t.Skip("m6a.xlarge is not cheaper than m6i.xlarge in this table; the premise is gone")
	}
	wantX86 := (cur - amd) * 2
	if math.Abs(got[0].DollarImpactMonthly-wantX86) > 0.01 {
		t.Errorf("DollarImpactMonthly = %.2f, want the x86 (AMD) delta %.2f — a larger number means the "+
			"Graviton saving was banked, and whether the images run on arm64 is unreadable here", got[0].DollarImpactMonthly, wantX86)
	}
	ev := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(ev, "NOT BANKED") || !strings.Contains(ev, "arm64") {
		t.Error("the Graviton option must appear in the evidence, marked as not banked and naming arm64")
	}
}

// TestGenerationLag_RefusesShapesTheTableCannotDescribe — a GPU family and a local-NVMe variant say nothing.
func TestGenerationLag_RefusesShapesTheTableCannotDescribe(t *testing.T) {
	for _, itype := range []string{"g5.xlarge", "m5d.xlarge", "i3.large", "p4d.24xlarge", "mac2.metal"} {
		if got := (InstanceGenerationLag{}).Evaluate(awsPool(itype, 1), Options{}); len(got) != 0 {
			t.Errorf("%s produced %d finding(s); its shape is not vCPU+memory and must not be compared", itype, len(got))
		}
	}
}

// TestGenerationLag_OneFindingPerPool.
func TestGenerationLag_OneFindingPerPool(t *testing.T) {
	inv := awsPool("t2.large", 4)
	if got := (InstanceGenerationLag{}).Evaluate(inv, Options{}); len(got) != 1 {
		t.Errorf("4 nodes of one type produced %d finding(s), want 1", len(got))
	}
}

// TestGenerationLag_NotAWSIsSilence — no shape table, no comparison.
func TestGenerationLag_NotAWSIsSilence(t *testing.T) {
	inv := &collect.Inventory{Nodes: []corev1.Node{poolNode("n1", "westeurope", "Standard_D4s_v3", "4", "16Gi")}}
	inv.Nodes[0].Spec.ProviderID = "azure:///sub/x"
	if got := (InstanceGenerationLag{}).Evaluate(inv, Options{}); len(got) != 0 {
		t.Errorf("an Azure pool produced %d finding(s); there is no shape table to guard the comparison", len(got))
	}
}

// TestParseAWSType_TakesNamesApartTheWayAWSBuildsThem.
func TestParseAWSType_TakesNamesApartTheWayAWSBuildsThem(t *testing.T) {
	for _, c := range []struct {
		in                                 string
		family, vendor, extras, dash, size string
		gen                                int
		comparable                         bool
	}{
		{"m6idn.2xlarge", "m", "i", "dn", "", "2xlarge", 6, false},
		{"c7i-flex.large", "c", "i", "", "-flex", "large", 7, true},
		{"m5.xlarge", "m", "", "", "", "xlarge", 5, true},
		{"t4g.medium", "t", "g", "", "", "medium", 4, true},
		{"r6a.4xlarge", "r", "a", "", "", "4xlarge", 6, true},
		{"g5.xlarge", "g", "", "", "", "xlarge", 5, false},
		{"m5zn.large", "m", "", "zn", "", "large", 5, true},
	} {
		got, ok := parseAWSType(c.in)
		if !ok {
			t.Errorf("%s did not parse", c.in)
			continue
		}
		if got.family != c.family || got.vendor != c.vendor || got.extras != c.extras || got.dash != c.dash || got.size != c.size || got.gen != c.gen {
			t.Errorf("%s -> %+v", c.in, got)
		}
		if got.comparable() != c.comparable {
			t.Errorf("%s comparable = %v, want %v", c.in, got.comparable(), c.comparable)
		}
	}
	if _, ok := parseAWSType("Standard_D4s_v3"); ok {
		t.Error("an Azure SKU parsed as an AWS type")
	}
}

// TestEquivalentShape_SameVCPUAtLeastTheMemory.
func TestEquivalentShape_SameVCPUAtLeastTheMemory(t *testing.T) {
	cur := pricing.Shape{VCPU: 4, MemGiB: 16}
	if !equivalentShape(cur, pricing.Shape{VCPU: 4, MemGiB: 16}) || !equivalentShape(cur, pricing.Shape{VCPU: 4, MemGiB: 32}) {
		t.Error("an equal or larger-memory shape with the same vCPU must qualify")
	}
	if equivalentShape(cur, pricing.Shape{VCPU: 2, MemGiB: 16}) || equivalentShape(cur, pricing.Shape{VCPU: 4, MemGiB: 8}) || equivalentShape(cur, pricing.Shape{VCPU: 8, MemGiB: 16}) {
		t.Error("fewer vCPU, less memory, or MORE vCPU must all be rejected — a different machine is not an equivalent")
	}
}
