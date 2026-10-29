package collect

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// twoM6iLargeEKS returns an inventory with two m6i.large nodes in eu-central-1
// behind an EKS provider id — the canonical priced fixture for cost tests.
func twoM6iLargeEKS() *Inventory {
	return &Inventory{
		Nodes: []corev1.Node{
			node("n1", "eu-central-1a", "m6i.large", "aws:///eu-central-1a/i-1"),
			node("n2", "eu-central-1b", "m6i.large", "aws:///eu-central-1b/i-2"),
		},
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
}

func TestBuildReport_NodeCosting_PricedEKS(t *testing.T) {
	ar := BuildReport(twoM6iLargeEKS(), nil, "c", 0, pricing.Embedded())

	per, ok := pricing.NodeMonthlyUSD("eks", "eu-central-1", "m6i.large", types.CapacityUnknown)
	if !ok {
		t.Fatal("test precondition: m6i.large must be priced in eu-central-1")
	}
	want := 2*per + pricing.EKSControlPlaneMonthlyUSD()

	if len(ar.Architecture.UnpricedNodeTypes) != 0 {
		t.Errorf("UnpricedNodeTypes = %v, want empty", ar.Architecture.UnpricedNodeTypes)
	}
	if len(ar.Architecture.NodePools) != 1 || math.Abs(ar.Architecture.NodePools[0].CostMo-per) > 0.01 {
		t.Errorf("pool CostMo = %v, want ~%v", ar.Architecture.NodePools, per)
	}
	if rel := math.Abs(ar.Cluster.EstimatedMonthlySpend-want) / want; rel > 0.01 {
		t.Errorf("EstimatedMonthlySpend = %.2f, want within 1%% of %.2f (rel=%.4f)",
			ar.Cluster.EstimatedMonthlySpend, want, rel)
	}
}

func TestBuildReport_NodeCosting_NLBAdded(t *testing.T) {
	inv := twoM6iLargeEKS()
	inv.Services = []corev1.Service{
		{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}},
		{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP}},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())

	per, _ := pricing.NodeMonthlyUSD("eks", "eu-central-1", "m6i.large", types.CapacityUnknown)
	nlb, _ := pricing.NLBMonthlyUSD("eu-central-1")
	want := 2*per + pricing.EKSControlPlaneMonthlyUSD() + nlb // one LoadBalancer Service
	if rel := math.Abs(ar.Cluster.EstimatedMonthlySpend-want) / want; rel > 0.01 {
		t.Errorf("spend with one NLB = %.2f, want ~%.2f", ar.Cluster.EstimatedMonthlySpend, want)
	}
}

func TestBuildReport_NodeCosting_UnpricedType(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			node("n1", "eu-central-1a", "m6i.large", "aws:///eu-central-1a/i-1"),
			node("n2", "eu-central-1b", "made.up.xl", "aws:///eu-central-1b/i-2"),
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())

	if got := ar.Architecture.UnpricedNodeTypes; len(got) != 1 || got[0] != "made.up.xl" {
		t.Errorf("UnpricedNodeTypes = %v, want [made.up.xl]", got)
	}
	// Spend counts only the priced node + EKS fee — never the unknown one.
	per, _ := pricing.NodeMonthlyUSD("eks", "eu-central-1", "m6i.large", types.CapacityUnknown)
	want := per + pricing.EKSControlPlaneMonthlyUSD()
	if rel := math.Abs(ar.Cluster.EstimatedMonthlySpend-want) / want; rel > 0.01 {
		t.Errorf("spend = %.2f, want ~%.2f (priced node only)", ar.Cluster.EstimatedMonthlySpend, want)
	}

	// AND THE POOL ITSELF MUST SAY SO. CostSource was stamped BEFORE the price lookup and the
	// price-not-found branch left it alone, so an unpriced pool travelled as
	// {cost: 0, costSource: "list-estimate"} — the same source string as a pool that WAS priced.
	//
	// The document survived that by cross-referencing Architecture.UnpricedNodeTypes. The instrument
	// cannot: the island carries the pools and never carried that list, so its Cost workspace printed
	// "$0" under the pool's name and "Standard_D4as_v5 · list-estimate" as the basis — a list-price
	// estimate asserted for a type that could not be priced. A fake zero in the one workspace whose
	// whole subject is money.
	//
	// "unpriced" is a cost source: it says where the figure came from, which is nowhere.
	var priced, unpriced *types.NodePoolSummary
	for i := range ar.Architecture.NodePools {
		switch ar.Architecture.NodePools[i].Type {
		case "m6i.large":
			priced = &ar.Architecture.NodePools[i]
		case "made.up.xl":
			unpriced = &ar.Architecture.NodePools[i]
		}
	}
	if priced == nil || unpriced == nil {
		t.Fatalf("expected both pools; got %+v", ar.Architecture.NodePools)
	}
	if unpriced.CostMo != 0 {
		t.Errorf("the unpriced pool carries $%.2f", unpriced.CostMo)
	}
	if unpriced.CostSource == priced.CostSource {
		t.Errorf("the unpriced pool and the priced pool both report CostSource %q, so nothing downstream "+
			"can tell a zero that was measured from a zero that means nothing", unpriced.CostSource)
	}
	if unpriced.CostSource != types.CostSourceUnpriced {
		t.Errorf("the unpriced pool's CostSource is %q, want %q", unpriced.CostSource, types.CostSourceUnpriced)
	}
	if priced.CostSource != types.CostSourceListEstimate {
		t.Errorf("the priced pool's CostSource became %q", priced.CostSource)
	}
}

func TestBuildReport_NodeCosting_AKSPriced(t *testing.T) {
	// AKS-style node with a real Azure SKU: multi-cloud tables now price it, so
	// spend is > 0 with no UnpricedNodeTypes. AKS control plane is the free tier
	// ($0), so spend == compute only here.
	inv := &Inventory{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "aks-0", Labels: map[string]string{
					"topology.kubernetes.io/region":    "westus3",
					"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
				}},
				Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "aks-1", Labels: map[string]string{
					"topology.kubernetes.io/region":    "westus3",
					"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
				}},
				Spec: corev1.NodeSpec{ProviderID: "azure:///sub/y"},
			},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "aks-dev", 0, pricing.Embedded())

	if ar.Cluster.Provider != "aks" {
		t.Fatalf("provider = %q, want aks", ar.Cluster.Provider)
	}
	if len(ar.Architecture.UnpricedNodeTypes) != 0 {
		t.Errorf("UnpricedNodeTypes = %v, want empty (Azure type is priced)", ar.Architecture.UnpricedNodeTypes)
	}
	per, ok := pricing.NodeMonthlyUSD("aks", "westus3", "Standard_D4lds_v5", types.CapacityUnknown)
	if !ok {
		t.Fatal("test precondition: Standard_D4lds_v5 must be priced in westus3")
	}
	want := 2*per + pricing.ControlPlaneMonthlyUSD("aks") // AKS control plane = $0
	if ar.Cluster.EstimatedMonthlySpend <= 0 {
		t.Fatalf("spend = %.2f, want > 0 (AKS node now priced)", ar.Cluster.EstimatedMonthlySpend)
	}
	if rel := math.Abs(ar.Cluster.EstimatedMonthlySpend-want) / want; rel > 0.01 {
		t.Errorf("spend = %.2f, want ~%.2f (2 × Azure node, free control plane)", ar.Cluster.EstimatedMonthlySpend, want)
	}
	if !methodologyHas(ar, "Azure on-demand list") {
		t.Errorf("methodology missing Azure source note: %v", ar.Methodology.DataSources)
	}
}

func TestBuildReport_NodeCosting_GKEPriced(t *testing.T) {
	// GKE-style node with a real GCP type: priced, plus the $0.10/h GKE
	// control-plane fee.
	inv := &Inventory{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "gke-0", Labels: map[string]string{
					"topology.kubernetes.io/region":    "us-central1",
					"node.kubernetes.io/instance-type": "e2-standard-4",
				}},
				Spec: corev1.NodeSpec{ProviderID: "gce://proj/zone/gke-0"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "gke-1", Labels: map[string]string{
					"topology.kubernetes.io/region":    "us-central1",
					"node.kubernetes.io/instance-type": "e2-standard-4",
				}},
				Spec: corev1.NodeSpec{ProviderID: "gce://proj/zone/gke-1"},
			},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "gke-dev", 0, pricing.Embedded())

	if ar.Cluster.Provider != "gke" {
		t.Fatalf("provider = %q, want gke", ar.Cluster.Provider)
	}
	if len(ar.Architecture.UnpricedNodeTypes) != 0 {
		t.Errorf("UnpricedNodeTypes = %v, want empty (GCP type is priced)", ar.Architecture.UnpricedNodeTypes)
	}
	per, ok := pricing.NodeMonthlyUSD("gke", "us-central1", "e2-standard-4", types.CapacityUnknown)
	if !ok {
		t.Fatal("test precondition: e2-standard-4 must be priced in us-central1")
	}
	want := 2*per + pricing.ControlPlaneMonthlyUSD("gke") // GKE control plane = $73/mo
	if ar.Cluster.EstimatedMonthlySpend <= 0 {
		t.Fatalf("spend = %.2f, want > 0 (GKE node now priced)", ar.Cluster.EstimatedMonthlySpend)
	}
	if rel := math.Abs(ar.Cluster.EstimatedMonthlySpend-want) / want; rel > 0.01 {
		t.Errorf("spend = %.2f, want ~%.2f (2 × GCP node + GKE control plane)", ar.Cluster.EstimatedMonthlySpend, want)
	}
	if !methodologyHas(ar, "GCP on-demand list") {
		t.Errorf("methodology missing GCP source note: %v", ar.Methodology.DataSources)
	}
}

// "neverlandcentral" IS DELIBERATE AND IS NOT A TYPO.
//
// This case used francecentral until 2026-08-31, when the pricing generator moved from four
// hand-listed Azure regions to all 69 the Retail API sells in — and francecentral became covered, so
// the assertion that an uncovered region suppresses the headline was quietly testing a covered one.
// A well-formed name no catalogue will ever carry keeps the case non-vacuous no matter how far
// coverage grows, which is the point: the suppression guard must go on being proven precisely
// BECAUSE the uncovered set is shrinking.
// TestBuildReport_UncoveredRegionSuppressesSpend is the credibility guard: an
// AKS cluster in a region the pricing table does NOT cover (neverlandcentral) must
// NOT present a misleading near-zero spend headline. Every node prices to $0, so
// without suppression the headline would be the bare LB/control-plane residue
// (or $0) in front of a paying buyer. BuildReport routes that into the honest
// "unpriced/unknown" state: spend == 0 (the existing $0 empty state), the node
// types recorded in UnpricedNodeTypes, and a methodology note naming the gap.
func TestBuildReport_UncoveredRegionSuppressesSpend(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "aks-0", Labels: map[string]string{
					"topology.kubernetes.io/region":    "neverlandcentral",
					"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
				}},
				Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "aks-1", Labels: map[string]string{
					"topology.kubernetes.io/region":    "neverlandcentral",
					"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
				}},
				Spec: corev1.NodeSpec{ProviderID: "azure:///sub/y"},
			},
		},
		// A LoadBalancer service whose flat Azure LB base would otherwise leak a
		// non-zero, misleading "$36/mo" headline with all compute at $0.
		Services: []corev1.Service{
			{Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "aks-fr", 0, pricing.Embedded())

	if ar.Cluster.Provider != "aks" {
		t.Fatalf("provider = %q, want aks", ar.Cluster.Provider)
	}
	if ar.Cluster.Region != "neverlandcentral" {
		t.Fatalf("region = %q, want neverlandcentral", ar.Cluster.Region)
	}
	// The headline must be suppressed to the honest $0 empty state, NOT a
	// fabricated low number assembled from LB residue.
	if ar.Cluster.EstimatedMonthlySpend != 0 {
		t.Errorf("EstimatedMonthlySpend = %.2f, want 0 (suppressed — region unpriced)", ar.Cluster.EstimatedMonthlySpend)
	}
	// The node type is honestly recorded as unpriced.
	if got := ar.Architecture.UnpricedNodeTypes; len(got) != 1 || got[0] != "Standard_D4lds_v5" {
		t.Errorf("UnpricedNodeTypes = %v, want [Standard_D4lds_v5]", got)
	}
	// Methodology says why the spend is suppressed (region not covered), so the
	// reader sees an honest gap rather than a silent $0.
	if !methodologyHas(ar, "neverlandcentral") {
		t.Errorf("methodology missing the uncovered-region note: %v", ar.Methodology.DataSources)
	}
}

// TestBuildReport_CoveredRegionStillPrices guards against over-suppression: a
// covered Azure region (westus3) must keep pricing normally.
func TestBuildReport_CoveredRegionStillPrices(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "aks-0", Labels: map[string]string{
					"topology.kubernetes.io/region":    "westus3",
					"node.kubernetes.io/instance-type": "Standard_D4lds_v5",
				}},
				Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"},
			},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "aks-ok", 0, pricing.Embedded())
	if ar.Cluster.EstimatedMonthlySpend <= 0 {
		t.Errorf("EstimatedMonthlySpend = %.2f, want > 0 (covered region must still price)", ar.Cluster.EstimatedMonthlySpend)
	}
}

func TestBuildReport_Discount(t *testing.T) {
	full := BuildReport(twoM6iLargeEKS(), nil, "c", 0, pricing.Embedded()).Cluster.EstimatedMonthlySpend
	half := BuildReport(twoM6iLargeEKS(), nil, "c", 0.5, pricing.Embedded()).Cluster.EstimatedMonthlySpend
	// The node hours halve; the control-plane fee does not, as the help and the methodology note both say.
	cp := pricing.EKSControlPlaneMonthlyUSD()
	if want := (full-cp)/2 + cp; math.Abs(half-want) > 0.01 {
		t.Errorf("discount 0.5: spend = %.2f, want half the node hours plus the fee at list = %.2f", half, want)
	}
	if !methodologyHas(BuildReport(twoM6iLargeEKS(), nil, "c", 0.5, pricing.Embedded()), "discount applied: 50%") {
		t.Error("methodology missing '50%' discount line")
	}
	if !methodologyHas(BuildReport(twoM6iLargeEKS(), nil, "c", 0, pricing.Embedded()), "no discount applied") {
		t.Error("methodology missing no-discount line")
	}
	// Out-of-range clamps rather than inflating.
	if neg := BuildReport(twoM6iLargeEKS(), nil, "c", -1, pricing.Embedded()).Cluster.EstimatedMonthlySpend; math.Abs(neg-full) > 0.01 {
		t.Errorf("negative discount = %.2f, want clamped to full %.2f", neg, full)
	}
}

func methodologyHas(ar *types.AuditReport, substr string) bool {
	for _, s := range ar.Methodology.DataSources {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func node(name, zone, itype, providerID string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			"topology.kubernetes.io/zone":      zone,
			"topology.kubernetes.io/region":    "eu-central-1",
			"node.kubernetes.io/instance-type": itype,
		}},
		Spec: corev1.NodeSpec{ProviderID: providerID},
	}
}

func TestBuildReport(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			node("n1", "eu-central-1a", "m6i.large", "aws:///eu-central-1a/i-1"),
			node("n2", "eu-central-1b", "m6i.large", "aws:///eu-central-1b/i-2"),
		},
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		},
		Deployments: []appsv1.Deployment{
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"},
				Spec: corev1.PodSpec{NodeName: "n1"}},
		},
		Meta: Meta{ServerVersion: "v1.30.2", Collected: []string{"nodes"}, StartedAt: time.Now(), Duration: 3 * time.Second},
	}
	f := types.Finding{
		ID: "f-abc", RuleID: "k8s.workload.missing-resource-requests", RuleVersion: "1.0.0",
		Title: "t", Description: "d", WhyItMatters: "w", Evidence: []string{"e"},
		Severity: types.SeverityMedium, Category: types.CategoryConfig,
		AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "default", Name: "app"}},
		EstimatedEffort:   types.EffortLow, Confidence: 1.0,
		Provenance: types.Provenance{Collector: "kubernetes", Version: "dev"},
	}
	ar := BuildReport(inv, []types.Finding{f}, "my-cluster", 0, pricing.Embedded())

	if err := ar.Validate(); err != nil {
		t.Fatalf("assembled report invalid: %v", err)
	}
	if ar.Cluster.Provider != "eks" {
		t.Errorf("provider = %q, want eks (from aws:// providerID)", ar.Cluster.Provider)
	}
	if ar.Cluster.Region != "eu-central-1" || ar.Cluster.NodeCount != 2 {
		t.Errorf("cluster info wrong: %+v", ar.Cluster)
	}
	if ar.Architecture == nil || len(ar.Architecture.AZs) != 2 {
		t.Fatalf("want 2 AZs, got %+v", ar.Architecture)
	}
	if len(ar.Architecture.NodePools) != 1 || ar.Architecture.NodePools[0].Count != 2 {
		t.Errorf("node pools wrong: %+v", ar.Architecture.NodePools)
	}
	if ar.Summary.TotalFindings != 1 {
		t.Errorf("summary not derived: %+v", ar.Summary)
	}
	// finding count attribution: namespace summary for "default" must show 1
	for _, ns := range ar.Architecture.Namespaces {
		if ns.Name == "default" && ns.FindingCount != 1 {
			t.Errorf("default ns findingCount = %d, want 1", ns.FindingCount)
		}
	}
}

func TestProviderFrom(t *testing.T) {
	cases := map[string]string{
		"aws:///eu/i-1":   "eks",
		"gce://proj/z/n":  "gke",
		"azure:///sub":    "aks",
		"kind://docker/x": "kind",
		"":                "unknown",
	}
	for pid, want := range cases {
		n := corev1.Node{Spec: corev1.NodeSpec{ProviderID: pid}}
		if got := providerFrom([]corev1.Node{n}); got != want {
			t.Errorf("providerFrom(%q) = %q, want %q", pid, got, want)
		}
	}
}

func TestBuildArchitecture_DefaultsToDeclaredTier(t *testing.T) {
	inv := &Inventory{} // no workloads, no telemetry
	arch := buildArchitecture(inv, nil, "eu-central-1", "eks", pricing.Embedded())
	if arch.Tier != types.TierDeclared {
		t.Errorf("Tier = %q, want declared (no Prometheus run is Tier-3 at assembly)", arch.Tier)
	}
}

// TestBuildReport_DeniedStackCRSurfacesInDataSources pins the honesty hook: a
// denied stack-CR list (cr:<group-resource> in Meta.Denied) must surface in the
// Methodology partial-collection note so a future refactor can't silently drop
// denied CRD lists from the methodology.
func TestBuildReport_DeniedStackCRSurfacesInDataSources(t *testing.T) {
	inv := &Inventory{
		Meta: Meta{
			ServerVersion: "v1.29.0",
			Collected:     []string{"nodes", "namespaces"},
			Denied:        []string{"cr:certificates.cert-manager.io: certificates.cert-manager.io is forbidden"},
		},
	}
	ar := BuildReport(inv, nil, "test", 0, pricing.Embedded())
	joined := strings.Join(ar.Methodology.DataSources, " | ")
	if !strings.Contains(joined, "cr:certificates.cert-manager.io") {
		t.Errorf("denied stack CR list must surface in DataSources partial-collection note: %v", ar.Methodology.DataSources)
	}
}

// TestPricingNote_StorageSummedOnlyWhenPVPVCListed pins fix #9: the pricing note
// must claim storage was "summed from PV/PVC" ONLY when both lists succeeded. PV
// is cluster-scoped and often RBAC-denied; a denied list must flip the note to an
// honest "not included / could not be enumerated" rather than assert a summed $0.
func TestPricingNote_StorageSummedOnlyWhenPVPVCListed(t *testing.T) {
	// Both lists collected ⇒ may legitimately claim "summed".
	listed := twoM6iLargeEKS()
	listed.Meta.Collected = append(listed.Meta.Collected, "persistentvolumes", "persistentvolumeclaims")
	if !methodologyHas(BuildReport(listed, nil, "c", 0, pricing.Embedded()), "summed from PV/PVC") {
		t.Error("with PV+PVC collected, the note may state storage was summed from PV/PVC")
	}

	// PV list DENIED ⇒ must NOT claim "summed"; must say storage was not enumerated.
	denied := twoM6iLargeEKS()
	denied.Meta.Denied = append(denied.Meta.Denied, "persistentvolumes: persistentvolumes is forbidden")
	denied.Meta.Collected = append(denied.Meta.Collected, "persistentvolumeclaims")
	arDenied := BuildReport(denied, nil, "c", 0, pricing.Embedded())
	if methodologyHas(arDenied, "summed from PV/PVC") {
		t.Errorf("denied PV list must NOT claim storage was summed (denial-blind overclaim): %v", arDenied.Methodology.DataSources)
	}
	if !methodologyHas(arDenied, "PV/PVC list was denied") {
		t.Errorf("denied PV list must be disclosed honestly in the note: %v", arDenied.Methodology.DataSources)
	}

	// Neither recorded (un-confirmed) ⇒ treated as not-listed (never assert success
	// we can't see): also must NOT claim "summed".
	unconfirmed := twoM6iLargeEKS() // Meta has no PV/PVC entries
	if methodologyHas(BuildReport(unconfirmed, nil, "c", 0, pricing.Embedded()), "summed from PV/PVC") {
		t.Error("un-confirmed PV/PVC list must NOT claim storage was summed")
	}
}

// nodeWithCapacity is `node` plus the machine shape the kubelet actually reports.
func nodeWithCapacity(name, zone, itype, providerID, cpu, mem string) corev1.Node {
	n := node(name, zone, itype, providerID)
	n.Status.Capacity = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(cpu),
		corev1.ResourceMemory: resource.MustParse(mem),
	}
	return n
}

// TestBuildReport_NodePoolSpecComesFromRealCapacity closes a gap where the fixture was richer than
// reality: testdata/golden/sample-audit.json carries spec "4 vCPU · 16 GiB" for every pool, and a
// real audit produced spec:"" for all of them, because NodePoolSummary.Spec was never assigned
// outside the fixture. The report renders that as a column full in the demo and blank for every
// client.
//
// It is derived from Status.Capacity rather than from the instance-type table on purpose: capacity
// is what this machine actually reports, so it stays right for a shape the table has never heard of,
// and it cannot drift from the pricing table's idea of the same type.
func TestBuildReport_NodePoolSpecComesFromRealCapacity(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			nodeWithCapacity("n1", "eu-central-1a", "m6i.xlarge", "aws:///eu-central-1a/i-1", "4", "16Gi"),
			nodeWithCapacity("n2", "eu-central-1b", "m6i.xlarge", "aws:///eu-central-1b/i-2", "4", "16Gi"),
			nodeWithCapacity("n3", "eu-central-1c", "m6i.large", "aws:///eu-central-1c/i-3", "2", "8Gi"),
		},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		Meta:       Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())
	if ar.Architecture == nil {
		t.Fatal("no architecture")
	}

	got := map[string]string{}
	for _, p := range ar.Architecture.NodePools {
		got[p.Type] = p.Spec
	}
	for itype, want := range map[string]string{
		"m6i.xlarge": "4 vCPU · 16 GiB",
		"m6i.large":  "2 vCPU · 8 GiB",
	} {
		if got[itype] != want {
			t.Errorf("pool %s spec = %q, want %q", itype, got[itype], want)
		}
	}
}

// TestBuildReport_NodePoolSpecAbsentWhenCapacityIs — no capacity reported means no claim about the
// shape, not a guessed one.
func TestBuildReport_NodePoolSpecAbsentWhenCapacityIs(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{
			node("n1", "eu-central-1a", "m6i.xlarge", "aws:///eu-central-1a/i-1"), // no Status.Capacity
		},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		Meta:       Meta{ServerVersion: "v1.30.2", Duration: time.Second},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())
	for _, p := range ar.Architecture.NodePools {
		if p.Spec != "" {
			t.Errorf("pool %s spec = %q, want empty — the shape was never reported", p.Type, p.Spec)
		}
	}
}

// TestBuildReport_RecordsMachineReadableRunBasis — a comparison between two audits is only honest if
// it can establish that both runs looked at the same things. Today the only record of that is a prose
// sentence in Methodology.DataSources that concatenates inv.Meta.Denied, raw error strings included:
// unparseable by a guard, and it leaks whatever the API server said into the report.
//
// So the basis is recorded as data. Kind NAMES only, never the error text.
func TestBuildReport_RecordsMachineReadableRunBasis(t *testing.T) {
	inv := &Inventory{
		Nodes:      []corev1.Node{nodeWithCapacity("n1", "eu-central-1a", "m6i.large", "aws:///eu-central-1a/i-1", "2", "8Gi")},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid-42"}}},
		Meta: Meta{
			ServerVersion: "v1.30.2",
			Duration:      time.Second,
			Collected:     []string{"nodes", "namespaces", "pods"},
			Denied:        []string{"networkpolicies: networkpolicies.networking.k8s.io is forbidden: User \"x\" cannot list"},
		},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())

	if got := ar.Methodology.CollectedKinds; len(got) != 3 {
		t.Errorf("CollectedKinds = %v, want the three collected kinds", got)
	}
	if got := ar.Methodology.DeniedKinds; len(got) != 1 || got[0] != "networkpolicies" {
		t.Errorf("DeniedKinds = %v, want exactly [networkpolicies] — the kind name without the error text", got)
	}
	// The raw API error must not travel into the structured field. It stays in the prose sentence,
	// where a human reads it; a guard must never have to parse it, and it must not be duplicated.
	for _, k := range ar.Methodology.DeniedKinds {
		if strings.Contains(k, "forbidden") || strings.Contains(k, "cannot list") {
			t.Errorf("DeniedKinds carries API error text: %q", k)
		}
	}
	if ar.Methodology.RunBasis == nil {
		t.Fatal("RunBasis is nil — nothing identifies which cluster this reading is of")
	}
	if ar.Methodology.RunBasis.ClusterUID != "cluster-uid-42" {
		t.Errorf("ClusterUID = %q, want the kube-system namespace UID — the only stable cluster identity "+
			"available from a read-only snapshot (a context name can be renamed or reused)",
			ar.Methodology.RunBasis.ClusterUID)
	}
}

// TestBuildReport_RunBasisAbsentWhenUnknowable — no kube-system namespace means no cluster identity,
// and a guessed identity is worse than none: it would let two different clusters be compared.
func TestBuildReport_RunBasisAbsentWhenUnknowable(t *testing.T) {
	inv := &Inventory{
		Nodes:      []corev1.Node{node("n1", "eu-central-1a", "m6i.large", "aws:///eu-central-1a/i-1")},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}},
		Meta:       Meta{ServerVersion: "v1.30.2", Duration: time.Second, Collected: []string{"nodes"}},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())
	if ar.Methodology.RunBasis != nil && ar.Methodology.RunBasis.ClusterUID != "" {
		t.Errorf("ClusterUID = %q with no kube-system namespace collected", ar.Methodology.RunBasis.ClusterUID)
	}
}

// The denial format is fmt.Sprintf("%s: %v", kind, err) — colon then SPACE. A split on the first bare
// colon truncated every custom-resource step to the literal "cr", which collapsed distinct denials into
// identical entries and broke the one match that matters: an analyzer declaring a dependency on
// "cr:certificates.cert-manager.io" could never see that same list had been refused, so its findings
// would be reported as gone from the cluster.
func TestDeniedKindNames_KeepsTheWholeCustomResourceStepName(t *testing.T) {
	got := deniedKindNames([]string{
		"poddisruptionbudgets: poddisruptionbudgets is forbidden: User \"x\" cannot list",
		"cr:certificates.cert-manager.io: the server could not find the requested resource",
		"cr:applications.argoproj.io: forbidden",
		"cr:applications.argoproj.io: forbidden",
	})
	want := []string{"poddisruptionbudgets", "cr:certificates.cert-manager.io", "cr:applications.argoproj.io"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// "Kubernetes API (server )" — A BLANK PRETENDING TO BE A VERSION.
//
// Measured by auditing a context whose cluster had been deleted, with today's engine:
//
//	dataSources:
//	  · Kubernetes API (server )
//	  · Partial collection — 28 resource kind(s) could not be read: server-resources (not reachable), …
//
// The second line is right — M-94's causes, one per kind. The first has an empty slot where the server
// version goes, because discovery never answered. It is the smallest version of the defect this project
// keeps closing: a value that was not read, printed as though it were read and happened to be nothing. And
// it lands on the methodology line of exactly the reading a customer sends back when something went wrong.
//
// A version that was not read is named as not read. A version that WAS read is printed unchanged, which is
// the over-reach guarded below.
func TestBuildReport_AnUnreadServerVersionIsNamedRatherThanBlank(t *testing.T) {
	blind := &Inventory{Meta: Meta{
		Denied: []string{"nodes: dial tcp 127.0.0.1:53339: connect: connection refused"},
	}}
	joined := strings.Join(BuildReport(blind, nil, "test", 0, pricing.Embedded()).Methodology.DataSources, " | ")
	if strings.Contains(joined, "(server )") {
		t.Errorf("a server version nobody read is printed as a blank: %q", joined)
	}
	if !strings.Contains(joined, "Kubernetes API") {
		t.Errorf("the API is no longer named as a source at all: %q", joined)
	}
	if !strings.Contains(joined, "not read") && !strings.Contains(joined, "unknown") {
		t.Errorf("the missing version is not named as missing: %q", joined)
	}

	// THE OVER-REACH: a version that was read is printed as itself.
	seen := &Inventory{Meta: Meta{ServerVersion: "v1.29.0", Collected: []string{"nodes"}}}
	if got := strings.Join(BuildReport(seen, nil, "test", 0, pricing.Embedded()).Methodology.DataSources, " | "); !strings.Contains(got, "Kubernetes API (server v1.29.0)") {
		t.Errorf("a server version that was read lost its sentence: %q", got)
	}
}
