package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// TestCrossSeamCapacityParity is the P1.5 footgun guard: cluster spend (Seam A,
// internal/collect.BuildReport) and per-finding savings (Seam B,
// internal/rules.NodeHeadroom) MUST classify an IDENTICAL node identically.
//
// Both seams re-derive provider/region on their own paths, so the only thing
// keeping their pool-keying in lockstep is the SINGLE shared classifier
// (collect.ClassifyCapacityType). This test constructs one corev1.Node, runs it
// through BOTH seams' real pool-building code, and asserts they agree on its
// capacity. If a future change forks the classification (e.g. a provider-blind
// copy creeps into one seam), cluster spend and per-finding savings would
// silently disagree on whether a pool is spot — this test goes red first.
func TestCrossSeamCapacityParity(t *testing.T) {
	// One EKS node group, split: a spot node and an on-demand node of the SAME
	// instance type. The split is the interesting case — both seams must key
	// instanceType+capacity the same way, so the spot node lands in a spot pool
	// in BOTH seams and never collapses into the on-demand pool.
	parityNode := func(name, capLabel string) corev1.Node {
		labels := map[string]string{
			"topology.kubernetes.io/zone":      "eu-central-1a",
			"topology.kubernetes.io/region":    "eu-central-1",
			"node.kubernetes.io/instance-type": "m6i.large",
			"eks.amazonaws.com/capacityType":   capLabel, // EKS MNG: UPPERCASE
		}
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Spec:       corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/" + name},
			Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1800m"),
				corev1.ResourceMemory: resource.MustParse("7Gi"),
			}},
		}
	}
	// Three spot + three on-demand so NodeHeadroom can find removable slack in
	// BOTH pools: the HA floor leaves >=2 nodes, so a pool now needs >=3 nodes
	// (and idle capacity) to yield a finding.
	nodes := []corev1.Node{
		parityNode("spot-1", "SPOT"),
		parityNode("spot-2", "SPOT"),
		parityNode("spot-3", "SPOT"),
		parityNode("od-1", "ON_DEMAND"),
		parityNode("od-2", "ON_DEMAND"),
		parityNode("od-3", "ON_DEMAND"),
	}
	// Tiny requests so each pool has whole-node slack and yields a finding.
	pods := []corev1.Pod{
		requestPod("app", "p-spot", "spot-1", "100m", "256Mi"),
		requestPod("app", "p-od", "od-1", "100m", "256Mi"),
	}
	inv := &collect.Inventory{
		Nodes:      nodes,
		Pods:       pods,
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app"}}},
		Meta:       collect.Meta{ServerVersion: "v1.30.2", Collected: []string{"nodes", "pods"}},
	}

	// --- Direct classifier parity: the literal "identical node, identical
	// verdict" assertion the spec calls out. Both seams derive the provider
	// independently; assert the classifier returns the same value for the same
	// node regardless of which seam's provider-string spelling reaches it. ---
	collectProvider := "eks" // internal/collect.providerFrom returns "eks" for aws://
	rulesProvider := "aws"   // internal/rules.providerFromNodes returns "aws"
	for _, n := range nodes {
		a := collect.ClassifyCapacityType(collectProvider, n)
		b := collect.ClassifyCapacityType(rulesProvider, n)
		if a != b {
			t.Fatalf("classifier disagrees across seam provider spellings for %s: collect(%q)=%q rules(%q)=%q",
				n.Name, collectProvider, a, rulesProvider, b)
		}
	}

	// --- Seam A: collect re-keys pools by instanceType+capacity. Capture the
	// capacity each pool was assigned. ---
	ar := collect.BuildReport(inv, nil, "parity", 0, pricing.Embedded())
	if ar.Architecture == nil {
		t.Fatal("collect seam produced no architecture")
	}
	collectPoolCap := map[types.CapacityType]bool{}
	for _, p := range ar.Architecture.NodePools {
		if p.Type == "m6i.large" {
			collectPoolCap[p.Capacity] = true
			if p.Capacity == types.CapacitySpot && p.CostSource != types.CostSourceSpotCeiling {
				t.Errorf("collect seam: spot pool CostSource = %q, want spot-ceiling", p.CostSource)
			}
		}
	}
	if !collectPoolCap[types.CapacitySpot] || !collectPoolCap[types.CapacityOnDemand] {
		t.Fatalf("collect seam did not split the pool by capacity: pools=%+v", ar.Architecture.NodePools)
	}

	// --- Seam B: rules' NodeHeadroom keys the same way. The finding ID is a
	// hash, so recover each finding's pool capacity from its affected-node
	// membership: the rules seam grouped these nodes into a pool, so every node
	// in one finding shares a capacity (look it up via the shared classifier).
	// A split-by-capacity working correctly yields one finding per capacity, and
	// the spot finding must carry the upper-bound caveat. ---
	nodeCap := map[string]types.CapacityType{}
	for _, n := range nodes {
		nodeCap[n.Name] = collect.ClassifyCapacityType(rulesProvider, n)
	}
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	rulesPoolCap := map[types.CapacityType]bool{}
	sawSpotCaveat := false
	for _, f := range fs {
		// Capacity of this finding's pool = capacity of its (homogeneous) nodes.
		var cap types.CapacityType
		homogeneous := true
		for _, r := range f.AffectedResources {
			if r.Kind != "Node" {
				continue
			}
			c, ok := nodeCap[r.Name]
			if !ok {
				continue
			}
			if cap == "" {
				cap = c
			} else if cap != c {
				homogeneous = false
			}
		}
		if !homogeneous {
			t.Errorf("rules seam pooled nodes of MIXED capacity into one finding %s — split is broken", f.ID)
		}
		rulesPoolCap[cap] = true
		hasCaveat := false
		for _, e := range f.Evidence {
			if strings.Contains(e, "UPPER BOUND") {
				hasCaveat = true
			}
		}
		switch cap {
		case types.CapacitySpot:
			sawSpotCaveat = sawSpotCaveat || hasCaveat
		case types.CapacityOnDemand:
			if hasCaveat {
				t.Errorf("rules seam: on-demand finding %s carries a spot upper-bound caveat (false honesty signal)", f.ID)
			}
		}
	}
	if !rulesPoolCap[types.CapacitySpot] || !rulesPoolCap[types.CapacityOnDemand] {
		t.Fatalf("rules seam did not split the pool by capacity: findings=%+v", fs)
	}

	// --- The parity assertion: the SET of capacities each seam assigned to the
	// m6i.large nodes must be identical. ---
	for cap := range collectPoolCap {
		if !rulesPoolCap[cap] {
			t.Errorf("seam disagreement: collect classified an m6i.large pool as %q but rules did not", cap)
		}
	}
	for cap := range rulesPoolCap {
		if !collectPoolCap[cap] {
			t.Errorf("seam disagreement: rules classified an m6i.large pool as %q but collect did not", cap)
		}
	}

	// Honesty cross-check: the spot pool carries the upper-bound caveat on the
	// rules side, mirroring the spot-ceiling CostSource on the collect side.
	if !sawSpotCaveat {
		t.Error("rules seam spot finding missing the upper-bound caveat (honesty invariant)")
	}
}
