package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A VOLUME'S NODE AFFINITY IS A SCHEDULER FILTER, WHATEVER KEY IT IS WRITTEN IN.
//
// The scheduler's VolumeBinding filter places a pod only on a node whose labels satisfy the required nodeAffinity
// of every PersistentVolume the pod has bound. The model read that affinity for two shapes only: a hostname pin,
// and a zone pin written in topology.kubernetes.io/zone or its beta key. CSI drivers write the zone in their own
// key — Azure Disk in topology.disk.csi.azure.com/zone, EBS in topology.ebs.csi.aws.com/zone, GCE PD in
// topology.gke.io/zone — and label the nodes with it, so on a cluster whose disks came from a driver the model
// saw no pin at all. A zone loss that strands a database was "nothing stops it", and a drain that sends a pod with
// a zonal disk to the other zone was a pod with somewhere to go: the one direction this model may not be wrong in.

// csiZoneFixture is zoneLossFixture with the volume's zone written in a driver's key, and every node labelled
// with that key as the driver's node plugin labels it.
func csiZoneFixture(key string) *collect.Inventory {
	inv := zoneLossFixture()
	for i := range inv.Nodes {
		inv.Nodes[i].Labels[key] = inv.Nodes[i].Labels["topology.kubernetes.io/zone"]
	}
	inv.PVs[0].Spec.NodeAffinity.Required.NodeSelectorTerms = []corev1.NodeSelectorTerm{{
		MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: key, Operator: corev1.NodeSelectorOpIn, Values: []string{"eu-central-1a"},
		}},
	}}
	return inv
}

var csiZoneKeys = []string{
	"topology.disk.csi.azure.com/zone",
	"topology.ebs.csi.aws.com/zone",
	"topology.gke.io/zone",
}

func affects(f types.Finding, ns, name string) bool {
	for _, r := range f.AffectedResources {
		if r.Kind == "Pod" && r.Namespace == ns && r.Name == name {
			return true
		}
	}
	return false
}

func findingFor(out []types.Finding, ns, name string) *types.Finding {
	for i := range out {
		if affects(out[i], ns, name) {
			return &out[i]
		}
	}
	return nil
}

// Losing the zone a driver-written zonal disk lives in strands the pod that mounts it, and names the volume.
func TestFeasibility_ADriverZonalDiskIsImmobileWhenItsZoneIsLost(t *testing.T) {
	for _, key := range csiZoneKeys {
		t.Run(key, func(t *testing.T) {
			out := realFindings((ZoneLossFeasibility{}).Evaluate(csiZoneFixture(key), Options{IncludeSystem: true}))
			f := findingFor(out, "data", "pinned-db-0")
			if f == nil {
				t.Fatalf("losing eu-central-1a does not name data/pinned-db-0, whose disk %s pins it there", key)
			}
			if blob := strings.Join(f.Evidence, "\n"); !strings.Contains(blob, "pv-pinned-db") {
				t.Errorf("the finding does not name the volume that holds the pod:\n%s", blob)
			}
		})
	}
}

// Any key, not a list of keys: a volume pinned by a label the model has never heard of is pinned all the same,
// because the scheduler evaluates the expression and not the key's name.
func TestFeasibility_AVolumePinnedByAnyLabelIsImmobileWhenNoNodeLeftCarriesIt(t *testing.T) {
	inv := zoneLossFixture()
	for i := range inv.Nodes {
		inv.Nodes[i].Labels["example.com/rack"] = map[string]string{"node-a1": "r1", "node-a2": "r1", "node-b1": "r2"}[inv.Nodes[i].Name]
	}
	inv.PVs[0].Spec.NodeAffinity.Required.NodeSelectorTerms = []corev1.NodeSelectorTerm{{
		MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: "example.com/rack", Operator: corev1.NodeSelectorOpIn, Values: []string{"r1"},
		}},
	}}
	out := realFindings((ZoneLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))
	if findingFor(out, "data", "pinned-db-0") == nil {
		t.Fatal("losing every node of rack r1 does not name data/pinned-db-0, whose volume admits only rack r1")
	}
}

// THE DRAIN HALF. node-a2 is drained; its pod's zonal disk admits only eu-central-1a, where the one node left
// (node-a1) carries a taint the pod does not tolerate. node-b1 has the room but is in the other zone, and the
// scheduler refuses it on the volume. Before, the model placed the pod on node-b1 — whichever key the zone was in.
func TestFeasibility_AZonalDiskRefusesANodeInAnotherZone(t *testing.T) {
	for _, key := range append([]string{"topology.kubernetes.io/zone"}, csiZoneKeys...) {
		t.Run(key, func(t *testing.T) {
			inv := csiZoneFixture(key)
			out := realFindings((NodeLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}))
			var onA2 *types.Finding
			for i := range out {
				if out[i].IDBasis != nil && out[i].IDBasis.Name == "node-a2" {
					onA2 = &out[i]
				}
			}
			if onA2 == nil || !affects(*onA2, "data", "pinned-db-0") {
				t.Fatalf("losing node-a2 does not name data/pinned-db-0: its disk admits only eu-central-1a, and the "+
					"one node left there refuses it on a taint (findings: %d)", len(out))
			}
		})
	}
}

// NON-VACUITY, the other direction: a volume that admits a surviving node constrains nothing the drain cares
// about. Two zones listed in one term, or two terms (an OR), leave the pod a home in the zone that survives.
func TestFeasibility_AVolumeThatAdmitsASurvivorDoesNotStrand(t *testing.T) {
	for name, terms := range map[string][]corev1.NodeSelectorTerm{
		"two values": {{MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: "topology.disk.csi.azure.com/zone", Operator: corev1.NodeSelectorOpIn,
			Values: []string{"eu-central-1a", "eu-central-1b"},
		}}}},
		"two terms": {
			{MatchExpressions: []corev1.NodeSelectorRequirement{{
				Key: "topology.disk.csi.azure.com/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"eu-central-1a"},
			}}},
			{MatchExpressions: []corev1.NodeSelectorRequirement{{
				Key: "topology.disk.csi.azure.com/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"eu-central-1b"},
			}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			inv := csiZoneFixture("topology.disk.csi.azure.com/zone")
			inv.PVs[0].Spec.NodeAffinity.Required.NodeSelectorTerms = terms
			for _, f := range allFeasibilityFindings(t, inv) {
				if affects(f, "data", "pinned-db-0") {
					t.Errorf("%s names data/pinned-db-0, whose volume admits node-b1 in the zone that survives:\n%s",
						f.RuleID, f.Title)
				}
			}
		})
	}
}

// The per-pod zone note reads the driver's key too, and counts the nodes the volume admits.
func TestZonePinnedVolume_ReadsADriverZoneKey(t *testing.T) {
	for _, key := range csiZoneKeys {
		t.Run(key, func(t *testing.T) {
			out := realFindings(ZonePinnedVolume{}.Evaluate(csiZoneFixture(key), Options{IncludeSystem: true}))
			f := findingFor(out, "data", "pinned-db-0")
			if f == nil {
				t.Fatalf("a disk pinned to eu-central-1a by %s produced no zone-pin finding", key)
			}
			if !strings.Contains(f.Title, "eu-central-1a") {
				t.Errorf("the finding does not name the zone: %s", f.Title)
			}
			if blob := strings.Join(f.Evidence, "\n"); !strings.Contains(blob, "2 nodes") {
				t.Errorf("the finding does not count the two nodes the volume admits:\n%s", blob)
			}
		})
	}
}

// A HOSTNAME PIN THAT NAMES TWO NODES PINS TO NEITHER. A local volume whose affinity lists node-a2 and node-b1
// is satisfied by either, so draining node-a2 leaves the pod node-b1. Before, the first name matched and the
// drain was reported blocked by a volume that does not block it.
func TestNodePinnedVolume_AVolumeAdmittingAnotherNodeDoesNotPin(t *testing.T) {
	inv := zoneLossFixture()
	inv.PVs[0].Spec.NodeAffinity.Required.NodeSelectorTerms = []corev1.NodeSelectorTerm{{
		MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a2", "node-b1"},
		}},
	}}
	if got := (NodePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
		t.Errorf("a volume that admits node-a2 and node-b1 was reported pinning a pod to one node: %s", got[0].Title)
	}
	// And with one name it still pins, or the test above proves nothing.
	inv.PVs[0].Spec.NodeAffinity.Required.NodeSelectorTerms[0].MatchExpressions[0].Values = []string{"node-a2"}
	if got := (NodePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) == 0 {
		t.Error("a volume that admits only node-a2 no longer pins the pod running there")
	}
}
