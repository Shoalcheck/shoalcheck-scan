package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// EPIC 0.3 — minAvailable IS RESOLVED AGAINST THE WRONG DENOMINATOR.
//
// pdb_blocks_drains.go resolves minAvailable against each matched workload's spec.replicas, one workload at a
// time. A PDB's scope is not one workload: its selector matches whatever it matches, and the eviction API
// arithmetic is over the WHOLE matched set. status.expectedPods is that set, and status.disruptionsAllowed is
// the answer the API will actually act on.
//
// The case below is the one the founder logged. Two 3-replica Deployments share a label; one PDB selects both
// with minAvailable=5. The API sees 6 pods, keeps 5, and allows exactly ONE disruption — a drain proceeds. The
// rule loops per workload, computes 5 >= 3 twice, and reports zero disruption budget on both, so the operator
// is told drains stall forever on a cluster where they do not.
//
// THIS IS AN OVERCLAIM, WHICH RANKS ABOVE A CRASH HERE. And it is the exact error class Epic 2 must not repeat:
// the correct reading was available in the same inventory the whole time. node_drain.go already reads
// st.DisruptionsAllowed and st.ExpectedPods; this file is the outlier that reads spec.
//
// FAILS TODAY BY DESIGN.
func TestPDBBlocksDrains_MinAvailableSpansEveryMatchedWorkload(t *testing.T) {
	minAvail := intstr.FromInt32(5)
	inv := &collect.Inventory{
		// Both carry app=api, so one PDB selects both. deploy() labels the pod template with app=<name>, so
		// the labels are set explicitly here to make the shared selector the point of the fixture.
		Deployments: []appsv1.Deployment{
			deploy("app", "api-blue", 3, func(d *appsv1.Deployment) {
				d.Spec.Template.Labels = map[string]string{"app": "api"}
			}),
			deploy("app", "api-green", 3, func(d *appsv1.Deployment) {
				d.Spec.Template.Labels = map[string]string{"app": "api"}
			}),
		},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &minAvail
				// What the eviction API published for this PDB: 6 pods in scope, 5 must stay healthy, so one
				// disruption is allowed. This is the reading the rule must use.
				p.Status = policyv1.PodDisruptionBudgetStatus{
					ExpectedPods:       6,
					CurrentHealthy:     6,
					DesiredHealthy:     5,
					DisruptionsAllowed: 1,
				}
			}),
		},
	}

	fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
	if len(fs) != 0 {
		var ev []string
		for _, f := range fs {
			ev = append(ev, f.Evidence...)
		}
		t.Errorf("the eviction API allows 1 disruption over 6 expected pods, and the rule emitted %d "+
			"finding(s) claiming otherwise:\n  %s\n\n"+
			"minAvailable was resolved against one workload's spec.replicas (3) instead of the PDB's own "+
			"status.expectedPods (6). The operator is told drains stall forever on a cluster where a drain "+
			"proceeds.", len(fs), strings.Join(ev, "\n  "))
	}
}

// The other side of the same fix: a PDB that really does allow nothing must still be caught, or the fix has
// traded a false positive for a false negative. status.disruptionsAllowed=0 over a healthy, fully-scoped PDB is
// the honest zero-budget case.
//
// PASSES TODAY, and must still pass after the denominator is corrected.
func TestPDBBlocksDrains_AGenuineZeroBudgetIsStillCaught(t *testing.T) {
	minAvail := intstr.FromInt32(3)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 3, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &minAvail
				p.Status = policyv1.PodDisruptionBudgetStatus{
					ExpectedPods:       3,
					CurrentHealthy:     3,
					DesiredHealthy:     3,
					DisruptionsAllowed: 0,
				}
			}),
		},
	}
	fs := (PDBBlocksDrains{}).Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("minAvailable=3 over expectedPods=3 leaves no disruption budget and must be reported; "+
			"got %d finding(s)", len(fs))
	}
}

// AN EMPTY STATUS IS NOT A ZERO BUDGET.
//
// The denial guard for a status field, one level below the usual one: the object WAS collected, the answer was
// not computed. A PDB created seconds before the audit has no status, and reading that as
// disruptionsAllowed=0 would invent the strongest claim this rule makes out of a missing reading.
func TestPDBBlocksDrains_AnUncomputedStatusIsNotJudged(t *testing.T) {
	minAvail := intstr.FromInt32(3)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 3, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &minAvail
				// No Status at all: the disruption controller has not answered yet.
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a PDB whose status has not been computed produced %d finding(s); an absent answer is not "+
			"an answer of zero:\n  %+v", len(fs), fs[0].Evidence)
	}
}

// And a status computed for a SUPERSEDED spec is not judged either: someone edited minAvailable a moment ago
// and the numbers in front of us describe the previous one.
func TestPDBBlocksDrains_AStaleStatusIsNotJudged(t *testing.T) {
	minAvail := intstr.FromInt32(3)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 3, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Generation = 4
				p.Spec.MinAvailable = &minAvail
				st := zeroBudgetStatus(3, 3)
				st.ObservedGeneration = 3 // one spec behind
				p.Status = st
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a status one generation behind the spec produced %d finding(s); it describes a PDB that no "+
			"longer exists:\n  %+v", len(fs), fs[0].Evidence)
	}
}
