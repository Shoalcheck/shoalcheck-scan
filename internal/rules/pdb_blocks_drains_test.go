package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// testPDB builds a PDB selecting sel; mutate sets the budget fields.
func testPDB(ns, name string, sel map[string]string, mutate func(*policyv1.PodDisruptionBudget)) policyv1.PodDisruptionBudget {
	p := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
	if sel != nil {
		p.Spec.Selector = &metav1.LabelSelector{MatchLabels: sel}
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

// zeroBudgetStatus is the status the disruption controller publishes for a PDB that allows nothing: it has
// counted `expected` pods in scope, wants `desired` healthy, and reports no disruption allowed.
//
// EVERY minAvailable FIXTURE NOW CARRIES ONE, and the rule requires it. Four tests in this file used to assert
// a finding from spec alone, which is how the wrong-denominator bug survived: the fixtures never had the field
// that holds the right answer, so nothing in the suite could notice it was being ignored. A PDB on a real
// cluster always has a status; a fixture without one was not a smaller cluster, it was an impossible one.
func zeroBudgetStatus(expected, desired int32) policyv1.PodDisruptionBudgetStatus {
	return policyv1.PodDisruptionBudgetStatus{
		ExpectedPods:       expected,
		CurrentHealthy:     expected,
		DesiredHealthy:     desired,
		DisruptionsAllowed: 0,
	}
}

func TestPDBBlocksDrains_MaxUnavailableZero(t *testing.T) {
	cases := []struct {
		name string
		v    intstr.IntOrString
	}{
		{"int-zero", intstr.FromInt32(0)},
		{"string-zero", intstr.FromString("0")},
		{"percent-zero", intstr.FromString("0%")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.v
			inv := &collect.Inventory{
				Deployments: []appsv1.Deployment{deploy("app", "api", 3, nil)},
				PDBs: []policyv1.PodDisruptionBudget{
					testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
						p.Spec.MaxUnavailable = &v
					}),
				},
			}
			fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
			if len(fs) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
			}
			f := fs[0]
			if f.RuleID != "k8s.reliability.pdb-blocks-drains" {
				t.Errorf("ruleID = %q", f.RuleID)
			}
			joined := strings.Join(f.Evidence, " ")
			if !strings.Contains(joined, "maxUnavailable="+tc.v.String()) {
				t.Errorf("evidence must cite the collected value: %v", f.Evidence)
			}
			if len(f.AffectedResources) != 2 ||
				f.AffectedResources[0].Kind != "PodDisruptionBudget" || f.AffectedResources[0].Name != "api-pdb" ||
				f.AffectedResources[1].Kind != "Deployment" || f.AffectedResources[1].Name != "api" {
				t.Errorf("affected must be PDB + matched workload: %+v", f.AffectedResources)
			}
			if !strings.Contains(f.RemediationCommand, "kubectl -n app patch pdb api-pdb") ||
				!strings.Contains(f.RemediationCommand, `"maxUnavailable":1`) {
				t.Errorf("remediation command not PDB-specific: %q", f.RemediationCommand)
			}
			if f.Confidence != 1.0 {
				t.Errorf("confidence = %v, want 1.0", f.Confidence)
			}
		})
	}
}

func TestPDBBlocksDrains_MinAvailableSwallowsReplicas(t *testing.T) {
	min2 := intstr.FromInt32(2)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &min2
				p.Status = zeroBudgetStatus(2, 2)
			}),
		},
	}
	fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	// The evidence now cites the PDB's OWN scope and the API's own answer. It used to read
	// "minAvailable=2 equals replicas=2", which was the bug written down: replicas belong to one workload and
	// the budget belongs to the selector.
	if !strings.Contains(joined, "minAvailable=2") || !strings.Contains(joined, "expectedPods=2") ||
		!strings.Contains(joined, "disruptionsAllowed=0") || !strings.Contains(joined, "Deployment app/api") {
		t.Errorf("evidence must cite the PDB's own scope and the eviction API's answer: %v", fs[0].Evidence)
	}
	if strings.Contains(joined, "replicas=") {
		t.Errorf("evidence still compares against a workload's replicas, which is the wrong denominator: %v",
			fs[0].Evidence)
	}
}

func TestPDBBlocksDrains_MinAvailableExceedsReplicas(t *testing.T) {
	min5 := intstr.FromInt32(5)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &min5
				p.Status = zeroBudgetStatus(2, 5)
			}),
		},
	}
	fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(joined, "minAvailable=5") || !strings.Contains(joined, "expectedPods=2") ||
		!strings.Contains(joined, "desiredHealthy=5") {
		t.Errorf("evidence must show the declared minimum against the PDB's own scope: %v", fs[0].Evidence)
	}
}

func TestPDBBlocksDrains_MinAvailable100PercentFlagged(t *testing.T) {
	all := intstr.FromString("100%")
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 3, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "api-pdb", map[string]string{"app": "api"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &all
				p.Status = zeroBudgetStatus(3, 3)
			}),
		},
	}
	if got := len(PDBBlocksDrains{}.Evaluate(inv, Options{})); got != 1 {
		t.Fatalf("minAvailable=100%% must flag, got %d findings", got)
	}
}

func TestPDBBlocksDrains_HealthyPDBNotFlagged(t *testing.T) {
	mu1 := intstr.FromInt32(1)
	min1 := intstr.FromInt32(1)
	half := intstr.FromString("50%")
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "a", 2, nil),
			deploy("app", "b", 2, nil),
			deploy("app", "c", 2, nil),
		},
		PDBs: []policyv1.PodDisruptionBudget{
			// maxUnavailable=1 leaves a drain budget.
			testPDB("app", "a-pdb", map[string]string{"app": "a"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MaxUnavailable = &mu1
			}),
			// minAvailable=1 < replicas=2 leaves a drain budget.
			testPDB("app", "b-pdb", map[string]string{"app": "b"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &min1
			}),
			// minAvailable=50% of 2 = 1 < 2 leaves a drain budget.
			testPDB("app", "c-pdb", map[string]string{"app": "c"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &half
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("healthy PDBs flagged: %+v", fs)
	}
}

func TestPDBBlocksDrains_MinAvailableNoMatchedWorkloadNotFlagged(t *testing.T) {
	min2 := intstr.FromInt32(2)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "other", 2, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "orphan-pdb", map[string]string{"app": "nothing-matches"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &min2
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("minAvailable with no matched workload must not flag: %+v", fs)
	}
}

func TestPDBBlocksDrains_SystemNamespaceSkipped(t *testing.T) {
	zero := intstr.FromInt32(0)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("kube-system", "coredns", 2, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("kube-system", "coredns-pdb", map[string]string{"app": "coredns"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MaxUnavailable = &zero
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default: %+v", fs)
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{IncludeSystem: true}); len(fs) != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", len(fs))
	}
}

func TestPDBBlocksDrains_DistinctIDs(t *testing.T) {
	zero := intstr.FromInt32(0)
	z2 := zero
	inv := &collect.Inventory{
		// Each PDB must guard a real workload — orphan PDBs are no longer flagged.
		Deployments: []appsv1.Deployment{
			deploy("app", "x", 2, nil),
			deploy("app", "y", 2, nil),
		},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "p1", map[string]string{"app": "x"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MaxUnavailable = &zero
			}),
			testPDB("app", "p2", map[string]string{"app": "y"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MaxUnavailable = &z2
			}),
		},
	}
	fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].ID == fs[1].ID || !strings.HasPrefix(fs[0].ID, "f-") {
		t.Fatalf("finding IDs must be distinct f-prefixed hashes: %q vs %q", fs[0].ID, fs[1].ID)
	}
}

func TestPDBBlocksDrains_OrphanMaxUnavailableZeroNotFlagged(t *testing.T) {
	zero := intstr.FromInt32(0)
	inv := &collect.Inventory{
		// PDB with maxUnavailable=0 but its selector matches no collected workload.
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "orphan", map[string]string{"app": "ghost"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MaxUnavailable = &zero
			}),
		},
	}
	if fs := (PDBBlocksDrains{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("orphan maxUnavailable=0 PDB must not be flagged (no pods to stall): %+v", fs)
	}
}

func TestPDBBlocksDrains_PercentEvidenceShowsRawValue(t *testing.T) {
	hundred := intstr.FromString("100%")
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "web", 3, nil)},
		PDBs: []policyv1.PodDisruptionBudget{
			testPDB("app", "web-pdb", map[string]string{"app": "web"}, func(p *policyv1.PodDisruptionBudget) {
				p.Spec.MinAvailable = &hundred
				p.Status = zeroBudgetStatus(3, 3)
			}),
		},
	}
	fs := PDBBlocksDrains{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(joined, "100%") {
		t.Errorf("evidence must show the raw spec value 100%%, not just the resolved integer: %q", joined)
	}
}
