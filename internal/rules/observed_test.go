package rules

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// The escape hatch this test exists to prevent: for years three copies of this guard treated an
// inventory that mentioned a kind in NEITHER Meta slice as a successful list, reasoning that a fixture
// carrying objects must have observed them. The reasoning inverts on the only case that matters. Rules
// like SingleReplicaNoPDB and NoNetworkPolicy fire on ABSENCE, so the inventory the hatch waved through
// was the one holding ZERO objects and no record of having looked — exactly the fabricated claim the
// guard was written to prevent.
func TestObserved_AnInventoryThatNeverSaidWhatItReadProvesNothing(t *testing.T) {
	empty := &collect.Inventory{}
	for _, kind := range []string{"poddisruptionbudgets", "networkpolicies", "endpointslices", "services"} {
		if observed(empty, kind) {
			t.Errorf("observed(%q) on an inventory with no Meta returned true — an unlooked-at list is "+
				"being read as an empty one", kind)
		}
	}
}

func TestObserved_DenialBeatsCollection(t *testing.T) {
	// A well-formed Meta names a kind in exactly one slice. If it somehow appears in both, refusing is
	// the only safe reading — the alternative asserts success we cannot see.
	inv := &collect.Inventory{Meta: collect.Meta{
		Collected: []string{"poddisruptionbudgets"},
		Denied:    []string{"poddisruptionbudgets: forbidden"},
	}}
	if observed(inv, "poddisruptionbudgets") {
		t.Error("a kind recorded as both collected and denied was read as observed")
	}
}

func TestObserved_MatchesTheCollectorsDenialFormat(t *testing.T) {
	// The collector writes a denial as "<kind>: <error>", never the bare kind, so a guard that only
	// compared for equality would treat every real denial as an un-mentioned kind.
	inv := &collect.Inventory{Meta: collect.Meta{
		Denied: []string{`services: services is forbidden: User "x" cannot list resource "services"`},
	}}
	if observed(inv, "services") {
		t.Error("a denial in the collector's own format was not recognised")
	}
	// A kind whose NAME is a prefix of another must not be swallowed by it.
	inv2 := &collect.Inventory{Meta: collect.Meta{Collected: []string{"persistentvolumeclaims"}}}
	if observed(inv2, "persistentvolumes") {
		t.Error("persistentvolumes was read as observed because persistentvolumeclaims was collected")
	}
}

// The behavioural consequence, end to end: a rule that reports an absence must fall silent when the list
// that would have shown the objects was refused. Without this the audit reports the operator's own
// missing RBAC verb as a fleet-wide reliability problem.
func TestAbsenceRules_FallSilentWhenTheListWasDenied(t *testing.T) {
	one := int32(1)
	dep := appsv1.Deployment{}
	dep.Namespace, dep.Name = "app", "exposed"
	dep.Spec.Replicas = &one
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{dep},
		PDBs:        []policyv1.PodDisruptionBudget{},
		Meta: collect.Meta{
			Collected: []string{"deployments", "services"},
			Denied:    []string{"poddisruptionbudgets: forbidden"},
		},
	}
	if fs := (SingleReplicaNoPDB{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("reported %d finding(s) about missing PDBs from a run that was refused the PDB list: %+v", len(fs), fs)
	}
}
