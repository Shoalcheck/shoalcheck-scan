package rules

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// observed reports whether the collector confirmed a successful list of this kind.
//
// This is the denial guard every rule shares. Its whole purpose is that an empty slice in the Inventory
// has two meanings — the cluster has none of these objects, or the run was never allowed to look — and
// only Meta can tell them apart. Reading the first meaning off the second is how a scanner fabricates a
// finding for every namespace in a cluster whose operator simply lacked one RBAC verb.
//
// A kind mentioned by NEITHER slice returns false. Treating it as success, on the reasoning that a hand-built
// inventory carrying the objects must have observed them, does not survive the case that matters: those rules fire on
// ABSENCE, so the fixture such a hatch waves through is precisely an inventory holding zero objects and no record of
// having looked — a fabricated claim, waved through by the guard written to prevent it. A fixture that means "I
// observed an empty list" has to say so in Meta.
//
// THE IMPLEMENTATION IS collect.Observed and this is a name, not a copy. The reasoning above is kept here because this
// is where rule authors look; internal/collect, internal/rules and internal/analyzers must not drift apart over the
// escape hatch described above.
func observed(inv *collect.Inventory, kind string) bool { return collect.Observed(inv, kind) }

// observedCR is observed for a custom-resource step, whose label the collector builds as
// "cr:<resource>.<group>". Built with the same expression the collector uses so it cannot drift.
func observedCR(inv *collect.Inventory, group, resource string) bool {
	return observed(inv, "cr:"+(schema.GroupResource{Group: group, Resource: resource}).String())
}

// notRead is the clause that says a kind is outside this product's read set, built from the collector's own step
// table (ENG-15). A hand-written claim that priority classes went unread outlived the day the collector began
// reading them, and was published in every feasibility finding. A kind the collector does read is a programming error here: the
// sentence would be false the moment it printed, so it panics in every test that renders it.
func notRead(kind string) string {
	if _, ok := collect.StepTuple(kind); ok {
		panic("rules: " + kind + " is read by the collector; a sentence saying otherwise would be false")
	}
	return kind + " are not read by this product"
}
