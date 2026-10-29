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
// A kind mentioned by NEITHER slice returns false. That case used to be treated as success in three of
// the four copies of this guard, on the reasoning that a hand-built inventory carrying the objects must
// have observed them. The reasoning does not survive contact with the case that matters: those rules fire
// on ABSENCE, so the fixture the hatch waved through was precisely an inventory holding zero objects and
// no record of having looked — a fabricated claim, waved through by the guard written to prevent it. A
// fixture that means "I observed an empty list" has to say so in Meta, and one line in a test is a much
// smaller price than a guard with a hole in it.
//
// THE IMPLEMENTATION MOVED to collect.Observed on 2026-08-30 and this is now a name, not a copy. The
// reasoning above is why it reads the way it does and is kept here because this is where rule authors look;
// what changed is that internal/collect, internal/rules and internal/analyzers can no longer drift apart,
// which they had already done once over the escape hatch described above.
func observed(inv *collect.Inventory, kind string) bool { return collect.Observed(inv, kind) }

// observedCR is observed for a custom-resource step, whose label the collector builds as
// "cr:<resource>.<group>". Built with the same expression the collector uses so it cannot drift.
func observedCR(inv *collect.Inventory, group, resource string) bool {
	return observed(inv, "cr:"+(schema.GroupResource{Group: group, Resource: resource}).String())
}
