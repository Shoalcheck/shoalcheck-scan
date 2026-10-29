package divergence_test

import (
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// §5.7 — A REGRESSION GUARD ON A REFUSAL, and it pins the gate that future convenience will want to relax.
//
// internal/history is the obvious place to reach for when someone wants a fleet comparison: it already knows
// how to say "these two readings differ, and here is what could not be told apart". It cannot be used, and
// the reason is a FEATURE rather than an oversight — history.Compute's Gate 0 refuses two readings whose
// ClusterUID differs, because a cross-cluster comparison presented as a change over time would report
// another cluster's state as this cluster's regression.
//
// Every member of a fleet has a different UID by construction, so the gate that makes history correct is the
// gate that makes it unusable here. This test exists so that a later change to Gate 0 — made for some
// unrelated good reason — cannot quietly open a door this design closed on purpose.
//
// It lives in package divergence_test rather than divergence: the engine itself must NOT import
// internal/history, and an external test package is how that is kept true while still asserting the refusal.
func TestDivergence_CannotBeBuiltFromHistoryCompute(t *testing.T) {
	mk := func(uid string) *types.AuditReport {
		return &types.AuditReport{
			SchemaVersion: "v1",
			GeneratedAt:   time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC),
			Cluster:       types.ClusterInfo{Name: "c-" + uid},
			Methodology: types.Methodology{
				CollectedKinds: []string{"namespaces"},
				RunBasis: &types.RunBasis{
					ClusterUID:    uid,
					EngineVersion: "0.14.0",
				},
			},
		}
	}
	deps := map[string]history.Deps{}

	d := history.Compute(mk("uid-staging"), mk("uid-prod"), deps)
	if d.Comparable.OK {
		t.Fatal("history.Compute compared two clusters. Gate 0's ClusterUID refusal is what stops a " +
			"cross-cluster difference being rendered as this cluster's regression, and the fleet " +
			"divergence engine exists because of it — if this gate opens, that engine's reason for " +
			"existing has silently gone")
	}

	// NON-VACUITY, and it is the important half: the SAME two reports with a forced-equal UID must compare.
	// Without this the test would pass on a fixture that was simply broken — an unstamped RunBasis, a
	// missing deps map, any of Gate 0's other refusals — and would prove nothing about the UID at all.
	same := mk("uid-shared")
	other := mk("uid-shared")
	other.Cluster.Name = "c-other"
	d2 := history.Compute(same, other, deps)
	if !d2.Comparable.OK {
		t.Fatalf("two readings sharing a ClusterUID did not compare (%q), so the refusal above cannot be "+
			"attributed to the UID", d2.Comparable.Reason)
	}
}
