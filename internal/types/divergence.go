package types

// divergence.go — what N audited clusters declare differently, as a serialisable part of the fleet document.
//
// Spec: `docs/superpowers/specs/2026-08-28-fleet-divergence-design.md`. The types live here rather than in
// the engine's package for the reason every other assembled surface does: the renderer consumes an assembled
// report and does not assemble one, so what it draws has to arrive in the document.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE THREE-WAY CLASSIFICATION, AND THE THIRD STATE IS THE WHOLE DESIGN
//
//	SAME        — every cluster readable on this dimension, all equal. A count, never rows.
//	DIFFERENT   — every cluster readable, values unequal. This is what a reader sees.
//	NOT COMPARED — at least one cluster could not read the dimension. ITS OWN BUCKET, its own count,
//	              never folded into "same".
//
// Rendering an unknown as a match is the defect this design exists to prevent, and internal/history's
// `blockedBy` is the precedent copied deliberately: denied and un-mentioned are both "not confirmed read".
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// NO BASELINE, EVER
//
// With N clusters there are N(N-1)/2 pairs and NOTHING TOLD US WHICH CLUSTER IS CANONICAL. So a dimension
// reports the set of distinct observed values with the clusters holding each — symmetric, identical in shape
// at N=2 and N=9, and it never implies one side is right. A baseline would require a fact about the
// customer's intent that no input to this product carries.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS IS NOT
//
//	NOT A VERDICT. Staging and production are SUPPOSED to differ in places and we do not know which places.
//	The supportable sentence is "these clusters declare different values for X" and nothing stronger.
//
//	NOT DRIFT. The word asserts that a shared origin existed and moved apart. We did not read an origin.
//
//	NOT A TREND. It is one moment across N clusters, not change over time.
//
//	NOT "SAME MEANS SAFE". Two clusters can agree on every dimension readable here and disagree on ten
//	that are not.

// FleetDivergence is what the audited clusters declare differently. Absent (nil) below two audited clusters
// — not an empty table with a heading, nothing.
type FleetDivergence struct {
	// Clusters names the audited clusters this comparison covers, sorted. A reader needs to know the
	// denominator before any row means anything.
	Clusters []string `json:"clusters"`

	// Unreached names contexts that were asked for and not audited, carried INTO this surface rather than
	// left in the fleet overview. A divergence table listing three clusters out of five, with the other two
	// mentioned on a different screen, repeats the bug FleetReport.Skipped was added to fix.
	Unreached []SkippedCluster `json:"unreached,omitempty"`

	// Rows are the differing dimensions, sorted by scope then dimension.
	Rows []DivergenceRow `json:"rows,omitempty"`

	// NamespaceMembership names namespaces absent from at least one cluster. NOT a divergence in any
	// dimension: "cluster B has no Pod Security label on payments" is a false sentence when payments does
	// not exist in cluster B. Reported once, and the dimensions inside such a namespace are not compared.
	NamespaceMembership []NamespaceMembership `json:"namespaceMembership,omitempty"`

	// The counts behind the rows, so a reader can see how much agreed and how much could not be asked.
	SameCount        int `json:"sameCount"`
	NotComparedCount int `json:"notComparedCount"`

	// NotCompared lists what could not be compared and which cluster could not read it. A count alone would
	// be a number with no way to act on it.
	NotCompared []NotComparedDimension `json:"notCompared,omitempty"`
}

// DivergenceRow is one dimension whose value differs across the clusters that could read it.
type DivergenceRow struct {
	// Scope is "cluster" or the namespace name.
	Scope string `json:"scope"`
	// Dimension is a stable identifier, e.g. "pod-security.enforce".
	Dimension string `json:"dimension"`
	// Values is the set of distinct observed values, each with the clusters holding it, sorted by value.
	// There is no "expected" entry and no ordering that implies one.
	Values []DivergenceValue `json:"values"`
}

// DivergenceValue is one observed value and who declares it.
type DivergenceValue struct {
	// Value is rendered as read. An empty declaration is spelled out rather than left blank, because a blank
	// cell reads as "no data" and this one means "read, and the declaration is absent".
	Value    string   `json:"value"`
	Clusters []string `json:"clusters"`
}

// NamespaceMembership is a namespace that does not exist in every audited cluster.
type NamespaceMembership struct {
	Namespace string   `json:"namespace"`
	Present   []string `json:"present"`
	Absent    []string `json:"absent"`
}

// NotComparedDimension is a dimension at least one cluster could not read.
type NotComparedDimension struct {
	Scope     string `json:"scope"`
	Dimension string `json:"dimension"`
	// Blocked names the clusters whose reading could not confirm this dimension — denied, or never
	// attempted. The two are one bucket on purpose: neither is a confirmed read, and distinguishing them
	// here would invite a reader to treat "never attempted" as "probably fine".
	Blocked []string `json:"blocked"`
}
