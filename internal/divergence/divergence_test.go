package divergence

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// divergence_test.go — §5 of the fleet-divergence spec, each test with what stops it being vacuous.
//
// THIS FAMILY'S NORMAL OUTPUT IS "SAME", so every test that asserts a row also asserts the neighbouring
// fixture that must NOT produce one. A classifier that answered "different" to everything, or "not compared"
// to everything, would pass half of these and fail the other half — which is the only arrangement that
// distinguishes a working classifier from a stuck one.

func cluster(name string, p *types.PolicyPosture) *types.AuditReport {
	return &types.AuditReport{Cluster: types.ClusterInfo{Name: name}, PolicyPosture: p}
}

func nsPosture(name, enforce string, np, rq, lr int, npRead, rqRead, lrRead bool) types.NamespacePosture {
	return types.NamespacePosture{
		Name:                name,
		PodSecurity:         types.PodSecurityLabels{Enforce: enforce},
		PodSecurityRead:     true,
		NetworkPolicies:     np,
		NetworkPoliciesRead: npRead,
		ResourceQuotas:      rq,
		ResourceQuotasRead:  rqRead,
		LimitRanges:         lr,
		LimitRangesRead:     lrRead,
	}
}

func posture(read bool, ns ...types.NamespacePosture) *types.PolicyPosture {
	return &types.PolicyPosture{Namespaces: ns, OperatorsRead: read}
}

func rowFor(d *types.FleetDivergence, scope, dim string) *types.DivergenceRow {
	for i := range d.Rows {
		if d.Rows[i].Scope == scope && d.Rows[i].Dimension == dim {
			return &d.Rows[i]
		}
	}
	return nil
}

func notComparedFor(d *types.FleetDivergence, scope, dim string) *types.NotComparedDimension {
	for i := range d.NotCompared {
		if d.NotCompared[i].Scope == scope && d.NotCompared[i].Dimension == dim {
			return &d.NotCompared[i]
		}
	}
	return nil
}

// §5.1 — A DENIED DIMENSION IS NOT A MATCH.
//
// Non-vacuity: the same fixture with both sides confirmed-read must land in `same`, so a classifier that
// answers "not compared" to everything fails the second half.
func TestDivergence_ADeniedDimensionIsNotAMatch(t *testing.T) {
	// Both clusters have `payments` with no NetworkPolicy. Cluster B could not read NetworkPolicies.
	a := cluster("a", posture(true, nsPosture("payments", "baseline", 0, 0, 0, true, true, true)))
	b := cluster("b", posture(true, nsPosture("payments", "baseline", 0, 0, 0, false, true, true)))
	d := Compute([]*types.AuditReport{a, b}, nil)
	if d == nil {
		t.Fatal("two audited clusters produced no divergence surface")
	}
	nc := notComparedFor(d, "payments", DimNetworkPolicy)
	if nc == nil {
		t.Fatal("a denied NetworkPolicy list was not recorded as not-compared")
	}
	if !reflect.DeepEqual(nc.Blocked, []string{"b"}) {
		t.Errorf("blocked = %v, want [b]", nc.Blocked)
	}
	if rowFor(d, "payments", DimNetworkPolicy) != nil {
		t.Error("a denied dimension produced a divergence row")
	}

	// NON-VACUITY: confirm the same shape lands in `same` once both sides are read.
	b2 := cluster("b", posture(true, nsPosture("payments", "baseline", 0, 0, 0, true, true, true)))
	d2 := Compute([]*types.AuditReport{a, b2}, nil)
	if notComparedFor(d2, "payments", DimNetworkPolicy) != nil {
		t.Error("a confirmed-read dimension was still reported as not-compared")
	}
	if d2.SameCount == 0 {
		t.Error("two agreeing readable clusters produced no `same` count at all")
	}
}

// UNREADABILITY BEATS EQUALITY, and the order is not the obvious one: if any cluster could not read the
// dimension, it is not compared AT ALL, even when every cluster that COULD read it agreed. Reporting "same"
// from a subset tells a reader the fleet agrees on something part of it was never asked about.
func TestDivergence_AgreementAmongTheReadableIsStillNotCompared(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("payments", "baseline", 1, 0, 0, true, true, true)))
	b := cluster("b", posture(true, nsPosture("payments", "baseline", 1, 0, 0, true, true, true)))
	c := cluster("c", posture(true, nsPosture("payments", "baseline", 1, 0, 0, false, true, true)))
	d := Compute([]*types.AuditReport{a, b, c}, nil)
	if notComparedFor(d, "payments", DimNetworkPolicy) == nil {
		t.Fatal("a dimension one cluster could not read was compared anyway")
	}
	if rowFor(d, "payments", DimNetworkPolicy) != nil {
		t.Error("the dimension produced a row despite an unreadable cluster")
	}
}

// §5.2 — A NAMESPACE IN ONE CLUSTER ONLY IS A MEMBERSHIP DIFFERENCE, NOT A DIVERGENCE.
//
// Non-vacuity: the second half uses a namespace present in both with different labels, which MUST produce a
// dimension row — so a classifier that emitted membership rows for everything fails.
func TestDivergence_ANamespaceThatExistsInOneClusterIsNotADivergence(t *testing.T) {
	a := cluster("a", posture(true,
		nsPosture("payments", "restricted", 1, 1, 1, true, true, true),
		nsPosture("legacy", "privileged", 0, 0, 0, true, true, true)))
	b := cluster("b", posture(true,
		nsPosture("payments", "restricted", 1, 1, 1, true, true, true)))
	d := Compute([]*types.AuditReport{a, b}, nil)

	if len(d.NamespaceMembership) != 1 || d.NamespaceMembership[0].Namespace != "legacy" {
		t.Fatalf("want one membership row for `legacy`, got %+v", d.NamespaceMembership)
	}
	if !reflect.DeepEqual(d.NamespaceMembership[0].Absent, []string{"b"}) {
		t.Errorf("absent = %v, want [b]", d.NamespaceMembership[0].Absent)
	}
	for _, r := range d.Rows {
		if r.Scope == "legacy" {
			t.Errorf("a namespace missing from one cluster produced dimension row %q — "+
				"\"cluster b declares no Pod Security label on legacy\" is a FALSE sentence, not a weak one",
				r.Dimension)
		}
	}
	for _, nc := range d.NotCompared {
		if nc.Scope == "legacy" {
			t.Errorf("a namespace missing from one cluster produced a not-compared row %q; membership is "+
				"reported once and the dimensions inside are not examined", nc.Dimension)
		}
	}

	// NON-VACUITY: a namespace present in BOTH with different labels must produce a dimension row.
	b2 := cluster("b", posture(true,
		nsPosture("payments", "baseline", 1, 1, 1, true, true, true)))
	d2 := Compute([]*types.AuditReport{a, b2}, nil)
	row := rowFor(d2, "payments", DimPSSEnforce)
	if row == nil {
		t.Fatal("differing Pod Security labels in a shared namespace produced no row")
	}
	if len(row.Values) != 2 {
		t.Fatalf("want 2 distinct values, got %d: %+v", len(row.Values), row.Values)
	}
}

// NO BASELINE. The values are a symmetric set, so neither cluster is named as the reference — and the
// ordering is by VALUE, which carries no claim, rather than by cluster order, which would.
func TestDivergence_NamesNoBaseline(t *testing.T) {
	a := cluster("zebra", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	b := cluster("alpha", posture(true, nsPosture("app", "baseline", 0, 0, 0, true, true, true)))
	d := Compute([]*types.AuditReport{a, b}, nil)
	row := rowFor(d, "app", DimPSSEnforce)
	if row == nil {
		t.Fatal("no row for differing enforce labels")
	}
	if row.Values[0].Value != "baseline" || row.Values[1].Value != "restricted" {
		t.Errorf("values are not sorted by value: %+v", row.Values)
	}
	// Reversing the input order must produce an identical row — that is what "symmetric" means here.
	d2 := Compute([]*types.AuditReport{b, a}, nil)
	if !reflect.DeepEqual(row, rowFor(d2, "app", DimPSSEnforce)) {
		t.Error("the row depends on the order the clusters were passed in, so one of them is a baseline")
	}
}

// A READ-BUT-UNDECLARED VALUE IS SPELLED OUT. A blank cell reads as "no data", and this state is the
// opposite: the namespace was read and declares nothing, which for PSA means the cluster default governs it.
func TestDivergence_AnUndeclaredValueIsNamedNotBlank(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	b := cluster("b", posture(true, nsPosture("app", "", 0, 0, 0, true, true, true)))
	row := rowFor(Compute([]*types.AuditReport{a, b}, nil), "app", DimPSSEnforce)
	if row == nil {
		t.Fatal("no row")
	}
	for _, v := range row.Values {
		if v.Value == "" {
			t.Error("an undeclared label rendered as an empty string, which a reader cannot tell from missing data")
		}
	}
}

// §5.3 — SKIPPED CLUSTERS APPEAR IN THIS SURFACE, not only in the fleet overview.
//
// Non-vacuity: the count is asserted as 1 rather than merely non-nil, and a fleet with no skips must
// produce an EMPTY list rather than a placeholder.
func TestDivergence_SkippedClustersAppearInTheSurface(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	b := cluster("b", posture(true, nsPosture("app", "baseline", 0, 0, 0, true, true, true)))
	skipped := []types.SkippedCluster{{Context: "eu-prod", Reason: "not reachable"}}
	d := Compute([]*types.AuditReport{a, b}, skipped)
	if len(d.Unreached) != 1 || d.Unreached[0].Context != "eu-prod" {
		t.Fatalf("the skip list did not reach the divergence surface: %+v", d.Unreached)
	}
	if got := Compute([]*types.AuditReport{a, b}, nil); len(got.Unreached) != 0 {
		t.Errorf("a fleet with no skips carries %d unreached entry/entries", len(got.Unreached))
	}
}

// §5.4 — NO SCALE FIELD IS REACHABLE. Structural: the projection carries no field a scale comparison could
// read, so the surface cannot render one even by mistake.
//
// Non-vacuity: the type must have at least one field, so an empty struct does not pass.
func TestDivergence_NoScaleFieldIsReachable(t *testing.T) {
	banned := []string{"replica", "node", "count", "cpu", "memory", "cost", "usd", "spend", "instance", "size"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(types.PolicyPosture{}),
		reflect.TypeOf(types.NamespacePosture{}),
		reflect.TypeOf(types.PodSecurityLabels{}),
	} {
		if typ.NumField() == 0 {
			t.Fatalf("%s has no fields, so this test proves nothing", typ.Name())
		}
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, b := range banned {
				if strings.Contains(name, b) {
					t.Errorf("%s.%s looks like a scale field — two clusters are EXPECTED to differ on "+
						"scale, and a surface able to render it would bury the policy signal",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

// The same exclusion one level out: the ENGINE never renders a count, even though the projection carries
// object counts for other consumers. `presence` is the only door and it returns two fixed strings.
func TestDivergence_RendersPresenceNeverACount(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("app", "restricted", 3, 0, 0, true, true, true)))
	b := cluster("b", posture(true, nsPosture("app", "restricted", 7, 0, 0, true, true, true)))
	d := Compute([]*types.AuditReport{a, b}, nil)
	if r := rowFor(d, "app", DimNetworkPolicy); r != nil {
		t.Errorf("three NetworkPolicies versus seven was reported as a divergence: %+v", r.Values)
	}
	// And zero versus some IS reported, which is what proves the dimension is being examined at all.
	c := cluster("b", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	if rowFor(Compute([]*types.AuditReport{a, c}, nil), "app", DimNetworkPolicy) == nil {
		t.Error("declared versus none-declared produced no row, so this dimension is not being compared")
	}
}

// §5.5 — BELOW TWO AUDITED CLUSTERS, SILENCE. A single-cluster fleet and a three-cluster fleet where two
// were skipped are the same case.
func TestDivergence_EmitsNothingBelowTwoAuditedClusters(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	if got := Compute([]*types.AuditReport{a}, nil); got != nil {
		t.Error("a single-cluster fleet produced a divergence surface")
	}
	skipped := []types.SkippedCluster{{Context: "b", Reason: "not reachable"}, {Context: "c", Reason: "not permitted"}}
	if got := Compute([]*types.AuditReport{a}, skipped); got != nil {
		t.Error("a three-cluster fleet with two skips produced a divergence surface from one report")
	}
	if got := Compute(nil, nil); got != nil {
		t.Error("an empty fleet produced a divergence surface")
	}
	// NON-VACUITY: two reports DO produce one, so a function that returned nil unconditionally fails here.
	b := cluster("b", posture(true, nsPosture("app", "baseline", 0, 0, 0, true, true, true)))
	if Compute([]*types.AuditReport{a, b}, nil) == nil {
		t.Error("two audited clusters produced nothing")
	}
}

// A REPORT WITH NO PROJECTION AT ALL — written before PolicyPosture shipped, or by a run that could read
// nothing — is unreadable on every dimension, never agreeing with anything.
func TestDivergence_AReportWithNoProjectionIsUnreadableNotAgreeing(t *testing.T) {
	a := cluster("a", posture(true, nsPosture("app", "restricted", 0, 0, 0, true, true, true)))
	b := cluster("b", nil)
	d := Compute([]*types.AuditReport{a, b}, nil)
	if d == nil {
		t.Fatal("no surface")
	}
	if d.SameCount != 0 {
		t.Errorf("a report carrying no policy projection agreed with %d dimension(s)", d.SameCount)
	}
	if notComparedFor(d, "cluster", DimOperators) == nil {
		t.Error("a missing projection was not recorded as unreadable on the operators dimension")
	}
	// Its namespaces are not asserted absent either: a cluster we could not read a namespace list from has
	// not been shown to lack anything.
	if len(d.NamespaceMembership) != 0 {
		t.Errorf("a cluster with no readable namespace list was reported as missing namespaces: %+v",
			d.NamespaceMembership)
	}
}

// §5.6 — THE BANNED-PHRASE TEST, AND ITS SCOPE IS THE HALF OF THE PAYLOAD WE WROTE.
//
// The first version of this test ran the banned list over the whole payload and failed on "baseline" — which
// is a Pod Security Admission LEVEL, one of privileged/baseline/restricted, read from a namespace label. The
// cluster's own word, not ours. A copy policy applied to cluster data has two failure modes and both are
// bad: a customer who names a namespace `legacy-wrong` fails our build, and the pressure that creates is to
// SANITISE the customer's data to pass a lint, which corrupts the evidence to satisfy the style guide.
//
// So the split is explicit and load-bearing:
//
//	OURS   — dimension identifiers, the presence strings, the absent string, the literal "cluster" scope.
//	         The banned list applies in full.
//	THEIRS — namespace names, PSA label values, operator group names. Rendered as read, never linted.
//
// Non-vacuity: fatal when the fixture produces no rows, no membership and no not-compared entries — a phrase
// test over an empty corpus passes for the wrong reason, which is the guard shape node_drain_test.go
// established.
func TestDivergence_NeverAssertsAVerdict(t *testing.T) {
	banned := []string{
		"drift", "misconfigured", "should match", "should be", "inconsistent", "wrong", "mismatch",
		"incorrect", "expected", "baseline", "canonical", "out of sync", "violation", "correct",
	}
	a := cluster("prod", posture(true,
		nsPosture("payments", "restricted", 1, 1, 1, true, true, true),
		nsPosture("legacy", "privileged", 0, 0, 0, true, true, true)))
	b := cluster("staging", posture(true,
		nsPosture("payments", "baseline", 0, 0, 0, true, false, true)))
	d := Compute([]*types.AuditReport{a, b}, []types.SkippedCluster{{Context: "dr", Reason: "not reachable"}})
	if d == nil || len(d.Rows) == 0 || len(d.NamespaceMembership) == 0 || len(d.NotCompared) == 0 {
		t.Fatalf("the fixture produced no rows, no membership and no not-compared entries, so this test "+
			"would pass over an empty corpus: %+v", d)
	}

	// OURS: every dimension identifier the payload actually emitted, plus the strings this package mints.
	ours := map[string]bool{absent: true, presence(0): true, presence(1): true}
	for _, r := range d.Rows {
		ours[r.Dimension] = true
		if r.Scope == "cluster" {
			ours[r.Scope] = true
		}
	}
	for _, nc := range d.NotCompared {
		ours[nc.Dimension] = true
	}
	if len(ours) < 5 {
		t.Fatalf("only %d authored string(s) reached the payload, so the ban has almost nothing to check", len(ours))
	}
	for s := range ours {
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("the authored string %q contains %q — the supportable sentence is \"these "+
					"clusters declare different values for X\" and nothing stronger", s, b)
			}
		}
	}

	// THEIRS: asserted PRESENT and unaltered, which is the other half of the same rule. A value read from a
	// namespace label reaches the payload exactly as the cluster wrote it.
	row := rowFor(d, "payments", DimPSSEnforce)
	if row == nil {
		t.Fatal("no enforce row")
	}
	var seen []string
	for _, v := range row.Values {
		seen = append(seen, v.Value)
	}
	if !reflect.DeepEqual(seen, []string{"baseline", "restricted"}) {
		t.Errorf("the cluster's own PSA levels were not rendered as read: %v", seen)
	}
}

// THE ENGINE'S OWN SOURCE MAY NOT USE "drift" IN AN EMITTED STRING either. internal/lexicon does not ban the
// word globally (that is a separate decision), so this family bans it for itself.
func TestDivergence_TheWordDriftIsNotInAnyEmittedString(t *testing.T) {
	for _, s := range []string{absent, presence(0), presence(1), DimPSSEnforce, DimPSSAudit, DimPSSWarn,
		DimNetworkPolicy, DimResourceQuota, DimLimitRange, DimOperators} {
		if strings.Contains(strings.ToLower(s), "drift") {
			t.Errorf("%q asserts a shared origin that moved apart, and we did not read an origin", s)
		}
	}
}
