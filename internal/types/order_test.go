package types

import "testing"

// order_test.go — the report's own ordering has to be an ORDER.
//
// SortByPriority sorted on severity then dollars and stopped there, so two findings tied on both compared
// equal in BOTH directions and kept their INPUT order. That is not an order: the same cluster read twice can
// put a different finding first, which is visible output — Summary.HighestPriorityID in the JSON, the
// renderer's "Highest priority" tile, and the deep-link ids in Architecture.Topologies and .Flows, all of
// which read findings[0] or keep the first finding per resource on a tie.
//
// internal/verdict has carried this tie-break since it was written, and all eight finding-emitting analyzers
// end with a sort on ID. The report's ordering was the one place the discipline was skipped.
//
// BOTH INPUT PERMUTATIONS ARE ASSERTED. A comparator with no tie-break preserves input order, so it agrees
// with exactly one of the two and a single-permutation test would pass on the broken code.

func TestSortByPriority_IsATotalOrder(t *testing.T) {
	tied := func(id string) Finding {
		return Finding{ID: id, Severity: SeverityHigh, DollarImpactMonthly: 100, Title: "tied"}
	}
	a, b := tied("f-aaaaaaaaaaaa"), tied("f-bbbbbbbbbbbb")

	fwd := []Finding{a, b}
	rev := []Finding{b, a}
	SortByPriority(fwd)
	SortByPriority(rev)
	if fwd[0].ID != rev[0].ID || fwd[1].ID != rev[1].ID {
		t.Fatalf("the output order follows the input order, so it is not an order:\n  a,b -> %s,%s\n  b,a -> %s,%s",
			fwd[0].ID, fwd[1].ID, rev[0].ID, rev[1].ID)
	}
	if fwd[0].ID != a.ID {
		t.Errorf("ties do not break on the id ascending: %s came first", fwd[0].ID)
	}

	// Non-vacuity: the tie-break is the LAST word, never the first. Severity outranks the id, and dollars
	// outrank the id within one severity — otherwise this test would pass on a comparator that sorts by id
	// alone and reorders the whole report.
	mixed := []Finding{
		{ID: "f-000000000001", Severity: SeverityLow, DollarImpactMonthly: 900},
		{ID: "f-zzzzzzzzzzzz", Severity: SeverityCritical, DollarImpactMonthly: 1},
		{ID: "f-mmmmmmmmmmmm", Severity: SeverityCritical, DollarImpactMonthly: 500},
	}
	SortByPriority(mixed)
	if mixed[0].Severity != SeverityCritical || mixed[0].DollarImpactMonthly != 500 {
		t.Errorf("the id tie-break outranked severity or dollars: first is %+v", mixed[0])
	}
	if mixed[2].Severity != SeverityLow {
		t.Errorf("a low-severity finding did not sort last: %+v", mixed[2])
	}
}

// DeriveSummary picks HighestPriorityID by its own scan, not by reading findings[0], and Validate() hard-fails
// a report whose stored value disagrees. So the scan needs the same total order or the two disagree on a tie.
func TestDeriveSummary_HighestPriorityIsTotallyOrdered(t *testing.T) {
	tied := func(id string) Finding {
		return Finding{ID: id, Severity: SeverityHigh, DollarImpactMonthly: 100}
	}
	a, b := tied("f-aaaaaaaaaaaa"), tied("f-bbbbbbbbbbbb")
	if got, want := DeriveSummary([]Finding{a, b}).HighestPriorityID, DeriveSummary([]Finding{b, a}).HighestPriorityID; got != want {
		t.Fatalf("HighestPriorityID depends on input order: %s vs %s", got, want)
	}
	if got := DeriveSummary([]Finding{b, a}).HighestPriorityID; got != a.ID {
		t.Errorf("the tie did not break on the id ascending: %s", got)
	}
}
