package types

import "testing"

// ONE PLACE DECIDES WHETHER A READING READ ANYTHING.
//
// Seventeen of the 127 closed entries in docs/DECISIONS.md are one mechanism: the raw AuditReport read by
// many packages, each deciding for itself what the reading amounts to. The money half was closed by
// DollarsAreAMeasurementForReading; this is the question underneath it, and the surfaces were asking it in
// their own words — `len(ar.Methodology.DeniedKinds) == 0` as a proof of completeness, which is only true
// if something was collected.
func TestCoverageOf_TellsTheFourStatesApart(t *testing.T) {
	for _, c := range []struct {
		name                string
		collected, denied   []string
		complete, nothing   bool
		partial, unrecorded bool
	}{
		{name: "everything asked for was read", collected: []string{"pods", "nodes"}, complete: true},
		{name: "some kinds were refused", collected: []string{"pods"}, denied: []string{"nodes"}, partial: true},
		{name: "nothing was read and the refusals are recorded", denied: []string{"pods", "nodes"}, nothing: true},
		// THE STATE THE EVIDENCE PACK GOT WRONG. No kind collected and no kind denied: an older engine, or a
		// run that failed before it asked. "Every kind the reading asked for was read" is a claim about a
		// reading that asked for nothing, and the pack made it.
		{name: "neither collected nor denied is recorded", unrecorded: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cov := CoverageOf(&AuditReport{Methodology: Methodology{
				CollectedKinds: c.collected, DeniedKinds: c.denied,
			}})
			if got := cov.Complete(); got != c.complete {
				t.Errorf("Complete() = %v, want %v", got, c.complete)
			}
			if got := cov.ReadNothing(); got != c.nothing {
				t.Errorf("ReadNothing() = %v, want %v", got, c.nothing)
			}
			if got := cov.Partial(); got != c.partial {
				t.Errorf("Partial() = %v, want %v", got, c.partial)
			}
			if got := cov.Unrecorded(); got != c.unrecorded {
				t.Errorf("Unrecorded() = %v, want %v", got, c.unrecorded)
			}
			// EXACTLY ONE. Four states that can overlap are four states a surface can read two ways.
			n := 0
			for _, b := range []bool{cov.Complete(), cov.ReadNothing(), cov.Partial(), cov.Unrecorded()} {
				if b {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%d of the four states are true at once; a reading is in one of them", n)
			}
		})
	}
}
