package types

// ReadingCoverage is what a reading amounts to, decided once.
//
// SEVENTEEN OF THE 127 CLOSED ENTRIES ARE THE SAME MECHANISM: the raw AuditReport read by many packages,
// each deciding for itself what the reading amounts to. The money question was closed first —
// DollarsAreAMeasurementForReading — and this is the question underneath it. The surfaces were asking it in
// their own words, and the words were not equivalent: an evidence pack proved completeness from
// `len(DeniedKinds) == 0`, which is true of a reading that never asked for anything.
//
// FOUR STATES, EXACTLY ONE OF WHICH IS TRUE. A reading either read everything it asked for, read some of
// it, read none of it, or does not record the question at all — and that fourth state is not a synonym for
// any of the others. It is what an older engine wrote, and what a run that failed before it asked leaves
// behind.
type ReadingCoverage struct {
	Collected, Denied int
}

// CoverageOf reads the two counts the reading carries. It takes the report rather than the counts so that
// a caller cannot accidentally ask the question about one of them.
func CoverageOf(ar *AuditReport) ReadingCoverage {
	if ar == nil {
		return ReadingCoverage{}
	}
	return ReadingCoverage{
		Collected: len(ar.Methodology.CollectedKinds),
		Denied:    len(ar.Methodology.DeniedKinds),
	}
}

// Complete: every kind the reading asked for was read. It requires a collected kind, because a reading that
// asked for nothing has not proved anything by failing at nothing.
func (c ReadingCoverage) Complete() bool { return c.Collected > 0 && c.Denied == 0 }

// Partial: something was read and something was not.
func (c ReadingCoverage) Partial() bool { return c.Collected > 0 && c.Denied > 0 }

// ReadNothing: the reading asked and every list failed. The refusals are the evidence that it asked.
func (c ReadingCoverage) ReadNothing() bool { return c.Collected == 0 && c.Denied > 0 }

// Unrecorded: neither side is recorded, so the reading cannot say. Never a synonym for Complete.
func (c ReadingCoverage) Unrecorded() bool { return c.Collected == 0 && c.Denied == 0 }
