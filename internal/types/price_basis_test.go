package types

import "testing"

// A ZERO OVER A READING THAT READ NOTHING IS NOT A MEASUREMENT EITHER, AND THE FINDINGS CANNOT SAY SO.
//
// DollarsAreAMeasurement's loop asks whether any finding failed to price. Over a reading that collected no
// resource kind at all there ARE no findings, so the loop passes vacuously and the rule answers true — the
// gate-over-an-empty-set shape, sitting inside the rule itself.
//
// Measured by opening ~/.shoalcheck/history/dead in the app window: 0 findings, 0 collected kinds, 20 denied,
// and /api/queue answered {"findings":0,"dollars":0,"dollarsPriced":true} — so the queue header printed
// "$0/mo" over a cluster nothing had ever connected to.
func TestDollarsAreAMeasurementForReading_AReadingThatReadNothingHasNoFigure(t *testing.T) {
	mk := func(collected, denied []string, fs ...Finding) *AuditReport {
		ar := &AuditReport{
			Findings:    fs,
			Methodology: Methodology{CollectedKinds: collected, DeniedKinds: denied},
		}
		ar.Summary = DeriveSummary(fs)
		return ar
	}
	priced := Finding{ID: "f-1", PriceBasis: PricePriced, DollarImpactMonthly: 400, Severity: SeverityHigh}
	unpriced := Finding{ID: "f-2", PriceBasis: PriceUnpriced, Severity: SeverityHigh}
	notCost := Finding{ID: "f-3", PriceBasis: PriceNotCost, Severity: SeverityHigh}

	cases := []struct {
		name string
		ar   *AuditReport
		want bool
		why  string
	}{
		{"read nothing at all", mk(nil, []string{"pods", "nodes"}), false,
			"no kind was read, so there are no findings to carry a basis and the zero is an absence of knowledge"},
		{"records no coverage", mk(nil, nil), false,
			"a reading that does not record what it read cannot say its zero was measured"},
		{"read everything, found nothing", mk([]string{"pods", "nodes"}, nil), true,
			"the kinds were read and no finding failed to price — this zero IS the measurement"},
		{"read one kind of twenty-three", mk([]string{"pods"}, []string{"nodes", "persistentvolumeclaims"}), false,
			"a zero over a partial read is the same claim the empty-state sentence already refuses: \"Some " +
				"resource kinds were not read at all, so nothing is claimed about them.\" A cost finding " +
				"comes from the kinds that were denied"},
		{"read everything, one unpriced", mk([]string{"pods"}, nil, unpriced), false,
			"one finding could not be priced, so the total is a floor of unknown depth"},
		{"read everything, all not-cost", mk([]string{"pods"}, nil, notCost), true,
			"nothing had a price dimension, which is a measured zero"},
		{"a real figure", mk([]string{"pods"}, nil, priced), true,
			"a positive total came from findings that priced"},
		{"a real figure over a partial read", mk([]string{"pods"}, []string{"nodes"}, priced), true,
			"the figure is real whatever else failed — never discard one the reading carries"},
		{"a real figure with no recorded coverage", mk(nil, nil, priced), true,
			"THE OVER-REACH THE COVERAGE CHECK MUST NOT COMMIT: a reading that does not record what it read " +
				"still carries a $412 finding that priced, and discarding that figure is the other half of " +
				"the same dishonesty"},
	}
	for _, c := range cases {
		if got := DollarsAreAMeasurementForReading(c.ar); got != c.want {
			t.Errorf("%s: got %v, want %v — %s", c.name, got, c.want, c.why)
		}
	}

	// A nil reading is not a reading with a measured zero.
	if DollarsAreAMeasurementForReading(nil) {
		t.Error("a nil reading reports a measured figure")
	}
	t.Logf("%d reading shape(s) checked", len(cases))
}
