package prom

import (
	"strings"
	"testing"
	"time"
)

// THE TEMPORAL CLAIMS NAMED THE WINDOW THEY ASKED FOR, NOT THE ONE THEY GOT.
//
// Measured on the mesh testbed after six hours of Prometheus:
//
//	usage methodology → window "6h"
//	throttling finding → "Over the 7-day window ending at this reading, 1 container(s) …"
//	alerts finding     → "read from this cluster's own Prometheus, 7-day window ending at this reading"
//
// Same shape as M-127 one file along: TemporalWindow is the span the QUERIES span, and Prometheus answers
// them over whatever history it holds. HistoryCoverage already measures the real span for the usage path;
// Temporal carries it now, and WindowText names the shorter of the two.
//
// A claim over six hours that says seven days is wrong in the direction that matters: it makes a quiet
// afternoon look like a quiet week.
func TestTemporal_WindowTextNamesTheHistoryItActuallyHad(t *testing.T) {
	full := &Temporal{Window: TemporalWindow}
	if got := full.WindowText(); !strings.Contains(got, "7-day") {
		t.Errorf("a temporal set with no coverage measured lost its nominal window: %q", got)
	}

	short := &Temporal{Window: TemporalWindow, Covered: 6 * time.Hour, CoverageKnown: true}
	got := short.WindowText()
	if strings.Contains(got, "7-day") {
		t.Errorf("six hours of history is described as seven days: %q", got)
	}
	if !strings.Contains(got, "6h") {
		t.Errorf("the text does not name the history it had: %q", got)
	}
	if !strings.Contains(got, "ending at this reading") {
		t.Errorf("the text lost the clause that anchors it in time: %q", got)
	}

	// THE OVER-REACH: coverage at or beyond the nominal window keeps the nominal wording, because that is
	// what the queries measured.
	long := &Temporal{Window: TemporalWindow, Covered: 30 * 24 * time.Hour, CoverageKnown: true}
	if got := long.WindowText(); !strings.Contains(got, "7-day") {
		t.Errorf("a cluster with a month of history reports %q instead of the window the queries span", got)
	}
}
