package collect

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

// THE DATE OF A READING IS AN INPUT; HOW LONG THE RUN TOOK IS NOT.
//
// Meta.StartedAt is the clock every duration in a finding is measured against — rules.readingTime and
// analyzers.readingTime both return it — and it was time.Now() with no way to say otherwise. The committed
// reference reading therefore carried a sentence that changed by itself: "62 day(s) since the pod was
// created" became 63 at midnight, and `make ci` failed the next morning on a tree nobody had touched. The
// fixture stamps its objects absolutely on purpose, which pins the STATE and leaves every DURATION drifting
// because the other end of the subtraction was the wall clock.
//
// AND THE TWO CLOCKS ARE NOT ONE. The first version of this pinned StartedAt and left the run's duration as
// time.Since(StartedAt), which reported 39,796 seconds for a run that took 0.4 — the pinned instant
// subtracted from the moment the golden happened to be generated. A reading is DATED at StartedAt and TOOK
// Duration, and those are different questions.
func TestWithClock_PinsTheReadingDateAndNotTheRunDuration(t *testing.T) {
	pinned := time.Date(2026, 9, 15, 5, 28, 50, 0, time.UTC)

	inv, err := NewWithClients(fake.NewSimpleClientset(), nil, nil,
		WithClock(func() time.Time { return pinned })).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !inv.Meta.StartedAt.Equal(pinned) {
		t.Errorf("Meta.StartedAt is %s, want the pinned %s — every duration a finding states is measured "+
			"against this, so a reference reading regenerated tomorrow says something different",
			inv.Meta.StartedAt, pinned)
	}
	// The run took milliseconds. Anything near the distance between the pinned instant and now is the
	// duration having been derived from the pinned clock instead of from wall time.
	if inv.Meta.Duration > time.Hour {
		t.Errorf("Meta.Duration is %s for a run against a fake clientset: the duration is being measured "+
			"from the PINNED instant rather than from when the run actually started", inv.Meta.Duration)
	}

	// AND THE REPORT IS DATED BY THE SAME CLOCK. GeneratedAt was a SECOND wall-clock read, and
	// internal/pipeline renders it as a DATE into the methodology — "read via dynamic discovery … as of
	// 2026-09-15". A date in prose is not an RFC3339 instant, so the golden gate's instant-normalisation
	// cannot see it, and both reference readings still drifted at midnight UTC after the durations had
	// been pinned. One fact, one clock.
	ar := BuildReport(inv, nil, "pinned", 0, nil)
	if !ar.GeneratedAt.Equal(pinned) {
		t.Errorf("the report is dated %s and the reading was taken at %s; a second clock here is a date "+
			"rendered into the methodology that changes by itself", ar.GeneratedAt, pinned)
	}

	// AND THE DEFAULT IS THE WALL CLOCK, because a real audit passes no clock and must not be pinned to
	// anything. Without this the seam could default to a zero time and nothing here would notice.
	live, err := NewWithClients(fake.NewSimpleClientset(), nil, nil).Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect without a clock: %v", err)
	}
	if live.Meta.StartedAt.IsZero() {
		t.Error("a collector with no clock recorded no reading time at all")
	}
	if time.Since(live.Meta.StartedAt) > time.Hour {
		t.Errorf("a collector with no clock dated its reading %s ago; the default must be now",
			time.Since(live.Meta.StartedAt))
	}
}
