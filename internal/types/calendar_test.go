package types

import (
	"strings"
	"testing"
)

// Spec 2026-08-28 §5: a date we did not read is not a date. Every row names one source and only one; a
// not-assessed entry names a clock and a reason. The validator is where that stops being prose.
func TestCalendar_ValidateRefusesARowWithoutASource(t *testing.T) {
	obj := &ResourceRef{Kind: "Certificate", Namespace: "payments", Name: "tls"}
	good := []CalendarRow{
		{Date: "2026-09-14", Kind: CalendarRowObject, Object: obj, Field: "status.notAfter", Observation: "Certificate payments/tls reports status.notAfter = 2026-09-14"},
		{Date: "2026-11-26", Kind: CalendarRowDataset, Dataset: "kubeversions", DatasetVersion: "2026-08-31", DatasetSource: "embedded", Observation: "ordinary support for Kubernetes 1.31 on aws ends 2026-11-26"},
	}
	if errs := validateCalendar(&Calendar{Rows: good, NotAssessed: []ClockNotAssessed{{Clock: "operator support windows", Reason: "an image tag is not a version"}}}); len(errs) != 0 {
		t.Fatalf("two well-formed rows refused: %v", errs)
	}
	if errs := validateCalendar(nil); len(errs) != 0 {
		t.Fatalf("a nil calendar is a reading that recorded none, not an error: %v", errs)
	}
	if errs := validateCalendar(&Calendar{}); len(errs) != 0 {
		t.Fatalf("an empty calendar is assessed-with-none, not an error: %v", errs)
	}

	bad := map[string]CalendarRow{
		"object row without an object":        {Date: "2026-09-14", Kind: CalendarRowObject, Field: "status.notAfter", Observation: "x"},
		"object row without a field":          {Date: "2026-09-14", Kind: CalendarRowObject, Object: obj, Observation: "x"},
		"dataset row without a version":       {Date: "2026-11-26", Kind: CalendarRowDataset, Dataset: "kubeversions", DatasetSource: "embedded", Observation: "x"},
		"dataset row with an invented source": {Date: "2026-11-26", Kind: CalendarRowDataset, Dataset: "kubeversions", DatasetVersion: "2026-08-31", DatasetSource: "guessed", Observation: "x"},
		"row citing both":                     {Date: "2026-11-26", Kind: CalendarRowDataset, Dataset: "kubeversions", DatasetVersion: "2026-08-31", DatasetSource: "embedded", Object: obj, Observation: "x"},
		"row of no kind":                      {Date: "2026-11-26", Observation: "x"},
		"row with a loose date":               {Date: "2026-9-1", Kind: CalendarRowObject, Object: obj, Field: "status.notAfter", Observation: "x"},
		"row with no observation":             {Date: "2026-09-01", Kind: CalendarRowObject, Object: obj, Field: "status.notAfter"},
	}
	for name, r := range bad {
		if errs := validateCalendar(&Calendar{Rows: []CalendarRow{r}}); len(errs) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	if errs := validateCalendar(&Calendar{NotAssessed: []ClockNotAssessed{{Clock: "certificate expiry"}}}); len(errs) == 0 {
		t.Error("a not-assessed clock without a reason was accepted")
	}

	// Through the report's own Validate, so the block is on the path every assembled report takes.
	ar := &AuditReport{SchemaVersion: "v1", Summary: DeriveSummary(nil), Calendar: &Calendar{Rows: []CalendarRow{bad["row of no kind"]}}}
	err := ar.Validate()
	if err == nil || !strings.Contains(err.Error(), "calendar row 0") {
		t.Fatalf("AuditReport.Validate did not reach the calendar: %v", err)
	}
}
