package types

import (
	"fmt"
	"time"
)

// calendar.go — "things with a clock": the dated obligations a run could read, each with where its date came
// from, and the clocks the run could not assess.
//
// WHY A SEPARATE BLOCK AND NOT A FINDING FAMILY. A finding says something is wrong; a date says when something
// will be true. The certificate that expires on the 14th is not a defect on the 3rd — it is a scheduled fact
// the report can state without asserting anything about the cluster's health. The backlog (W-1) wanted the
// front page turned into this; the spec (2026-08-28) narrowed it to a component inside the Change Preflight
// pillar, because "what will stop your next change" is the question a date answers.
//
// TWO KINDS OF ROW, AND A ROW IS NEVER BOTH. An OBJECT row's date was read from a field on an object in the
// cluster (cert-manager's status.notAfter). A DATASET row's date came from a reference table this build carries
// (a Kubernetes minor's support window), and it names the table's version and where the bytes came from,
// because an embedded table and a live one age differently. Validate refuses a row with both provenances or
// neither: "a date we did not read is not a date" is the spec's first boundary and it is enforced here rather
// than in prose.
//
// NotAssessed IS NOT OPTIONAL PADDING. "Four dated obligations" is a claim about our coverage as much as about
// the cluster; the list beside it is what stops the shorter census from overclaiming. A renderer prints them
// together or not at all.

// Calendar is the block.
type Calendar struct {
	// Rows are the dated obligations, sorted by date. An empty slice with a non-nil Calendar means ASSESSED
	// WITH NONE ON RECORD — a different statement from a nil Calendar (the reading recorded no calendar) and
	// from an entry in NotAssessed (a clock this run could not read).
	Rows []CalendarRow `json:"rows"`
	// NotAssessed names every clock the run could not read, with the reason. Always rendered beside the count.
	NotAssessed []ClockNotAssessed `json:"notAssessed,omitempty"`
}

// CalendarRow is one dated obligation.
type CalendarRow struct {
	// Date is "YYYY-MM-DD". A time of day, where the source has one, belongs in Observation.
	Date string `json:"date"`
	// Passed is true when Date is before the day the snapshot was taken — the snapshot's own clock, never the
	// wall clock, so re-rendering yesterday's reading does not move a row across the line.
	Passed bool `json:"passed,omitempty"`
	// Kind is CalendarRowObject or CalendarRowDataset.
	Kind string `json:"kind"`
	// Object and Field are set on an object row: the object the date was read from and the field it sat in.
	Object *ResourceRef `json:"object,omitempty"`
	Field  string       `json:"field,omitempty"`
	// Dataset, DatasetVersion and DatasetSource are set on a dataset row: the registry name of the table, its
	// stamp, and the closed provenance set embedded|cache|bundle|live (see DataSourceValid).
	Dataset        string `json:"dataset,omitempty"`
	DatasetVersion string `json:"datasetVersion,omitempty"`
	DatasetSource  string `json:"datasetSource,omitempty"`
	// Observation is one sentence stating the fact: what reports the date, and what the date is the end of.
	// No urgency vocabulary — the calendar lexicon scope bans it — because the date already implies whatever
	// urgency there is, and the reader draws it.
	Observation string `json:"observation"`
	// FindingIDs are the findings this row rests on or bears on, so a surface can deep-link them.
	FindingIDs []string `json:"findingIds,omitempty"`
}

// ClockNotAssessed is one clock the run could not read, and why.
type ClockNotAssessed struct {
	Clock  string `json:"clock"`
	Reason string `json:"reason"`
}

// Deadline is a date a finding read from the object it is about, as a structured value beside the prose that
// already quotes it. It exists so the calendar can be assembled from findings without parsing evidence
// sentences, and so a future analyzer with a clock joins the block by setting one field.
type Deadline struct {
	// Date is "YYYY-MM-DD".
	Date string `json:"date"`
	// Field is the object field the date was read from, e.g. "status.notAfter".
	Field string `json:"field"`
}

// Headline is the opening: at most five claims, each with where it came from.
type Headline struct {
	Lines []HeadlineLine `json:"lines"`
	// Remainder is the one line for everything not shown, so nothing is hidden by being left out.
	Remainder string `json:"remainder,omitempty"`
	// Trace is the reading's own cost: what it issued, what it wrote, what it could not read.
	Trace string `json:"trace,omitempty"`
	Shown int    `json:"shown"`
	Total int    `json:"total"`
}

// HeadlineLine is one claim and the basis under it. Never one without the other.
type HeadlineLine struct {
	Claim      string   `json:"claim"`
	Basis      string   `json:"basis"`
	Kind       string   `json:"kind"`
	FindingIDs []string `json:"findingIds,omitempty"`
}

// The two row kinds.
const (
	CalendarRowObject  = "object"
	CalendarRowDataset = "dataset"
)

// calendarDay is the Date layout.
const calendarDay = "2006-01-02"

// ParseCalendarDay parses a row's Date. It is exported because the pipeline and the renderer both need the same
// reading of the same string.
func ParseCalendarDay(s string) (time.Time, bool) {
	t, err := time.Parse(calendarDay, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// validateCalendar enforces the row contract. A nil calendar is valid: readings written before the block
// existed carry none, and the renderer has a sentence for that.
func validateCalendar(c *Calendar) []error {
	if c == nil {
		return nil
	}
	var errs []error
	for i, r := range c.Rows {
		at := fmt.Sprintf("calendar row %d", i)
		if _, ok := ParseCalendarDay(r.Date); !ok {
			errs = append(errs, fmt.Errorf("%s: date %q is not YYYY-MM-DD", at, r.Date))
		}
		if r.Observation == "" {
			errs = append(errs, fmt.Errorf("%s: empty observation", at))
		}
		hasObject := r.Object != nil || r.Field != ""
		hasDataset := r.Dataset != "" || r.DatasetVersion != "" || r.DatasetSource != ""
		switch r.Kind {
		case CalendarRowObject:
			if r.Object == nil || r.Object.Kind == "" || r.Object.Name == "" || r.Field == "" {
				errs = append(errs, fmt.Errorf("%s: an object row needs the object (kind and name) and the field the date was read from", at))
			}
			if hasDataset {
				errs = append(errs, fmt.Errorf("%s: an object row must not also cite a dataset", at))
			}
		case CalendarRowDataset:
			if r.Dataset == "" || r.DatasetVersion == "" || !DataSourceValid(r.DatasetSource) {
				errs = append(errs, fmt.Errorf("%s: a dataset row needs the dataset, its version and a valid source (got %q, %q, %q)", at, r.Dataset, r.DatasetVersion, r.DatasetSource))
			}
			if hasObject {
				errs = append(errs, fmt.Errorf("%s: a dataset row must not also cite an object", at))
			}
		default:
			errs = append(errs, fmt.Errorf("%s: kind %q is neither %q nor %q", at, r.Kind, CalendarRowObject, CalendarRowDataset))
		}
	}
	for i, n := range c.NotAssessed {
		if n.Clock == "" || n.Reason == "" {
			errs = append(errs, fmt.Errorf("calendar notAssessed %d: a clock and a reason are both required (got %q, %q)", i, n.Clock, n.Reason))
		}
	}
	return errs
}
