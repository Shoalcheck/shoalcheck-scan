package history

import (
	"fmt"
	"sort"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Recurrence across readings: the pairwise comparison applied per (finding, reading).
//
// THE ARCHITECTURAL CONSTRAINT (spec 2026-08-28 §2): a membership scan — "is finding X in reading k?" — would
// bypass every gate and draw a denied read as an absence N-1 times per finding. So a cell is decided by the
// same question the diff asks: could that reading have seen this finding? Blocked answers; the walk never
// re-implements it. Nothing here computes a rate, a frequency or a trend: readings happen when the operator
// runs them, and the axis is their timestamps as recorded.

// StateKind is one of the four things a reading can say about a finding.
type StateKind string

const (
	StatePresent     StateKind = "present"
	StateAbsent      StateKind = "absent"
	StateNotReadable StateKind = "not readable"
	StateRuleChanged StateKind = "present under a changed rule"
)

// State is one cell. Reason is set for StateNotReadable (the missing input, from Blocked) and RuleVersion for
// the two present kinds.
type State struct {
	Kind        StateKind
	Reason      string
	RuleVersion string
}

// Reading is one column: the snapshot's timestamp and what it carried.
type Reading struct {
	At       time.Time
	Path     string
	Label    string
	Findings int

	// Collected and Denied are how many resource kinds the run read and how many it did not, because
	// "0 findings" is not a fact about the cluster unless something was read. A reading with no collected
	// kinds and twenty denied ones renders the same "0 findings" as a clean one, and a reader scanning the
	// column sees a cluster that has been quiet — which is the one conclusion this product refuses to draw
	// from an absence.
	Collected int
	Denied    int
}

// ReadNothing reports whether this reading got no resource list back at all.
func (r Reading) ReadNothing() bool { return r.Collected == 0 && r.Denied > 0 }

// Segment is a run of consecutive readings Gate 0 allowed to be compared. BreakReason is Gate 0's sentence for
// why the reading after To starts a new segment; empty on the last segment.
type Segment struct {
	From, To    int
	BreakReason string
}

// Row is one finding across every reading, index-aligned with Timeline.Readings.
type Row struct {
	FindingID, RuleID, Title string
	States                   []State
}

// Timeline is what `shoalcheck history timeline` prints. Kept is how many readings the store holds for the cluster;
// Limit is how many were asked for — both stated, so a chart over 5 of 200 readings cannot pass as complete.
type Timeline struct {
	Cluster  string
	Readings []Reading
	Rows     []Row
	Segments []Segment
	Limit    int
	Kept     int
}

// Timeline loads the newest `limit` readings of cluster (oldest first in the result), splits them where Gate 0
// refuses a consecutive pair, and decides every (finding, reading) cell. The reference reading for a row's
// rule version is the FIRST reading in the row's segment where the finding is present.
func (s *Store) Timeline(cluster string, deps map[string]Deps, limit int) (Timeline, error) {
	if deps == nil {
		return Timeline{}, fmt.Errorf("no record of what each finding rests on was supplied")
	}
	if limit <= 0 {
		return Timeline{}, fmt.Errorf("limit must be positive; the count looked at is part of the claim")
	}
	snaps, err := s.List(cluster)
	if err != nil {
		return Timeline{}, err
	}
	tl := Timeline{Cluster: cluster, Limit: limit, Kept: len(snaps)}
	if len(snaps) > limit {
		snaps = snaps[:limit]
	}
	// List is newest-first; the timeline reads oldest-first.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].At.Before(snaps[j].At) })
	reports := make([]*types.AuditReport, 0, len(snaps))
	for _, sn := range snaps {
		ar, err := s.Load(sn.Path)
		if err != nil {
			return Timeline{}, err
		}
		reports = append(reports, ar)
		tl.Readings = append(tl.Readings, Reading{
			At: sn.At, Path: sn.Path, Label: ar.Methodology.Label, Findings: len(ar.Findings),
			Collected: len(ar.Methodology.CollectedKinds), Denied: len(ar.Methodology.DeniedKinds),
		})
	}
	tl.Segments = segments(reports, deps)

	// Every finding ID seen anywhere, with the first title and rule it appeared under.
	type seen struct{ rule, title string }
	ids := map[string]seen{}
	var order []string
	for _, ar := range reports {
		for _, f := range ar.Findings {
			if _, ok := ids[f.ID]; !ok {
				ids[f.ID] = seen{f.RuleID, f.Title}
				order = append(order, f.ID)
			}
		}
	}
	sort.Strings(order)
	for _, id := range order {
		r := Row{FindingID: id, RuleID: ids[id].rule, Title: ids[id].title, States: make([]State, len(reports))}
		for _, seg := range tl.Segments {
			// The reference version and the exemplar are the first presence inside THIS segment: a segment
			// boundary is exactly the place where continuity may not be asserted. A segment where the finding
			// never appears borrows the finding's identity from wherever it was first seen, so Blocked can
			// still be asked about the right rule and version.
			exemplar := types.Finding{ID: id, RuleID: r.RuleID, RuleVersion: firstVersionAnywhere(reports, id)}
			for k := seg.From; k <= seg.To; k++ {
				if f, ok := findingIn(reports[k], id); ok {
					exemplar = f
					break
				}
			}
			ref := exemplar.RuleVersion
			for k := seg.From; k <= seg.To; k++ {
				if f, ok := findingIn(reports[k], id); ok {
					if f.RuleVersion != ref {
						r.States[k] = State{Kind: StateRuleChanged, RuleVersion: f.RuleVersion}
					} else {
						r.States[k] = State{Kind: StatePresent, RuleVersion: f.RuleVersion}
					}
					continue
				}
				// Absent from this reading: could it have been seen?
				if why, blocked := Blocked(exemplar, reports[k], deps); blocked {
					r.States[k] = State{Kind: StateNotReadable, Reason: why}
				} else {
					r.States[k] = State{Kind: StateAbsent}
				}
			}
		}
		tl.Rows = append(tl.Rows, r)
	}
	return tl, nil
}

func findingIn(ar *types.AuditReport, id string) (types.Finding, bool) {
	for _, f := range ar.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return types.Finding{}, false
}

func firstVersionAnywhere(reports []*types.AuditReport, id string) string {
	for _, ar := range reports {
		if f, ok := findingIn(ar, id); ok {
			return f.RuleVersion
		}
	}
	return ""
}

// segments applies Gate 0 to every consecutive pair. A refusal ends the segment; the reason travels on it.
func segments(reports []*types.AuditReport, deps map[string]Deps) []Segment {
	if len(reports) == 0 {
		return nil
	}
	var out []Segment
	from := 0
	for k := 1; k < len(reports); k++ {
		if c := comparable(reports[k-1], reports[k], deps); !c.OK {
			out = append(out, Segment{From: from, To: k - 1, BreakReason: c.Reason})
			from = k
		}
	}
	return append(out, Segment{From: from, To: len(reports) - 1})
}
