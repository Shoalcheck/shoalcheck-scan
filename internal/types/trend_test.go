package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestTrendDelta_OmittedWhenNil proves AuditReport.Trend is omitempty: a report
// built without history marshals without a "trend" key at all, so existing
// fixtures, the round-trip test, and Validate() are unaffected by the addition.
func TestTrendDelta_OmittedWhenNil(t *testing.T) {
	ar := AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   time.Now(),
		Cluster:       ClusterInfo{Name: "c"},
		Summary:       DeriveSummary(nil),
		Methodology:   Methodology{CollectorsRun: []string{"kubernetes"}},
	}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "trend") {
		t.Fatalf("nil Trend must be omitted from JSON, got: %s", data)
	}
	// A report with no Trend must still validate (Trend is never required).
	if err := ar.Validate(); err != nil {
		t.Fatalf("report without Trend must validate: %v", err)
	}
}

// TestTrendDelta_PresentRoundTrips proves a populated Trend marshals with the
// documented JSON keys and survives a round-trip.
func TestTrendDelta_PresentRoundTrips(t *testing.T) {
	prev := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	ar := AuditReport{
		SchemaVersion: "v1",
		GeneratedAt:   time.Now(),
		Cluster:       ClusterInfo{Name: "c"},
		Summary:       DeriveSummary(nil),
		Methodology:   Methodology{CollectorsRun: []string{"kubernetes"}},
		Trend: &TrendDelta{
			PreviousAt:    prev,
			NewCount:      3,
			ResolvedCount: 2,
			FindingsDelta: 1,
			SavingsDelta:  -150.5,
		},
	}
	data, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"trend"`, `"previousAt"`, `"newCount"`, `"resolvedCount"`, `"findingsDelta"`, `"savingsDelta"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshalled report missing key %s: %s", key, data)
		}
	}
	var got AuditReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Trend == nil {
		t.Fatal("Trend lost in round-trip")
	}
	if !got.Trend.PreviousAt.Equal(prev) || got.Trend.NewCount != 3 ||
		got.Trend.ResolvedCount != 2 || got.Trend.FindingsDelta != 1 || got.Trend.SavingsDelta != -150.5 {
		t.Fatalf("Trend round-trip mismatch: %+v", got.Trend)
	}
}
