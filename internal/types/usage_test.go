package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUsageConfidenceValid(t *testing.T) {
	cases := []struct {
		c    UsageConfidence
		want bool
	}{
		{UsageConfidenceHigh, true},
		{UsageConfidenceLow, true},
		{UsageConfidenceNone, true},
		{"", true}, // zero value valid so omitempty-absent never fails Validate
		{"bogus", false},
	}
	for _, tc := range cases {
		if got := tc.c.Valid(); got != tc.want {
			t.Errorf("UsageConfidence(%q).Valid() = %v, want %v", tc.c, got, tc.want)
		}
	}
}

func TestUsageMethodologyZeroValue(t *testing.T) {
	var m UsageMethodology
	if m.Source != "" || m.Confidence != "" || m.Window != "" || len(m.Caveats) != 0 {
		t.Errorf("zero UsageMethodology must be all-empty, got %+v", m)
	}
}

// REPLACED 2026-09-10. This asserted that `CostFloorMo` was omitted when zero and serialised when set —
// and it was the ONLY writer of that field anywhere in the tree, which is precisely why it went. A spot
// price FLOOR existed in this test's expectations and in no reading ever produced: the spot work shipped
// the on-demand list as an honest ceiling and refused a floor, because a real spot price needs cloud auth
// this tool does not hold. See docs/DECISIONS.md M-62 and the removal note in audit.go.
//
// What survives is the property that outlives the field: the pool serialises without inventing a band.
func TestNodePoolSerialisesNoSpotBand(t *testing.T) {
	b, _ := json.Marshal(NodePoolSummary{Type: "m6i.large", Count: 1, CostMo: 75})
	for _, gone := range []string{"costFloorPerNodeMonth", "costFloor", "spotFloor"} {
		if strings.Contains(string(b), gone) {
			t.Errorf("a node pool serialises %q — the ceiling is the only price this product has, and a "+
				"floor field invites a band it cannot measure: %s", gone, b)
		}
	}
	if !strings.Contains(string(b), `"costPerNodeMonth":75`) {
		t.Errorf("the on-demand ceiling must still serialise, got %s", b)
	}
}

func TestStorageSchemaOmitempty(t *testing.T) {
	b, _ := json.Marshal(Architecture{})
	if strings.Contains(string(b), "unpricedStorageClasses") {
		t.Errorf("empty UnpricedStorageClasses must be omitted, got %s", b)
	}
	b2, _ := json.Marshal(ClusterInfo{Name: "c"})
	if strings.Contains(string(b2), "storageMonthlyUsd") || strings.Contains(string(b2), "egressMonthlyUsd") {
		t.Errorf("zero storage/egress must be omitted, got %s", b2)
	}
	b3, _ := json.Marshal(Architecture{UnpricedStorageClasses: []string{"gp2"}})
	if !strings.Contains(string(b3), `"unpricedStorageClasses":["gp2"]`) {
		t.Errorf("populated UnpricedStorageClasses must serialize, got %s", b3)
	}
}

func TestMethodologyUsageOmitempty(t *testing.T) {
	b, err := json.Marshal(Methodology{CollectorsRun: []string{"kubernetes"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "usageMethodology") {
		t.Errorf("nil UsageMethodology must be omitted, got %s", b)
	}

	b2, _ := json.Marshal(Methodology{
		CollectorsRun:    []string{"kubernetes"},
		UsageMethodology: &UsageMethodology{Source: "prometheus", Confidence: UsageConfidenceHigh, Window: "7d"},
	})
	if !strings.Contains(string(b2), `"usageMethodology"`) || !strings.Contains(string(b2), `"prometheus"`) {
		t.Errorf("populated UsageMethodology must serialize, got %s", b2)
	}
}
