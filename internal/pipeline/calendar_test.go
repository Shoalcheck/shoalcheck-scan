package pipeline

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// tableDay is the embedded support-window table's stamp as a day; every test measures from it rather than from
// today, because the block itself never reads the wall clock.
func tableDay(t *testing.T) time.Time {
	d, ok := types.ParseCalendarDay(kubeversions.AsOf())
	if !ok {
		t.Fatalf("kubeversions.AsOf() %q is not a day", kubeversions.AsOf())
	}
	return d
}

// calInput builds an inventory and a report the way the pipeline hands them to buildCalendar: the provider on
// the assembled cluster, the version and clock on the collector's Meta, the dataset stamp on the run basis.
func calInput(provider, version string, started time.Time, collected, denied []string, findings ...types.Finding) (*collect.Inventory, *types.AuditReport) {
	inv := &collect.Inventory{Meta: collect.Meta{ServerVersion: version, StartedAt: started, Collected: collected, Denied: denied}}
	ar := &types.AuditReport{
		Cluster:  types.ClusterInfo{Provider: provider},
		Findings: findings,
		Methodology: types.Methodology{RunBasis: &types.RunBasis{DataVersions: map[string]types.DataVersion{
			"kubeversions": {Version: kubeversions.AsOf(), Source: "embedded"},
		}}},
	}
	return inv, ar
}

func certFinding(id, ns, name, date string) types.Finding {
	return types.Finding{ID: id, RuleID: "stack.certmanager.expiring",
		AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: ns, Name: name}},
		Deadline:          &types.Deadline{Date: date, Field: "status.notAfter"}}
}

func reasonsFor(cal *types.Calendar, clock string) []string {
	var out []string
	for _, n := range cal.NotAssessed {
		if n.Clock == clock {
			out = append(out, n.Reason)
		}
	}
	return out
}

func datasetRows(cal *types.Calendar) (n int) {
	for _, r := range cal.Rows {
		if r.Kind == types.CalendarRowDataset {
			n++
		}
	}
	return n
}

// Spec §6 test 1. A table older than the claim window at the reading's own time yields no dataset row AND a
// sentence naming the table's date and the window; the same input inside the window yields rows, which is what
// stops the first half from passing on a builder that never produces any.
func TestCalendar_AnAgedDatasetIsNotAssessedNotEmpty(t *testing.T) {
	stamp := tableDay(t)
	inv, ar := calInput("aws", "v1.31.2-eks-1a2b3c4", stamp.AddDate(0, 0, calendarClaimWindowDays+20), []string{certificatesStep}, nil)
	cal := buildCalendar(inv, ar)
	if datasetRows(cal) != 0 {
		t.Fatalf("an aged table produced dataset rows: %+v", cal.Rows)
	}
	reasons := reasonsFor(cal, clockSupportWindow)
	if len(reasons) != 1 || !strings.Contains(reasons[0], kubeversions.AsOf()) || !strings.Contains(reasons[0], "180-day window") {
		t.Fatalf("the aged table was not named with its date and the window: %v", reasons)
	}
	for _, n := range cal.NotAssessed {
		if strings.Contains(strings.ToLower(n.Reason), "no deadlines found") {
			t.Fatalf("a not-assessed clock read as an absence: %q", n.Reason)
		}
	}

	inv, ar = calInput("aws", "v1.31.2-eks-1a2b3c4", stamp.AddDate(0, 0, 10), []string{certificatesStep}, nil)
	fresh := buildCalendar(inv, ar)
	if datasetRows(fresh) < 1 {
		t.Fatalf("non-vacuity: the same input inside the window produced no dataset row: %+v", fresh)
	}
	if len(reasonsFor(fresh, clockSupportWindow)) != 0 {
		t.Fatalf("a fresh table was reported as not assessed: %v", fresh.NotAssessed)
	}
}

// Spec §6 test 2. Every row has exactly one provenance — an object and its field, or a dataset triple — and the
// fixture produces rows of BOTH kinds, so a checker that only understands one cannot pass by accident.
func TestCalendar_EveryRowNamesItsSource(t *testing.T) {
	stamp := tableDay(t)
	inv, ar := calInput("aws", "v1.31.2-eks-1a2b3c4", stamp.AddDate(0, 0, 3), []string{certificatesStep}, nil,
		certFinding("f-cert", "payments", "tls", stamp.AddDate(0, 0, 9).Format("2006-01-02")),
		types.Finding{ID: "f-api", RuleID: calendarDeprecatedAPIRule})
	cal := buildCalendar(inv, ar)
	if err := (&types.AuditReport{SchemaVersion: "v1", Summary: types.DeriveSummary(nil), Calendar: cal}).Validate(); err != nil {
		t.Fatalf("the assembled block fails the schema's own validator: %v", err)
	}
	kinds := map[string]int{}
	for _, r := range cal.Rows {
		kinds[r.Kind]++
		object := r.Object != nil && r.Field != ""
		dataset := r.Dataset != "" && r.DatasetVersion != "" && r.DatasetSource != ""
		if object == dataset {
			t.Errorf("row %q has %v object provenance and %v dataset provenance; exactly one is allowed", r.Observation, object, dataset)
		}
		if r.Observation == "" || r.Date == "" {
			t.Errorf("row lacks a date or an observation: %+v", r)
		}
	}
	if kinds[types.CalendarRowObject] != 1 || kinds[types.CalendarRowDataset] != 2 {
		t.Fatalf("non-vacuity: want 1 object row and 2 dataset rows (ordinary + extension), got %v", kinds)
	}
	// The ordinary-support row links the API-removal finding and says the upgrade is where it applies.
	var std types.CalendarRow
	for _, r := range cal.Rows {
		if strings.HasPrefix(r.Observation, "ordinary support") {
			std = r
		}
	}
	if len(std.FindingIDs) != 1 || std.FindingIDs[0] != "f-api" || !strings.Contains(std.Observation, "1 API-removal finding applies") {
		t.Errorf("the ordinary-support row does not carry the API-removal finding: %+v", std)
	}
	// Sorted by date: the certificate (9 days out) precedes the two window dates only if those are later, and
	// the sort is by the string, so assert the invariant rather than the order.
	for i := 1; i < len(cal.Rows); i++ {
		if cal.Rows[i-1].Date > cal.Rows[i].Date {
			t.Errorf("rows out of date order: %s after %s", cal.Rows[i-1].Date, cal.Rows[i].Date)
		}
	}
	obj := cal.Rows[0]
	for _, r := range cal.Rows {
		if r.Kind == types.CalendarRowObject {
			obj = r
		}
	}
	if obj.Object.Namespace != "payments" || obj.Object.Name != "tls" || !strings.Contains(obj.Observation, "Certificate payments/tls reports status.notAfter = ") {
		t.Errorf("object row does not name its object and field: %+v", obj)
	}
}

// Spec §6 test 6. Nothing in the block reads the wall clock: the same reading produces the same block on any
// day, and a reading taken the day after the table's stamp is assessed no matter how old the table is today.
func TestCalendar_NoFailureConditionReadsTheWallClock(t *testing.T) {
	stamp := tableDay(t)
	inv, ar := calInput("azure", "1.32.4", stamp.AddDate(0, 0, 1), []string{certificatesStep}, nil)
	first := buildCalendar(inv, ar)
	second := buildCalendar(inv, ar)
	if len(first.Rows) != len(second.Rows) || len(first.NotAssessed) != len(second.NotAssessed) {
		t.Fatalf("two builds of one reading differ: %+v vs %+v", first, second)
	}
	for i := range first.Rows {
		if fmt.Sprintf("%+v", first.Rows[i]) != fmt.Sprintf("%+v", second.Rows[i]) {
			t.Fatalf("row %d differs between two builds", i)
		}
	}
	if datasetRows(first) == 0 {
		t.Fatalf("a reading one day after the stamp was not assessed: %+v", first.NotAssessed)
	}
	// Passed is measured at the reading's clock: a window that ended before the reading is "ended", one that
	// ends after it is "ends", and the wording follows the flag.
	for _, r := range first.Rows {
		d, _ := types.ParseCalendarDay(r.Date)
		wantPassed := stamp.AddDate(0, 0, 1).After(d)
		if r.Passed != wantPassed {
			t.Errorf("row %s: passed=%v, want %v at the reading's clock", r.Date, r.Passed, wantPassed)
		}
		if wantPassed && !strings.Contains(r.Observation, " ended ") || !wantPassed && !strings.Contains(r.Observation, " ends ") {
			t.Errorf("row %s: wording %q does not follow passed=%v", r.Date, r.Observation, r.Passed)
		}
	}
	// No timestamp at all: nothing can be measured, and the block says so rather than assuming today.
	inv, ar = calInput("azure", "1.32.4", time.Time{}, []string{certificatesStep}, nil)
	none := buildCalendar(inv, ar)
	if datasetRows(none) != 0 || len(reasonsFor(none, clockSupportWindow)) != 1 || !strings.Contains(reasonsFor(none, clockSupportWindow)[0], "no timestamp") {
		t.Fatalf("a reading without a clock was placed anyway: %+v", none)
	}
}

// The certificate clock has three states and each has its own sentence: refused (named as a refusal), never
// read (named as such), and read (no entry — the dates, if any, are rows).
func TestCalendar_ADeniedCertificateListIsNotAssessed(t *testing.T) {
	stamp := tableDay(t)
	inv, ar := calInput("aws", "v1.31.0", stamp, nil, []string{certificatesStep + ": forbidden"})
	if rs := reasonsFor(buildCalendar(inv, ar), clockCertificates); len(rs) != 1 || !strings.Contains(rs[0], "refused") {
		t.Errorf("denied list: %v", rs)
	}
	inv, ar = calInput("aws", "v1.31.0", stamp, nil, nil)
	if rs := reasonsFor(buildCalendar(inv, ar), clockCertificates); len(rs) != 1 || !strings.Contains(rs[0], "not served, or was not looked at") {
		t.Errorf("never read: %v", rs)
	}
	inv, ar = calInput("aws", "v1.31.0", stamp, []string{certificatesStep}, nil)
	if rs := reasonsFor(buildCalendar(inv, ar), clockCertificates); len(rs) != 0 {
		t.Errorf("a read list was reported as not assessed: %v", rs)
	}
}

// The clocks this build never carries are named on every run, and a version that cannot be placed says why.
func TestCalendar_NamesWhatItCannotAssess(t *testing.T) {
	stamp := tableDay(t)
	for _, tc := range []struct{ provider, version, want string }{
		{"", "v1.31.0", "provider could not be read"},
		{"unknown", "v1.31.0", "provider could not be read"},
		{"onprem", "v1.31.0", `"onprem"`},
		{"kind", "v1.31.0", `"kind"`},
		{"aws", "garbage", "no recognisable major.minor"},
		// THE NAME, not the table key: a refusal sentence is read by the same person who reads the rows.
		{"aws", "v1.2.0", "carries no window for AWS 1.2"},
	} {
		inv, ar := calInput(tc.provider, tc.version, stamp, []string{certificatesStep}, nil)
		cal := buildCalendar(inv, ar)
		if rs := reasonsFor(cal, clockSupportWindow); len(rs) != 1 || !strings.Contains(rs[0], tc.want) {
			t.Errorf("%s/%s: %v", tc.provider, tc.version, rs)
		}
		clocks := map[string]bool{}
		for _, n := range cal.NotAssessed {
			clocks[n.Clock] = true
		}
		if !clocks["cloud-provider deprecations (instance types, add-on versions)"] || !clocks["operator support windows"] {
			t.Errorf("the two clocks this build never carries are not both listed: %v", cal.NotAssessed)
		}
	}
	// A reading with no stamp for the table claims nothing from it.
	inv, ar := calInput("aws", "v1.31.0", stamp, []string{certificatesStep}, nil)
	ar.Methodology.RunBasis = nil
	if rs := reasonsFor(buildCalendar(inv, ar), clockSupportWindow); len(rs) != 1 || !strings.Contains(rs[0], "does not record which version") {
		t.Errorf("missing stamp: %v", rs)
	}
}

// The report's provider enum is eks|aks|gke; the window table is keyed aws|azure|gcp. A document assembled with
// the display enum and no nodes is still placed — through one mapping — and the golden fixture (EKS 1.31) is the
// case that found this: its first calendar said `"eks"` had no table.
func TestCalendar_TheReportsProviderEnumIsMapped(t *testing.T) {
	stamp := tableDay(t)
	// The `cloud` column is the table KEY the enum must map to; `name` is what the row must print. They are
	// different strings and the row used to print the key — "ordinary support for Kubernetes 1.31 on aws" —
	// beside dates the rest of the document attributes to AWS.
	for _, tc := range []struct{ enum, version, cloud, name string }{
		{"eks", "v1.31.2-eks-1a2b3c4", "aws", "AWS"},
		{"aks", "1.32.4", "azure", "Azure"},
		{"gke", "v1.33.1-gke.100", "gcp", "Google Cloud"},
	} {
		inv, ar := calInput(tc.enum, tc.version, stamp.AddDate(0, 0, 1), []string{certificatesStep}, nil)
		cal := buildCalendar(inv, ar)
		if datasetRows(cal) == 0 {
			t.Errorf("%s: no dataset row; not assessed: %v", tc.enum, reasonsFor(cal, clockSupportWindow))
			continue
		}
		if !strings.Contains(cal.Rows[0].Observation, " on "+tc.name+" ") {
			t.Errorf("%s: row names %q, want the provider written as %q", tc.enum, cal.Rows[0].Observation, tc.name)
		}
		if strings.Contains(cal.Rows[0].Observation, " on "+tc.cloud+" ") {
			t.Errorf("%s: row prints the table key %q as a name: %q", tc.enum, tc.cloud, cal.Rows[0].Observation)
		}
	}
}
