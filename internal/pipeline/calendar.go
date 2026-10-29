package pipeline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// cloudForReportProvider maps the report's provider enum (collect.providerFrom) to kubeversions' cloud keys.
// Only the three clouds with a window table appear; kind, onprem and unknown map to "" on purpose.
var cloudForReportProvider = map[string]string{
	"eks": "aws", "aks": "azure", "gke": "gcp",
	"aws": "aws", "azure": "azure", "gcp": "gcp",
}

// calendar.go — "things with a clock": the dated obligations this run could read, and the clocks it could not.
//
// ASSEMBLED HERE, AFTER THE REPORT, for the same reason pillars and finding bases are: internal/report may not
// import internal/rules or a dataset package (scripts/depcheck.sh rule 1), so the join between the inventory,
// the findings and the support-window table has to happen on the pipeline side and travel on the schema.
//
// TWO SOURCES OF DATE AND NOTHING ELSE (spec 2026-08-28 §4.1). An OBJECT row comes from a finding whose analyzer
// read a date off the object it is about — Finding.Deadline, set today by cert-manager expiry. A DATASET row
// comes from placing the cluster's Kubernetes minor in the provider's published support window, and it names
// the table's version and provenance because an embedded table and a live one age differently. A row is never
// inferred: no "approximately", no date from an image tag.
//
// THE COUNT NAMES ITS SCOPE. "Two dated obligations" is a claim about our coverage as much as about the cluster,
// so every clock this run could not read is listed beside the rows with its reason — a refused list, a version
// that cannot be placed, a table past the age this check will claim from, and the two clocks this build never
// carries (provider deprecations, operator support windows). A stale table degrades to "not assessed" with its
// stamp in the sentence, never to "no deadlines found".
//
// THE SNAPSHOT'S CLOCK, NEVER THE WALL CLOCK. Whether a date has passed and whether the table is too old are
// both measured at inv.Meta.StartedAt, so re-rendering yesterday's reading today does not move a row across
// the line or withhold a table that was fresh when the reading was taken.

// calendarClaimWindowDays is how long after its stamp the support-window table is trusted to place a version.
// Kubernetes ships three minors a year and providers publish end-of-support dates a year ahead, so a table
// half a year old has not missed a boundary that matters; past that, the honest reading is "not assessed",
// because an absent finding carries no stamp for a reader to distrust. Named in the sentence it produces.
const calendarClaimWindowDays = 180

const (
	calendarDatasetKubeversions = "kubeversions"
	calendarDeprecatedAPIRule   = "k8s.upgrade.deprecated-api-served"
	// certificatesStep is exactly what the collector records for cert-manager's Certificate list — see
	// analyzers.listSucceeded, which reads the same key.
	certificatesStep = collect.CRStepPrefix + "certificates.cert-manager.io"

	clockCertificates  = "certificate expiry"
	clockSupportWindow = "Kubernetes support window"
)

// buildCalendar assembles the block from the inventory and the assembled report. It never returns nil: a run
// that could read no clock still records which clocks it could not, which is a different document from one
// that recorded no calendar at all.
func buildCalendar(inv *collect.Inventory, ar *types.AuditReport) *types.Calendar {
	cal := &types.Calendar{Rows: []types.CalendarRow{}}
	if inv == nil {
		inv = &collect.Inventory{}
	}
	day, hasDay := snapshotDay(inv, ar)

	// Object rows: one per finding that read a date off its object.
	for _, f := range ar.Findings {
		if f.Deadline == nil || len(f.AffectedResources) == 0 {
			continue
		}
		obj := f.AffectedResources[0]
		name := obj.Name
		if obj.Namespace != "" {
			name = obj.Namespace + "/" + obj.Name
		}
		row := types.CalendarRow{
			Date:        f.Deadline.Date,
			Kind:        types.CalendarRowObject,
			Object:      &types.ResourceRef{Kind: obj.Kind, Namespace: obj.Namespace, Name: obj.Name},
			Field:       f.Deadline.Field,
			Observation: fmt.Sprintf("%s %s reports %s = %s", obj.Kind, name, f.Deadline.Field, f.Deadline.Date),
			FindingIDs:  []string{f.ID},
		}
		row.Passed = hasDay && datePassed(row.Date, day)
		cal.Rows = append(cal.Rows, row)
	}
	if reason := certificatesNotAssessed(inv); reason != "" {
		cal.NotAssessed = append(cal.NotAssessed, types.ClockNotAssessed{Clock: clockCertificates, Reason: reason})
	}

	// Dataset rows: the cluster's minor in its provider's window.
	if rows, reason := supportWindowRows(inv, ar, day, hasDay); reason != "" {
		cal.NotAssessed = append(cal.NotAssessed, types.ClockNotAssessed{Clock: clockSupportWindow, Reason: reason})
	} else {
		cal.Rows = append(cal.Rows, rows...)
	}

	// The two clocks this build never carries. Listed on every run, because their absence from the rows would
	// otherwise read as "none".
	cal.NotAssessed = append(cal.NotAssessed,
		types.ClockNotAssessed{
			Clock:  "cloud-provider deprecations (instance types, add-on versions)",
			Reason: "no dataset: this build carries no schedule of provider retirements, so none is claimed",
		},
		types.ClockNotAssessed{
			Clock:  "operator support windows",
			Reason: "an image tag is a string the operator chose, not a version, so no date is derived from one",
		},
	)

	sort.Slice(cal.Rows, func(i, j int) bool {
		a, b := cal.Rows[i], cal.Rows[j]
		if a.Date != b.Date {
			return a.Date < b.Date
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Observation < b.Observation
	})
	return cal
}

// snapshotDay is the day the reading was taken, truncated to UTC midnight: the collector's StartedAt, or the
// report's GeneratedAt for a document assembled without one. false when neither is set — then nothing can be
// said about passing or age, and the callers say so rather than assuming today.
func snapshotDay(inv *collect.Inventory, ar *types.AuditReport) (time.Time, bool) {
	at := inv.Meta.StartedAt
	if at.IsZero() {
		at = ar.GeneratedAt
	}
	if at.IsZero() {
		return time.Time{}, false
	}
	return at.UTC().Truncate(24 * time.Hour), true
}

// datePassed is true when the row's date is strictly before the snapshot's day. A provider's published end date
// is the last day of support, so a cluster is only past it from the following day — the same inclusive reading
// kubeversions.StatusOn uses, and getting it backwards would mark every boundary-day reading as passed.
func datePassed(date string, day time.Time) bool {
	d, ok := types.ParseCalendarDay(date)
	return ok && day.After(d)
}

// certificatesNotAssessed says why no certificate date could be read, or "" when the list was read and any date
// on it is in the rows already.
func certificatesNotAssessed(inv *collect.Inventory) string {
	for _, c := range inv.Meta.Collected {
		if c == certificatesStep {
			return ""
		}
	}
	for _, d := range inv.Meta.Denied {
		if d == certificatesStep || strings.HasPrefix(d, certificatesStep+":") {
			return "the certificates list (cert-manager.io) was refused by the cluster, so no notAfter was read"
		}
	}
	return "no Certificate list was read in this run — cert-manager's resource was not served, or was not looked at"
}

// supportWindowRows places the cluster's minor in its provider's window and returns the dated rows, or the
// reason none can be claimed. Exactly one of the two is non-empty.
func supportWindowRows(inv *collect.Inventory, ar *types.AuditReport, day time.Time, hasDay bool) ([]types.CalendarRow, string) {
	// The window table is keyed by cloud (aws|azure|gcp), which is what the rules' detector returns; the
	// report's Cluster.Provider is the display enum (eks|aks|gke|kind|onprem|unknown) and is the fallback for a
	// document assembled without nodes, mapped through the table below so the two vocabularies cannot drift.
	provider := rules.CloudProvider(inv.Nodes)
	if provider == "" {
		provider = cloudForReportProvider[ar.Cluster.Provider]
	}
	switch provider {
	case "aws", "azure", "gcp":
	case "":
		if rp := ar.Cluster.Provider; rp != "" && rp != "unknown" {
			return nil, fmt.Sprintf("the cluster's provider is %q, for which this build carries no support-window table", rp)
		}
		return nil, "the cluster's provider could not be read from the nodes, so its version cannot be placed in a published support window"
	}
	serverVersion := inv.Meta.ServerVersion
	if serverVersion == "" {
		serverVersion = ar.Cluster.KubernetesVersion
	}
	minor := kubeversions.Minor(serverVersion)
	if minor == "" {
		return nil, fmt.Sprintf("the API server's version string %q carries no recognisable major.minor, so it cannot be placed in a support window", serverVersion)
	}
	var stamp types.DataVersion
	if rb := ar.Methodology.RunBasis; rb != nil {
		stamp = rb.DataVersions[calendarDatasetKubeversions]
	}
	if stamp.Version == "" {
		return nil, "this reading does not record which version of the support-window table it used, so no date from it is claimed"
	}
	tableDay, ok := types.ParseCalendarDay(stamp.Version)
	if !ok {
		return nil, fmt.Sprintf("the support-window table's stamp %q is not a date, so its age cannot be measured and no date from it is claimed", stamp.Version)
	}
	if !hasDay {
		return nil, "this reading carries no timestamp to measure the support-window table's age against, so no date from it is claimed"
	}
	if age := day.Sub(tableDay); age > calendarClaimWindowDays*24*time.Hour {
		return nil, fmt.Sprintf("our support-window table is dated %s and is older than the %d-day window this check is willing to claim from, measured at the reading's own time (%s)",
			stamp.Version, calendarClaimWindowDays, day.Format("2006-01-02"))
	}
	window, ok := kubeversions.For(provider, minor)
	if !ok {
		return nil, fmt.Sprintf("the support-window table (version %s) carries no window for %s %s", stamp.Version, kubeversions.ProviderName(provider), minor)
	}
	if window.StandardEnds == "" {
		return nil, fmt.Sprintf("the support-window table (version %s) has no end of ordinary support for %s %s, and an unknown boundary is not a date", stamp.Version, kubeversions.ProviderName(provider), minor)
	}

	// The API-removal finding(s), when the report has them: the upgrade the ordinary-support date calls for is
	// where they apply, and the row links them so the reader lands on the list.
	var apiIDs []string
	for _, f := range ar.Findings {
		if f.RuleID == calendarDeprecatedAPIRule {
			apiIDs = append(apiIDs, f.ID)
		}
	}
	sort.Strings(apiIDs)

	dataset := func(date, observation string, ids []string) types.CalendarRow {
		return types.CalendarRow{
			Date: date, Kind: types.CalendarRowDataset,
			Dataset: calendarDatasetKubeversions, DatasetVersion: stamp.Version, DatasetSource: stamp.Source,
			Observation: observation, FindingIDs: ids,
			Passed: datePassed(date, day),
		}
	}
	tense := func(date string) string {
		if datePassed(date, day) {
			return "ended"
		}
		return "ends"
	}
	// THE NAME, NOT THE TABLE KEY. These rows are sentences a reader reads on a calendar; the key that
	// indexes the support table is aws | azure | gcp, and printing it here read as "on aws" beside dates
	// the rest of the document attributes to "AWS".
	name := kubeversions.ProviderName(provider)
	std := fmt.Sprintf("ordinary support for Kubernetes %s on %s %s %s", minor, name, tense(window.StandardEnds), window.StandardEnds)
	if n := len(apiIDs); n > 0 {
		std += fmt.Sprintf("; the upgrade this date calls for is where the report's %d API-removal finding%s appl%s", n, plural(n), map[bool]string{true: "ies", false: "y"}[n == 1])
	}
	rows := []types.CalendarRow{dataset(window.StandardEnds, std, apiIDs)}
	if window.ExtendedEnds != "" {
		rows = append(rows, dataset(window.ExtendedEnds,
			fmt.Sprintf("the paid extension for Kubernetes %s on %s %s %s", minor, name, tense(window.ExtendedEnds), window.ExtendedEnds), nil))
	}
	return rows, ""
}
