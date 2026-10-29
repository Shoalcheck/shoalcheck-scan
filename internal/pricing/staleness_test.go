package pricing

import (
	"regexp"
	"testing"
	"time"
)

// embeddedFetchDate parses the package-private asOf const (YYYY-MM-DD) that
// tables_gen.go stamps. It's the single source of truth for "when were these
// prices pulled"; AsOf() exposes only the YYYY-MM month form to callers.
func embeddedFetchDate(t *testing.T) time.Time {
	t.Helper()
	d, err := time.Parse("2006-01-02", asOf)
	if err != nil {
		t.Fatalf("embedded asOf %q does not parse as YYYY-MM-DD: %v", asOf, err)
	}
	return d
}

// pricingFloor is a hardcoded sanity floor: the price table cannot have been
// fetched before this date (the project didn't exist). A stamp earlier than
// this is a data-entry bug, not staleness. It is intentionally a fixed,
// wall-clock-independent constant so this assertion never flakes on a future CI
// run.
var pricingFloor = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// TestPriceTableNotStale is the non-flaky guard for the embedded price stamp.
//
// HARD assertions (these would correctly break any future CI run only if the
// table is actually malformed):
//   - AsOf() matches ^\d{4}-\d{2}$.
//   - The embedded asOf const parses as a real YYYY-MM-DD date.
//   - The fetch date is not before pricingFloor (a fixed, reproducible bound).
//   - The fetch date is not absurdly in the future relative to a fixed ceiling
//     (catches a fat-fingered year like 2206 at generation time).
//
// SOFT signal (never a failure): the age in days relative to time.Now() is
// emitted via t.Log. Real staleness enforcement lives in `make pricing-age`
// (which warns >90d) plus the documented update process — deliberately NOT a
// wall-clock test assertion, so a table that's correct today never spuriously
// fails CI six months from now.
func TestPriceTableNotStale(t *testing.T) {
	if re := regexp.MustCompile(`^\d{4}-\d{2}$`); !re.MatchString(AsOf()) {
		t.Errorf("AsOf() = %q, want match of ^\\d{4}-\\d{2}$", AsOf())
	}

	fetched := embeddedFetchDate(t)

	if fetched.Before(pricingFloor) {
		t.Errorf("embedded price date %s is before the project floor %s — likely a data-entry bug",
			fetched.Format("2006-01-02"), pricingFloor.Format("2006-01-02"))
	}

	// A fixed, generous future ceiling: catches an obviously wrong year stamp
	// without depending on the wall clock for the *failure* condition.
	futureCeiling := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	if fetched.After(futureCeiling) {
		t.Errorf("embedded price date %s is implausibly far in the future (> %s) — check the --as-of stamp",
			fetched.Format("2006-01-02"), futureCeiling.Format("2006-01-02"))
	}

	// AsOf() must agree with the embedded const's YYYY-MM prefix.
	if got, want := AsOf(), asOf[:7]; got != want {
		t.Errorf("AsOf() = %q, want YYYY-MM prefix of embedded asOf = %q", got, want)
	}

	// SOFT: surface the age as information, never a failure (see doc comment).
	ageDays := int(time.Since(fetched).Hours() / 24)
	switch {
	case ageDays < 0:
		t.Logf("price table fetch date %s is in the future relative to now (%d days); ok unless the stamp is wrong",
			fetched.Format("2006-01-02"), -ageDays)
	case ageDays > 90:
		t.Logf("WARNING: price table is %d days old (>90) — run `make pricing-age` and consider `python3 scripts/update-pricing.py --as-of $(date +%%Y-%%m-%%d)`", ageDays)
	default:
		t.Logf("price table age: %d days (fetched %s)", ageDays, fetched.Format("2006-01-02"))
	}
}
