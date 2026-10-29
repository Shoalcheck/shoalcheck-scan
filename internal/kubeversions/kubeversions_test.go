package kubeversions

import (
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// TestMinor_StripsEveryBuildSuffixAProviderAdds. A cluster never reports a bare "1.29": EKS appends
// its build, AKS and GKE their own. A parser that only handled the bare form would return unknown
// for every real managed cluster, which reads as "we have no data" while the data is right there.
func TestMinor_StripsEveryBuildSuffixAProviderAdds(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"v1.29.8-eks-a1b2c3", "1.29"},
		{"1.28.14+vmware.1", "1.28"},
		{"v1.30.2-gke.1587003", "1.30"},
		{"1.31.0", "1.31"},
		{"v1.32", "1.32"},
		{"", ""},
		{"v1", ""},
		{"vX.Y", ""},
		{"latest", ""},
	} {
		if got := Minor(c.in); got != c.want {
			t.Errorf("Minor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStatusOn_TheEndDateIsTheLASTSUPPORTEDDAY is the boundary that decides whether this fires a day
// early on every cluster that reads it on the line. A provider's published end date is inclusive.
func TestStatusOn_TheEndDateIsTheLASTSUPPORTEDDAY(t *testing.T) {
	w, ok := For("aws", "1.36")
	if !ok {
		t.Fatal("the table has no aws/1.36 — the fixture this test reasons about is gone")
	}
	end := day(w.StandardEnds)

	if got, _ := StatusOn("aws", "1.36", end); got != StatusSupported {
		t.Errorf("on the published end date itself the status is %q, want %q — the last supported day "+
			"is supported, and treating it as past fires a day early everywhere", got, StatusSupported)
	}
	if got, _ := StatusOn("aws", "1.36", end.AddDate(0, 0, 1)); got != StatusExtended {
		t.Errorf("the day after standard support the status is %q, want %q", got, StatusExtended)
	}
}

// TestStatusOn_GKEHasNoExtendedTierAndIsNotGivenOne. The source's field for GKE does not carry the
// meaning it carries for EKS and AKS, so the column is empty — and empty must resolve to
// unsupported, never to a fabricated extension window.
func TestStatusOn_GKEHasNoExtendedTierAndIsNotGivenOne(t *testing.T) {
	w, ok := For("gcp", "1.36")
	if !ok {
		t.Fatal("the table has no gcp/1.36")
	}
	if w.ExtendedEnds != "" {
		t.Errorf("gcp/1.36 carries ExtendedEnds=%q — GKE's source field does not mean that and must "+
			"not be emitted", w.ExtendedEnds)
	}
	got, _ := StatusOn("gcp", "1.36", day(w.StandardEnds).AddDate(0, 0, 1))
	if got != StatusUnsupported {
		t.Errorf("past standard support with no published extension the status is %q, want %q", got, StatusUnsupported)
	}
}

// TestStatusOn_UnknownIsNotSupported. The whole honesty policy in one assertion: a version the table
// cannot place must not read as fine.
func TestStatusOn_UnknownIsNotSupported(t *testing.T) {
	for _, c := range []struct{ provider, minor string }{
		{"aws", "1.99"},
		{"aws", ""},
		{"oracle", "1.30"},
		{"", "1.30"},
	} {
		if got, _ := StatusOn(c.provider, c.minor, day("2026-08-31")); got != StatusUnknown {
			t.Errorf("StatusOn(%q,%q) = %q, want %q — a version we cannot place is not a version we "+
				"have cleared", c.provider, c.minor, got, StatusUnknown)
		}
	}
}

// TestTable_CoversEveryProviderTheEngineCanDetect. A provider the collector can identify but the
// table cannot answer for produces silence that looks like a clean bill.
func TestTable_CoversEveryProviderTheEngineCanDetect(t *testing.T) {
	for _, p := range []string{"aws", "azure", "gcp"} {
		if len(windows[p]) < 5 {
			t.Errorf("provider %q has %d window(s); the generator refuses to emit fewer than 5, so this "+
				"table was hand-edited or the generator regressed", p, len(windows[p]))
		}
	}
}

// TestTable_IsNotStale. A support date does not drift, it passes — so a stale table does not make a
// number slightly wrong, it makes a finding fail to fire while the report says nothing at all.
func TestTable_IsNotStale(t *testing.T) {
	fetched, err := time.Parse("2006-01-02", asOf)
	if err != nil {
		t.Fatalf("asOf = %q is not YYYY-MM-DD: %v", asOf, err)
	}
	const maxAge = 120 * 24 * time.Hour
	if age := time.Since(fetched); age > maxAge {
		t.Errorf("the version table was fetched %s ago (%s), past the %s limit. Kubernetes ships about "+
			"three minors a year and providers retire them continuously; re-run "+
			"scripts/update-kubeversions.py --as-of $(date +%%F).",
			age.Round(24*time.Hour), asOf, maxAge)
	}
}
