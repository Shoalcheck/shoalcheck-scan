package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/kubeversions"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

func invAtVersion(version, region string, day time.Time) *collect.Inventory {
	inv := &collect.Inventory{Nodes: []corev1.Node{poolNode("n1", region, "m6i.large", "2", "8Gi")}}
	inv.Nodes[0].Spec.ProviderID = "aws:///eu-central-1a/i-0abc"
	inv.Meta.ServerVersion = version
	inv.Meta.StartedAt = day
	return inv
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// TestVersionSupport_TheFigureIsTheSURCHARGE. The failure this pins is claiming the whole
// control-plane bill as recoverable: an upgrade stops the extended-support charge and nothing else,
// so a figure near the total says the cluster becomes free.
func TestVersionSupport_TheFigureIsTheSURCHARGE(t *testing.T) {
	w, ok := kubeversions.For("aws", "1.31")
	if !ok {
		t.Fatal("the table has no aws/1.31 — this test's premise is gone")
	}
	inside := day(w.StandardEnds).AddDate(0, 0, 1)
	got := VersionPastStandardSupport{}.Evaluate(invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", inside), Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding one day past standard support, got %d", len(got))
	}
	hourly, ok := pricing.ExtendedSupportHourly("aws")
	if !ok {
		t.Fatal("this build has no AWS extended-support rate — the priced branch cannot be asserted")
	}
	want := hourly * versionHoursPerMonth
	if d := got[0].DollarImpactMonthly - want; d > 0.01 || d < -0.01 {
		t.Errorf("DollarImpactMonthly = %.2f, want the SURCHARGE %.2f", got[0].DollarImpactMonthly, want)
	}
}

// TestVersionSupport_SilentInsideOrdinarySupport — the healthy cluster says nothing.
func TestVersionSupport_SilentInsideOrdinarySupport(t *testing.T) {
	w, _ := kubeversions.For("aws", "1.31")
	if got := (VersionPastStandardSupport{}).Evaluate(
		invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", day(w.StandardEnds)), Options{}); len(got) != 0 {
		t.Errorf("on the last supported day itself the rule produced %d finding(s), want silence — the "+
			"published end date is inclusive and firing on it is a day early on every cluster", len(got))
	}
}

// TestVersionSupport_PastEverythingCarriesNoDollar. There is no surcharge left to stop, and inventing
// one would price a security exposure as though it were a bill.
func TestVersionSupport_PastEverythingCarriesNoDollar(t *testing.T) {
	w, _ := kubeversions.For("aws", "1.31")
	got := VersionPastStandardSupport{}.Evaluate(
		invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", day(w.ExtendedEnds).AddDate(0, 0, 1)), Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding past the extension, got %d", len(got))
	}
	if got[0].DollarImpactMonthly != 0 {
		t.Errorf("past the extension the figure is %.2f, want 0 — no surcharge remains to stop",
			got[0].DollarImpactMonthly)
	}
	if !strings.Contains(strings.ToLower(strings.Join(got[0].Evidence, " ")), "no surcharge left") {
		t.Error("the evidence does not say why there is no figure, so a reader sees a cost rule with no cost")
	}
}

// TestVersionSupport_UnknownIsSilence. An unrecognised provider, an unlisted minor, or an unparsable
// version string must produce nothing — not a reassurance.
func TestVersionSupport_UnknownIsSilence(t *testing.T) {
	for _, c := range []struct{ name, version, region string }{
		{"unlisted minor", "v1.99.0", "eu-central-1"},
		{"unparsable version", "unknown", "eu-central-1"},
		{"no version at all", "", "eu-central-1"},
	} {
		inv := invAtVersion(c.version, c.region, day("2026-08-31"))
		if got := (VersionPastStandardSupport{}).Evaluate(inv, Options{}); len(got) != 0 {
			t.Errorf("%s produced %d finding(s), want silence", c.name, len(got))
		}
	}
}

// TestVersionSupport_ReadsTheSnapshotClockNotTheWallClock. Re-rendering a collection from last year
// must produce last year's verdict; a rule that consulted time.Now() would rewrite history every run.
func TestVersionSupport_ReadsTheSnapshotClockNotTheWallClock(t *testing.T) {
	w, _ := kubeversions.For("aws", "1.31")
	early := day(w.Released).AddDate(0, 0, 30) // well inside ordinary support
	if got := (VersionPastStandardSupport{}).Evaluate(
		invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", early), Options{}); len(got) != 0 {
		t.Errorf("a snapshot taken during ordinary support produced %d finding(s) when replayed today; "+
			"the rule is reading the wall clock", len(got))
	}
}

// THE DATASET KEY IS NOT A NAME A CUSTOMER READS.
//
// The title on the reference document read "Kubernetes 1.31 is past aws's ordinary support window" — the
// support tables are keyed aws | azure | gcp (Cluster.Provider is eks | aks | gke, a different vocabulary),
// and the key was interpolated straight into prose. A title travels everywhere: the cover, the terminal,
// the app, the Markdown export, SARIF, a ticket. Every other cost sentence in the product says "AWS"
// because the renderer has cloudName; a rule cannot import the renderer, so the name belongs beside the
// table the key indexes.
func TestVersionSupport_NamesTheProviderAsAPersonWouldWriteIt(t *testing.T) {
	w, ok := kubeversions.For("aws", "1.31")
	if !ok {
		t.Fatal("the table has no aws/1.31 — this test's premise is gone")
	}
	got := VersionPastStandardSupport{}.Evaluate(
		invAtVersion("v1.31.2-eks-1a2b3c4", "eu-central-1", day(w.StandardEnds).AddDate(0, 0, 1)), Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]
	prose := []struct{ where, text string }{
		{"title", f.Title},
		{"description", f.Description},
	}
	for i, e := range f.Evidence {
		prose = append(prose, struct{ where, text string }{fmt.Sprintf("evidence[%d]", i), e})
	}
	for _, p := range prose {
		for _, key := range []string{"aws", "azure", "gcp"} {
			if strings.Contains(p.text, key) {
				t.Errorf("%s prints the dataset key %q as if it were a name: %q", p.where, key, p.text)
			}
		}
	}
	if !strings.Contains(f.Title, "AWS") {
		t.Errorf("the title does not name the provider at all: %q", f.Title)
	}
}
