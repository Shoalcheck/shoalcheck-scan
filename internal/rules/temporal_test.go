package rules

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// temporal_test.go — §6b's boundaries, each asserted, and each with what stops it being vacuous.
//
// THE THIRD STATE IS WHAT THIS FAMILY IS FOR. "Not assessed" is not "assessed and clean", and every rule
// here has to be silent on nil Temporal for a reason distinct from being silent on a clean cluster. So
// every silence test is paired with the fixture that DOES fire, which is the only arrangement that
// separates a working rule from one that never speaks.

func temporalInv() *collect.Inventory {
	lim := corev1.ResourceList{corev1.ResourceCPU: qty("500m")}
	return &collect.Inventory{
		Meta: collect.Meta{Collected: []string{"pods"}, StartedAt: fixedReading},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api-0"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{
				{Name: "api", Resources: corev1.ResourceRequirements{Limits: lim}},
				{Name: "sidecar"},
			}},
		}},
	}
}

func temporalOpts(t *prom.Temporal) Options { return Options{IncludeSystem: true, Temporal: t} }

func fullTemporal() *prom.Temporal {
	return &prom.Temporal{
		Window:       prom.TemporalWindow,
		AlertsSeries: true,
		Alerts: []prom.FiringAlert{
			{Name: "KubePodCrashLooping", Severity: "warning", Namespace: "payments", State: "firing", Count: 3},
			{Name: "TargetDown", Severity: "critical", State: "firing", Count: 1},
		},
		Throttling: map[string]prom.Throttling{
			"payments/api-0/api": {Namespace: "payments", Pod: "api-0", Container: "api",
				Ratio: 0.62, Periods: 40000},
		},
		Scrape: prom.ScrapeHealth{Up: 41, Down: 2, DownJobs: map[string]int{"kubelet": 2}, SeriesExists: true},
	}
}

func allTemporalFindings(inv *collect.Inventory, t *prom.Temporal) []types.Finding {
	o := temporalOpts(t)
	var out []types.Finding
	out = append(out, (AlertsFiring{}).Evaluate(inv, o)...)
	out = append(out, (ContainerThrottled{}).Evaluate(inv, o)...)
	out = append(out, (ScrapeTargetsDown{}).Evaluate(inv, o)...)
	return out
}

// NOT ASSESSED IS NOT CLEAN. Nil Temporal is the state when no source resolved AND when one resolved but
// could not be proven to be this cluster's — the B-145 state. Every rule here is silent on it.
//
// Non-vacuity: the same inventory with a populated Temporal produces all three findings, so a family that
// returned nil unconditionally fails the second half.
func TestTemporal_NilIsSilenceAndAPopulatedSourceIsNot(t *testing.T) {
	if got := allTemporalFindings(temporalInv(), nil); len(got) != 0 {
		t.Fatalf("a nil Temporal produced %d finding(s): %s", len(got), got[0].Title)
	}
	if got := allTemporalFindings(temporalInv(), fullTemporal()); len(got) != 3 {
		t.Fatalf("a populated Temporal produced %d finding(s), want 3", len(got))
	}
}

// AN UNPROVEN SOURCE PRODUCES NIL AT THE FETCH LAYER, which is where the gate belongs: a rule that had to
// remember to check the tier would eventually be written by someone who did not.
func TestTemporal_AnUnprovenSourceNeverReachesTheRules(t *testing.T) {
	for _, p := range []prom.Provenance{
		{Tier: prom.TierUnproven, Method: "exclusivity", Detail: "source holds 3.1x this cluster's pods"},
		{Tier: prom.TierNone},
		{},
	} {
		got, err := prom.FetchTemporal(context.Background(), nil, p)
		if err != nil {
			t.Fatalf("FetchTemporal: %v", err)
		}
		if got != nil {
			t.Errorf("tier %q produced a Temporal bundle", p.Tier)
		}
	}
}

// §6b.3 — NEVER INFER CAUSE, and never assert an alert is correct. The banned list is the sentence set that
// would be easy to write and false.
//
// Non-vacuity: fatal when the fixture produces no findings.
func TestTemporal_ClaimsNoCauseAndNoCalibration(t *testing.T) {
	banned := []string{
		"caused", "causing", "is slow", "users are", "user-impacting", "outage", "will fail",
		"because of", "resulting in", "leads to", "proves", "confirms that", "your alert is",
		"correctly configured", "is broken", "is unhealthy", "is down because",
	}
	got := allTemporalFindings(temporalInv(), fullTemporal())
	if len(got) == 0 {
		t.Fatal("the fixture produced no findings, so this test would pass over an empty corpus")
	}
	for _, f := range got {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters}, f.Evidence...), "\n"))
		for _, b := range banned {
			if strings.Contains(blob, b) {
				t.Errorf("%s says %q — a series is a fact and its consequence is not:\n%s", f.RuleID, b, blob)
			}
		}
	}
}

// A WINDOW IS PART OF THE CLAIM. "Throttled 43%" without "over 7 days" is not a claim.
func TestTemporal_EveryFindingNamesItsWindowAndItsSource(t *testing.T) {
	for _, f := range allTemporalFindings(temporalInv(), fullTemporal()) {
		blob := strings.Join(f.Evidence, "\n")
		if !strings.Contains(blob, "Prometheus") {
			t.Errorf("%s does not say the claim came from the cluster's own metrics source", f.RuleID)
		}
	}
	// The two rules measuring over a window must name it; scrape health is an instant and says THAT.
	for _, f := range allTemporalFindings(temporalInv(), fullTemporal()) {
		blob := strings.Join(f.Evidence, "\n")
		switch f.RuleID {
		case "k8s.observed.scrape-targets-down":
			if !strings.Contains(blob, "instant") {
				t.Error("scrape health is read as an instant and the finding does not say so")
			}
		default:
			if !strings.Contains(blob, "7-day window") {
				t.Errorf("%s does not carry the window it measured over:\n%s", f.RuleID, blob)
			}
		}
	}
}

// F-4 — A FIRING ALERT MEANS THE EXPRESSION EVALUATES TRUE. The finding has to say so, because the natural
// reading of "3 alerts firing" is "3 things are wrong".
func TestAlertsFiring_SaysWhatFiringActuallyMeans(t *testing.T) {
	got := (AlertsFiring{}).Evaluate(temporalInv(), temporalOpts(fullTemporal()))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(blob, "EXPRESSION EVALUATES TRUE") {
		t.Error("the finding does not distinguish a firing expression from a real situation")
	}
	// The customer's strings are quoted as data and are NOT in the Title or WhyItMatters.
	for _, s := range []string{"KubePodCrashLooping", "TargetDown"} {
		if !strings.Contains(blob, s) {
			t.Errorf("the alert name %q does not reach the evidence", s)
		}
		if strings.Contains(got[0].Title, s) || strings.Contains(got[0].WhyItMatters, s) {
			t.Errorf("the customer-authored string %q is interpolated into generated prose", s)
		}
	}
}

// THROTTLING WITHOUT A CPU LIMIT IS A CONTRADICTION IN OUR OWN READING, not a finding. The CFS quota is
// what throttles, so a container with no limit cannot be throttled by one.
//
// Non-vacuity: the limited container in the SAME fixture does fire, so a rule that skipped everything
// fails the first assertion.
func TestContainerThrottled_AContainerWithNoLimitIsDisclosedNotReported(t *testing.T) {
	inv := temporalInv()
	tm := fullTemporal()
	tm.Throttling["payments/api-0/sidecar"] = prom.Throttling{
		Namespace: "payments", Pod: "api-0", Container: "sidecar", Ratio: 0.9, Periods: 40000}
	got := (ContainerThrottled{}).Evaluate(inv, temporalOpts(tm))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(blob, "declare no CPU limit") {
		t.Error("a throttling series for a container with no limit was not disclosed")
	}
	if strings.Contains(blob, "container sidecar: throttled") {
		t.Error("a container with no CPU limit was reported as throttled against a limit it does not have")
	}
	if !strings.Contains(blob, "container api: throttled") {
		t.Error("the limited container did not fire, so the exclusion above proves nothing")
	}
}

// A CONTAINER ABSENT FROM THE SERIES IS UNKNOWN, NEVER UNTHROTTLED — and a ratio over too few periods is
// noise, not a fact. Both floors are asserted, and both directions of each.
func TestContainerThrottled_AbsenceAndThinDataAreBothSilence(t *testing.T) {
	inv := temporalInv()
	t.Run("absent from the series", func(t *testing.T) {
		tm := fullTemporal()
		tm.Throttling = map[string]prom.Throttling{}
		assertSilent(t, (ContainerThrottled{}).Evaluate(inv, temporalOpts(tm)))
	})
	t.Run("too few periods", func(t *testing.T) {
		tm := fullTemporal()
		tm.Throttling["payments/api-0/api"] = prom.Throttling{
			Namespace: "payments", Pod: "api-0", Container: "api", Ratio: 1.0, Periods: 3}
		assertSilent(t, (ContainerThrottled{}).Evaluate(inv, temporalOpts(tm)))
	})
	t.Run("below the sustained floor", func(t *testing.T) {
		tm := fullTemporal()
		tm.Throttling["payments/api-0/api"] = prom.Throttling{
			Namespace: "payments", Pod: "api-0", Container: "api", Ratio: 0.05, Periods: 40000}
		assertSilent(t, (ContainerThrottled{}).Evaluate(inv, temporalOpts(tm)))
	})
	t.Run("and the fixture at full strength fires", func(t *testing.T) {
		if got := (ContainerThrottled{}).Evaluate(inv, temporalOpts(fullTemporal())); len(got) != 1 {
			t.Fatal("the unmodified fixture produces no finding, so the three silences above prove nothing")
		}
	})
}

// A DENIED POD LIST IS SILENCE: the finding names pods, and it reads the CPU limit off the spec.
func TestContainerThrottled_ADeniedPodListIsSilence(t *testing.T) {
	inv := temporalInv()
	inv.Meta.Collected = nil
	inv.Meta.Denied = []string{"pods: forbidden"}
	assertSilent(t, (ContainerThrottled{}).Evaluate(inv, temporalOpts(fullTemporal())))
}

// up{} NOT BEING EXPORTED AND NO TARGET BEING DOWN PRODUCE THE IDENTICAL EMPTY RESULT. SeriesExists is what
// separates them, and without it an unexported series renders as a clean scrape surface.
func TestScrapeTargetsDown_AnUnexportedSeriesIsNotACleanCluster(t *testing.T) {
	inv := temporalInv()
	t.Run("series absent", func(t *testing.T) {
		tm := fullTemporal()
		tm.Scrape = prom.ScrapeHealth{SeriesExists: false, DownJobs: map[string]int{}}
		assertSilent(t, (ScrapeTargetsDown{}).Evaluate(inv, temporalOpts(tm)))
	})
	t.Run("series present, nothing down", func(t *testing.T) {
		tm := fullTemporal()
		tm.Scrape = prom.ScrapeHealth{Up: 43, Down: 0, DownJobs: map[string]int{}, SeriesExists: true}
		assertSilent(t, (ScrapeTargetsDown{}).Evaluate(inv, temporalOpts(tm)))
	})
	t.Run("series present, targets down", func(t *testing.T) {
		got := (ScrapeTargetsDown{}).Evaluate(inv, temporalOpts(fullTemporal()))
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(strings.Join(got[0].Evidence, "\n"), `job="kubelet"`) {
			t.Error("the failing job is not named")
		}
	})
}

// A FAILED SCRAPE AND AN UNHEALTHY SERVICE ARE OPPOSITE CONCLUSIONS when an exporter dies beside a working
// process. The finding must scope itself to the monitoring stack.
func TestScrapeTargetsDown_IsAboutTheStackNotTheWorkloads(t *testing.T) {
	got := (ScrapeTargetsDown{}).Evaluate(temporalInv(), temporalOpts(fullTemporal()))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "NOT ABOUT THE WORKLOADS") {
		t.Error("the finding does not scope itself to the monitoring stack")
	}
	if len(got[0].AffectedResources) != 0 {
		t.Errorf("the finding names %d resource(s); a failing scrape target is not a named object in this "+
			"reading and pointing at one would assert the workload is the problem",
			len(got[0].AffectedResources))
	}
}

func TestTemporal_NeverCarriesDollars(t *testing.T) {
	for _, f := range allTemporalFindings(temporalInv(), fullTemporal()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("%s carries $%.2f", f.RuleID, f.DollarImpactMonthly)
		}
	}
}

// The family is registered — a rule built and not registered produces nothing, silently.
func TestTemporal_EveryRuleInThisFileIsRegistered(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	reg := map[string]bool{}
	for _, r := range All() {
		reg[r.ID()] = true
	}
	for _, id := range temporalRuleIDs() {
		if !reg[id] {
			t.Errorf("%s is defined and not in All(), so it can never fire", id)
		}
	}
}
