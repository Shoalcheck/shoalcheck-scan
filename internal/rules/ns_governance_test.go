package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// govCollected is the Meta state for a healthy run where the governance
// object kinds were actually listed — required for the rule to assert their
// absence (see the denial guard).
func govCollected() collect.Meta {
	return collect.Meta{Collected: []string{"resourcequotas", "limitranges"}}
}

func TestNoResourceGovernance(t *testing.T) {
	inv := &collect.Inventory{
		Meta: govCollected(),
		Deployments: []appsv1.Deployment{
			deploy("app", "api", 2, nil),
			deploy("app", "worker", 2, nil),
			deploy("solo", "one", 1, nil), // exactly 1 workload → below the >1 bar
			deploy("quota", "a", 1, nil),
			deploy("quota", "b", 1, nil), // 2 workloads but has a ResourceQuota
			deploy("lr", "c", 1, nil),
			deploy("lr", "d", 1, nil), // 2 workloads but has a LimitRange
		},
		ResourceQuotas: []corev1.ResourceQuota{
			{ObjectMeta: metav1.ObjectMeta{Name: "rq", Namespace: "quota"}},
		},
		LimitRanges: []corev1.LimitRange{
			{ObjectMeta: metav1.ObjectMeta{Name: "limits", Namespace: "lr"}},
		},
	}
	fs := NoResourceGovernance{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (app only), got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.namespace.no-resource-governance" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0].Kind != "Namespace" || f.AffectedResources[0].Name != "app" {
		t.Errorf("affected = %+v, want single Namespace/app ref", f.AffectedResources)
	}

	// Honest calibration: object-absence is certain but governance-absence is
	// not, so confidence is held below 1.0; severity is the resolved Low.
	if f.Confidence >= 1.0 || f.Confidence < 0.5 {
		t.Errorf("confidence must reflect object-absence (not problem-certainty), got %v", f.Confidence)
	}
	if f.Severity != types.SeverityLow {
		t.Errorf("severity = %v, want Low (config hygiene)", f.Severity)
	}

	ev := strings.Join(f.Evidence, " ")
	// Evidence must be precise about WHAT was counted and that absence is observed.
	if !strings.Contains(ev, "long-running workloads") ||
		!strings.Contains(ev, "ResourceQuota") ||
		!strings.Contains(ev, "LimitRange") {
		t.Errorf("evidence must scope the count and list both absent object kinds: %v", f.Evidence)
	}
	if !strings.Contains(strings.ToLower(ev), "jobs/cronjobs") && !strings.Contains(strings.ToLower(ev), "cronjob") {
		t.Errorf("evidence must note Jobs/CronJobs are excluded from the count: %v", f.Evidence)
	}
	// Admission/policy-engine caveat must ride along (false-positive guard).
	all := f.Description + " " + ev
	if !strings.Contains(all, "Kyverno") && !strings.Contains(all, "webhook") && !strings.Contains(strings.ToLower(all), "admission") {
		t.Errorf("must caveat admission/policy-engine-injected governance: %q / %v", f.Description, f.Evidence)
	}
	// The bare containers (no requests) must be named since none were pinned.
	if !strings.Contains(ev, "api/main") || !strings.Contains(ev, "worker/main") {
		t.Errorf("evidence must name the containers that omit requests: %v", f.Evidence)
	}

	if !strings.Contains(f.RemediationYAML, "kind: LimitRange") ||
		!strings.Contains(f.RemediationYAML, "namespace: app") ||
		!strings.Contains(f.RemediationYAML, "100m") ||
		!strings.Contains(f.RemediationYAML, "starting point") {
		t.Errorf("remediation must be a conservative LimitRange flagged as a starting point:\n%s", f.RemediationYAML)
	}
}

// A namespace where every container already pins requests must NOT carry the
// "containers get none injected / runaway starves everything" causal claim —
// the rule only states what it observed (overclaim fix).
func TestNoResourceGovernance_FullyPinnedRequestsNoCausalClaim(t *testing.T) {
	inv := &collect.Inventory{
		Meta: govCollected(),
		Deployments: []appsv1.Deployment{
			deploy("payments", "api", 2, withFullSpec),
			deploy("payments", "ledger", 2, withFullSpec),
		},
	}
	fs := NoResourceGovernance{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for ungoverned namespace, got %d", len(fs))
	}
	d := fs[0].Description
	// Must NOT assert containers omit requests / one runaway starves everything.
	if strings.Contains(d, "starve everything") || strings.Contains(d, "get none injected") {
		t.Errorf("must not make the unverified starvation/no-injection claim when every container pins requests:\n%s", d)
	}
	// Should affirmatively reflect that requests ARE set.
	if !strings.Contains(d, "already sets explicit requests") {
		t.Errorf("description should acknowledge requests are present:\n%s", d)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "all observed containers") {
		t.Errorf("evidence should state all containers declare requests: %v", fs[0].Evidence)
	}
}

// Denial guard: if the governance object kinds were not collected (RBAC-denied
// / timed out), the rule must not assert their absence.
func TestNoResourceGovernance_DeniedKindsSkip(t *testing.T) {
	base := []appsv1.Deployment{
		deploy("app", "api", 2, nil),
		deploy("app", "worker", 2, nil),
	}
	cases := []struct {
		name      string
		collected []string
	}{
		{"nothing collected", nil},
		{"only resourcequotas", []string{"resourcequotas"}},
		{"only limitranges", []string{"limitranges"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := &collect.Inventory{
				Meta:        collect.Meta{Collected: tc.collected},
				Deployments: base,
			}
			if got := len(NoResourceGovernance{}.Evaluate(inv, Options{})); got != 0 {
				t.Fatalf("must skip when a governance kind is uncollected, got %d findings", got)
			}
		})
	}
	// Sanity: both collected → fires.
	inv := &collect.Inventory{Meta: govCollected(), Deployments: base}
	if got := len(NoResourceGovernance{}.Evaluate(inv, Options{})); got != 1 {
		t.Fatalf("with both kinds collected want 1 finding, got %d", got)
	}
}

func TestNoResourceGovernance_SystemNamespaces(t *testing.T) {
	inv := &collect.Inventory{Meta: govCollected(), Deployments: []appsv1.Deployment{
		deploy("kube-system", "coredns", 2, nil),
		deploy("kube-system", "kube-proxy-ish", 2, nil),
	}}
	if got := len(NoResourceGovernance{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("system namespace must be skipped by default, got %d findings", got)
	}
	if got := len(NoResourceGovernance{}.Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", got)
	}
}

func TestNoResourceGovernance_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{Meta: govCollected(), Deployments: []appsv1.Deployment{
		deploy("team-a", "x", 1, nil), deploy("team-a", "y", 1, nil),
		deploy("team-b", "x", 1, nil), deploy("team-b", "y", 1, nil),
	}}
	first := NoResourceGovernance{}.Evaluate(inv, Options{})
	second := NoResourceGovernance{}.Evaluate(inv, Options{})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want 2 findings per run, got %d and %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[0].ID == first[1].ID || !strings.HasPrefix(first[0].ID, "f-") {
		t.Errorf("IDs must be stable, distinct, f-prefixed: %q %q vs %q", first[0].ID, first[1].ID, second[0].ID)
	}
}
