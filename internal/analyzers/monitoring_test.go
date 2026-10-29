package analyzers

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// monitoring_test.go — each test with the reason it is not vacuous.
//
// THIS FAMILY'S NORMAL OUTPUT IS SILENCE, so a planted positive for every shape is not optional: it is the
// only thing that distinguishes "correct" than "asleep". And the refusals in §10.3 are asserted directly,
// because every one of them is a sentence that would be easy to write and false.

func monInv(resource string, objs []unstructured.Unstructured, coreKinds ...string) *collect.Inventory {
	version := "v1"
	if resource == "alertmanagerconfigs" {
		version = "v1alpha1"
	}
	gvr := schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: version, Resource: resource}
	collected := append([]string{"cr:" + gvr.GroupResource().String()}, coreKinds...)
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: objs},
		Meta:         collect.Meta{Collected: collected},
	}
}

func serviceMonitor(ns, name string, match map[string]interface{}, nsSel map[string]interface{}) unstructured.Unstructured {
	spec := map[string]interface{}{"selector": map[string]interface{}{"matchLabels": match}}
	if nsSel != nil {
		spec["namespaceSelector"] = nsSel
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "monitoring.coreos.com/v1",
		"kind":       "ServiceMonitor",
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"spec":       spec,
	}}
}

func svc(ns, name string, lbl map[string]string) corev1.Service {
	return corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbl}}
}

// ── ServiceMonitor ───────────────────────────────────────────────────────────────────────────────

// NOT VACUOUS: the matching half of the same fixture is asserted silent in the same test, so a rule that
// returned a finding for every ServiceMonitor would fail on the second subtest rather than pass on the first.
func TestServiceMonitor_FiresOnlyWhenNothingMatches(t *testing.T) {
	t.Run("selector matches nothing", func(t *testing.T) {
		inv := monInv("servicemonitors",
			[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)},
			"services")
		inv.Services = []corev1.Service{svc("obs", "grafana", map[string]string{"app": "grafana"})}
		got := (ServiceMonitorTargets{}).Analyze(inv)
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(got[0].Title, "obs/api") {
			t.Errorf("title does not name the ServiceMonitor: %s", got[0].Title)
		}
	})
	t.Run("selector matches a Service", func(t *testing.T) {
		inv := monInv("servicemonitors",
			[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)},
			"services")
		inv.Services = []corev1.Service{svc("obs", "api", map[string]string{"app": "api"})}
		if got := (ServiceMonitorTargets{}).Analyze(inv); len(got) != 0 {
			t.Errorf("a matching ServiceMonitor produced %d finding(s): %s", len(got), got[0].Title)
		}
	})
}

// THE NAMESPACE RULE, and it is the one a hand-written implementation gets wrong. Without a
// namespaceSelector a ServiceMonitor covers its OWN namespace only — so a Service with the right labels in
// a DIFFERENT namespace does not save it, and treating the selector as cluster-wide would silence a real
// finding on every multi-namespace cluster.
func TestServiceMonitor_DefaultScopeIsItsOwnNamespace(t *testing.T) {
	inv := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)},
		"services")
	inv.Services = []corev1.Service{svc("prod", "api", map[string]string{"app": "api"})}
	got := (ServiceMonitorTargets{}).Analyze(inv)
	if len(got) != 1 {
		t.Fatalf("a same-labelled Service in another namespace silenced the finding; want 1, got %d", len(got))
	}
	// And with any:true the same fixture must go quiet, which is what proves the scope is being read
	// rather than ignored in one direction.
	inv2 := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"},
			map[string]interface{}{"any": true})},
		"services")
	inv2.Services = []corev1.Service{svc("prod", "api", map[string]string{"app": "api"})}
	if got := (ServiceMonitorTargets{}).Analyze(inv2); len(got) != 0 {
		t.Errorf("namespaceSelector.any=true did not widen the scope: %s", got[0].Title)
	}
}

// AN EMPTY SELECTOR SELECTS EVERYTHING, which is inverted from intuition and is what the operator acts on.
// A reading that treated it as "matches nothing" would report every catch-all ServiceMonitor in existence.
func TestServiceMonitor_AnEmptySelectorMatchesEverything(t *testing.T) {
	inv := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "catch-all", map[string]interface{}{}, nil)},
		"services")
	inv.Services = []corev1.Service{svc("obs", "anything", nil)}
	if got := (ServiceMonitorTargets{}).Analyze(inv); len(got) != 0 {
		t.Errorf("an empty selector was read as matching nothing: %s", got[0].Title)
	}
}

// THE DENIAL GUARD IS WHOLE-RULE: an unmatched selector and an unread namespace look identical from here.
func TestServiceMonitor_ADeniedServiceListIsSilence(t *testing.T) {
	inv := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)})
	inv.Meta.Denied = []string{"services: forbidden"}
	if got := (ServiceMonitorTargets{}).Analyze(inv); len(got) != 0 {
		t.Errorf("a refused Services list produced a finding: %s", got[0].Title)
	}
	// Neither collected nor denied is also silence — the run has no record of having looked.
	inv2 := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)})
	if got := (ServiceMonitorTargets{}).Analyze(inv2); len(got) != 0 {
		t.Errorf("an unrecorded Services list produced a finding: %s", got[0].Title)
	}
}

// ── PodMonitor ───────────────────────────────────────────────────────────────────────────────────

func TestPodMonitor_FiresAndStaysSilentSymmetrically(t *testing.T) {
	pm := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "monitoring.coreos.com/v1", "kind": "PodMonitor",
		"metadata": map[string]interface{}{"namespace": "obs", "name": "workers"},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{"matchLabels": map[string]interface{}{"role": "worker"}}},
	}}
	inv := monInv("podmonitors", []unstructured.Unstructured{pm}, "pods")
	inv.Pods = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{
		Namespace: "obs", Name: "api-0", Labels: map[string]string{"role": "api"}}}}
	got := (PodMonitorTargets{}).Analyze(inv)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	// A POD LIST IS A MOMENT, and the finding has to say so — a workload scaled to zero looks exactly
	// like a typo'd selector from here.
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "scaled to zero") {
		t.Error("the finding does not disclose that a pod list is a moment")
	}
	inv.Pods[0].Labels = map[string]string{"role": "worker"}
	if got := (PodMonitorTargets{}).Analyze(inv); len(got) != 0 {
		t.Errorf("a matching PodMonitor produced a finding: %s", got[0].Title)
	}
}

// ── AlertmanagerConfig ───────────────────────────────────────────────────────────────────────────

func amConfig(ns, name string, receivers []string, route map[string]interface{}) unstructured.Unstructured {
	var rs []interface{}
	for _, r := range receivers {
		rs = append(rs, map[string]interface{}{"name": r})
	}
	spec := map[string]interface{}{"receivers": rs}
	if route != nil {
		spec["route"] = route
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "monitoring.coreos.com/v1alpha1", "kind": "AlertmanagerConfig",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     spec,
	}}
}

func TestAlertRouting_FiresOnAnUndeclaredReceiverAndNotOnADeclaredOne(t *testing.T) {
	t.Run("undeclared", func(t *testing.T) {
		obj := amConfig("obs", "team", []string{"slack"},
			map[string]interface{}{"receiver": "pagerduty"})
		got := (AlertRouting{}).Analyze(monInv("alertmanagerconfigs", []unstructured.Unstructured{obj}))
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "pagerduty") {
			t.Error("the evidence does not name the missing receiver")
		}
	})
	t.Run("declared", func(t *testing.T) {
		obj := amConfig("obs", "team", []string{"slack"}, map[string]interface{}{"receiver": "slack"})
		if got := (AlertRouting{}).Analyze(monInv("alertmanagerconfigs", []unstructured.Unstructured{obj})); len(got) != 0 {
			t.Errorf("a declared receiver produced a finding: %s", got[0].Title)
		}
	})
}

// A CHILD ROUTE WITH NO RECEIVER INHERITS ITS PARENT'S. Reporting an unnamed child would fire on ordinary
// routing — most alertmanager trees have them — which is the loudest possible false positive for this family.
func TestAlertRouting_AnInheritingChildRouteIsNotAMismatch(t *testing.T) {
	obj := amConfig("obs", "team", []string{"slack"}, map[string]interface{}{
		"receiver": "slack",
		"routes": []interface{}{
			map[string]interface{}{"matchers": []interface{}{}}, // inherits
			map[string]interface{}{"receiver": "slack"},         // declared
			map[string]interface{}{"receiver": "victorops"},     // NOT declared
		},
	})
	got := (AlertRouting{}).Analyze(monInv("alertmanagerconfigs", []unstructured.Unstructured{obj}))
	if len(got) != 1 {
		t.Fatalf("want exactly 1 finding for the one undeclared child, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(blob, "victorops") {
		t.Error("the undeclared child route is not reported")
	}
	if strings.Contains(blob, "routes[0]") {
		t.Error("an inheriting child route was reported as a mismatch")
	}
}

// §10.3's first refusal, asserted: never "your alerts do not work".
func TestMonitoring_NeverClaimsAlertingOrScrapingHappened(t *testing.T) {
	banned := []string{
		"alerts do not work", "alerts will not", "you are not monitoring", "not being monitored",
		"no alerts", "never fired", "will not fire", "is not scraped", "unmonitored",
		"you have no monitoring", "data loss", "will lose",
	}
	for _, f := range allMonitoringFindings() {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters}, f.Evidence...), "\n"))
		for _, b := range banned {
			if strings.Contains(blob, b) {
				t.Errorf("finding %s says %q — this reading sees what is CONFIGURED, never what is "+
					"scraped or delivered:\n%s", f.RuleID, b, blob)
			}
		}
	}
}

// The Secret boundary, stated in the finding rather than only in a comment: Alertmanager's main
// configuration is in a Secret this product refuses to read, so no sentence here may scope up to the cluster.
func TestAlertRouting_DisclosesTheSecretItCannotRead(t *testing.T) {
	obj := amConfig("obs", "team", []string{"slack"}, map[string]interface{}{"receiver": "pagerduty"})
	got := (AlertRouting{}).Analyze(monInv("alertmanagerconfigs", []unstructured.Unstructured{obj}))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "Secret") {
		t.Error("the finding does not disclose that Alertmanager's main configuration is unread")
	}
}

// ── Prometheus ───────────────────────────────────────────────────────────────────────────────────

func promObj(ns, name string, spec map[string]interface{}) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "monitoring.coreos.com/v1", "kind": "Prometheus",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     spec,
	}}
}

// BOTH DOORS. A reading that only checked spec.storage would report as ephemeral every Prometheus a chart
// backs through spec.volumes — durable storage, reported as absent.
func TestPrometheusDurability_BothStorageAndVolumesSilenceIt(t *testing.T) {
	fire := promObj("obs", "k8s", map[string]interface{}{"retention": "30d"})
	got := (PrometheusDurability{}).Analyze(monInv("prometheuses", []unstructured.Unstructured{fire}))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "30d") {
		t.Error("the finding does not cite the retention it is about")
	}
	for _, quiet := range []map[string]interface{}{
		{"storage": map[string]interface{}{"volumeClaimTemplate": map[string]interface{}{}}},
		{"volumes": []interface{}{map[string]interface{}{"name": "data"}}},
	} {
		obj := promObj("obs", "k8s", quiet)
		if got := (PrometheusDurability{}).Analyze(monInv("prometheuses", []unstructured.Unstructured{obj})); len(got) != 0 {
			t.Errorf("a Prometheus with %v was reported as declaring no storage", quiet)
		}
	}
}

// AN EMPTYDIR MAY BE DELIBERATE, and the finding has to say so — a federated or short-lived Prometheus that
// ships its series elsewhere needs no local durability, and this rule cannot tell one from a mistake.
func TestPrometheusDurability_AllowsThatItMayBeDeliberate(t *testing.T) {
	obj := promObj("obs", "k8s", map[string]interface{}{})
	got := (PrometheusDurability{}).Analyze(monInv("prometheuses", []unstructured.Unstructured{obj}))
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "deliberate") {
		t.Error("the finding does not allow that an emptyDir may be intended")
	}
}

// ── the family ───────────────────────────────────────────────────────────────────────────────────

// §10.3's third refusal: no monitoring CRDs means SILENCE, never "you have no monitoring". Asserted on an
// inventory that carries nothing at all.
func TestMonitoring_AnAbsentOperatorIsSilentNotAFinding(t *testing.T) {
	empty := &collect.Inventory{Meta: collect.Meta{Collected: []string{"services", "pods"}}}
	for _, a := range []StackAnalyzer{
		ServiceMonitorTargets{}, PodMonitorTargets{}, AlertRouting{}, PrometheusDurability{},
	} {
		if got := a.Analyze(empty); len(got) != 0 {
			t.Errorf("%s reported %d finding(s) on a cluster with no monitoring CRDs", a.ID(), len(got))
		}
	}
}

func TestMonitoring_NeverCarriesDollars(t *testing.T) {
	for _, f := range allMonitoringFindings() {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("%s carries $%.2f", f.RuleID, f.DollarImpactMonthly)
		}
	}
}

// allMonitoringFindings plants one of every shape this family produces.
func allMonitoringFindings() []types.Finding {
	var out []types.Finding

	smInv := monInv("servicemonitors",
		[]unstructured.Unstructured{serviceMonitor("obs", "api", map[string]interface{}{"app": "api"}, nil)},
		"services")
	smInv.Services = []corev1.Service{svc("obs", "grafana", map[string]string{"app": "grafana"})}
	out = append(out, (ServiceMonitorTargets{}).Analyze(smInv)...)

	pmObj := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "monitoring.coreos.com/v1", "kind": "PodMonitor",
		"metadata": map[string]interface{}{"namespace": "obs", "name": "workers"},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{"matchLabels": map[string]interface{}{"role": "worker"}}},
	}}
	pmInv := monInv("podmonitors", []unstructured.Unstructured{pmObj}, "pods")
	pmInv.Pods = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "obs", Name: "api-0"}}}
	out = append(out, (PodMonitorTargets{}).Analyze(pmInv)...)

	out = append(out, (AlertRouting{}).Analyze(monInv("alertmanagerconfigs",
		[]unstructured.Unstructured{amConfig("obs", "team", []string{"slack"},
			map[string]interface{}{"receiver": "pagerduty"})}))...)

	out = append(out, (PrometheusDurability{}).Analyze(monInv("prometheuses",
		[]unstructured.Unstructured{promObj("obs", "k8s", map[string]interface{}{"retention": "30d"})}))...)

	return out
}
