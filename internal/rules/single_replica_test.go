package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// srMeta marks both the PDB and Service lists as successfully collected so the
// denial guard does not fire and exposure determinations are trusted.
func srMeta() collect.Meta {
	return collect.Meta{Collected: []string{"deployments", "statefulsets", "services", "poddisruptionbudgets"}}
}

// srStatefulSet builds a 1-replica StatefulSet with pod labels {app: name}.
func srStatefulSet(ns, name string) appsv1.StatefulSet {
	r := int32(1)
	return appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &r,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
			},
		},
	}
}

func srOnly(t *testing.T, fs []types.Finding) types.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

// FINDING [SingleReplicaNoPDB] dangerous-recommendation: the rule must NOT emit
// a PodDisruptionBudget manifest for a 1-replica workload — minAvailable:1 on a
// single replica is the exact zero-disruption deadlock PDBBlocksDrains flags.
// Scaling to a second replica is the primary remediation.
func TestSingleReplica_NoDeadlockingPDBManifest(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("prod", "api")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))

	if f.RemediationYAML != "" {
		t.Errorf("must not emit a PDB manifest for a single replica (minAvailable:1 deadlocks drains):\n%s", f.RemediationYAML)
	}
	if strings.Contains(f.RemediationYAML, "minAvailable") {
		t.Errorf("RemediationYAML must never contain minAvailable on a single replica:\n%s", f.RemediationYAML)
	}
	// Primary remediation is the scale-up.
	if !strings.Contains(f.RemediationCommand, "--replicas=2") {
		t.Errorf("primary remediation must scale to 2 replicas, got: %q", f.RemediationCommand)
	}
	// If a PDB is mentioned, it must steer away from the deadlocking
	// minAvailable:1 form (a "never minAvailable:1" warning is fine; an actual
	// minAvailable:1 recommendation is not).
	if strings.Contains(f.RemediationCommand, "minAvailable: 1") || strings.Contains(f.RemediationCommand, "minAvailable:1") {
		t.Errorf("remediation must not recommend minAvailable:1 on a single replica: %q", f.RemediationCommand)
	}
}

// FINDING [SingleReplicaNoPDB] miscalibration: Confidence is no longer 1.0 (the
// impact is inferred, not measured) and Severity is modulated, not a flat High.
func TestSingleReplica_ConfidenceCalibrated(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("prod", "api")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Confidence == 1.0 {
		t.Errorf("confidence must not be a flat 1.0 — impact is inferred, not measured")
	}
	if f.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9 (certain fact, inferred impact)", f.Confidence)
	}
}

// FINDING [SingleReplicaNoPDB] miscalibration: severity High only for a workload
// fronted by a Service in a non-dev namespace.
func TestSingleReplica_Severity_ExposedProd_IsHigh(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("prod", "api")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityHigh {
		t.Errorf("exposed prod single-replica severity = %q, want high", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.WhyItMatters), "outage") && !strings.Contains(strings.ToLower(f.WhyItMatters), "user-visible") {
		t.Errorf("exposed workload WhyItMatters should speak to user-visible impact: %q", f.WhyItMatters)
	}
}

// FINDING [SingleReplicaNoPDB] miscalibration + missing-caveat: a workload with
// NO Service edge (background reconciler) is hygiene, not an outage — Low.
func TestSingleReplica_Severity_NoService_IsLow(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "reconciler", 1, nil)},
		// services collected, but none select the reconciler
		Meta: srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityLow {
		t.Errorf("un-exposed single-replica severity = %q, want low", f.Severity)
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "No Service") {
		t.Errorf("evidence must record that no Service selects the pods: %v", f.Evidence)
	}
}

// FINDING [SingleReplicaNoPDB] miscalibration: dev/staging single-replica is
// commonly intentional → tempered to Medium even when exposed.
func TestSingleReplica_Severity_DevNamespace_IsMedium(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("staging", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("staging", "api")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityMedium {
		t.Errorf("exposed dev/staging single-replica severity = %q, want medium", f.Severity)
	}
}

// FINDING [SingleReplicaNoPDB] missing-caveat (denial guard, policy #3): when the
// Service list was NOT collected, severity must not be overstated as High and we
// must not claim the workload is un-exposed.
func TestSingleReplica_ServicesNotCollected_NoExposureClaim(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		// services NOT in Collected; pdbs are, so the rule still runs
		Meta: collect.Meta{Collected: []string{"deployments", "poddisruptionbudgets"}},
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity == types.SeverityHigh {
		t.Errorf("must not claim High when exposure is unknown (services not collected), got %q", f.Severity)
	}
	if f.Severity != types.SeverityMedium {
		t.Errorf("unknown-exposure severity = %q, want medium (honest middle)", f.Severity)
	}
	ev := strings.Join(f.Evidence, " ")
	if strings.Contains(ev, "No Service") {
		t.Errorf("must NOT assert absence of a Service that was never listed: %v", f.Evidence)
	}
	if !strings.Contains(strings.ToLower(ev), "not collected") && !strings.Contains(strings.ToLower(ev), "not assessed") {
		t.Errorf("evidence must caveat that exposure was not assessed: %v", f.Evidence)
	}
}

// FINDING [SingleReplicaNoPDB] missing-caveat (denial guard, policy #3): when the
// PDB list itself was denied/timed-out, the rule must emit NOTHING — a workload
// with no observed PDB is indistinguishable from one we never read.
func TestSingleReplica_PDBListDenied_SkipsEntirely(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("prod", "api")},
		Meta: collect.Meta{
			Collected: []string{"deployments", "services"},
			Denied:    []string{"poddisruptionbudgets: forbidden"},
		},
	}
	if fs := (SingleReplicaNoPDB{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("PDB list denied → must not assert 'no PDB'; want 0 findings, got %d: %+v", len(fs), fs)
	}
}

// FINDING [SingleReplicaNoPDB] missing-caveat: absolute 'mechanically guaranteed'
// wording must be gone; the consequence is phrased conditionally.
func TestSingleReplica_WordingIsConditional(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "reconciler", 1, nil)},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	blob := strings.ToLower(f.Description + " " + f.WhyItMatters)
	for _, banned := range []string{"mechanically guaranteed", "zero ceremony"} {
		if strings.Contains(blob, banned) {
			t.Errorf("absolute wording %q must be softened to conditional: %q / %q", banned, f.Description, f.WhyItMatters)
		}
	}
}

// FINDING [SingleReplicaNoPDB] missing-caveat: the StatefulSet 'verify
// replication before scaling' caveat must surface in the rendered finding
// (Description), not only in the buried command comment.
func TestSingleReplica_StatefulSetCaveatSurfaced(t *testing.T) {
	inv := &collect.Inventory{
		StatefulSets: []appsv1.StatefulSet{srStatefulSet("prod", "pg")},
		Meta:         srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	desc := strings.ToLower(f.Description + " " + f.WhyItMatters)
	if !strings.Contains(desc, "statefulset") || !(strings.Contains(desc, "replication") || strings.Contains(desc, "corrupt") || strings.Contains(desc, "quorum")) {
		t.Errorf("StatefulSet caveat (verify replication / data-corruption risk) must be in the rendered finding, got: %q / %q", f.Description, f.WhyItMatters)
	}
	// The command also keeps its guard.
	if !strings.Contains(f.RemediationCommand, "verify the app supports >1 replica") {
		t.Errorf("StatefulSet scale command must keep its verify-replication guard: %q", f.RemediationCommand)
	}
}

// FINDING [SingleReplicaNoPDB] missing-caveat: a declared-intentional singleton
// (opt-out label) must be suppressed.
func TestSingleReplica_OptOutSuppresses(t *testing.T) {
	d := deploy("prod", "leader", 1, func(d *appsv1.Deployment) {
		d.Spec.Template.Labels["shoalcheck.dev/single-replica"] = "true"
	})
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{d},
		Services:    []corev1.Service{serviceFor("prod", "leader")},
		Meta:        srMeta(),
	}
	if fs := (SingleReplicaNoPDB{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("declared intentional singleton must be suppressed; want 0, got %d: %+v", len(fs), fs)
	}
}

// Covered-by-PDB and multi-replica workloads remain unflagged (regression of the
// original behavior, now under a populated Meta).
func TestSingleReplica_CoveredAndScaled_NotFlagged(t *testing.T) {
	pdb := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "covered"}},
		},
	}
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("prod", "covered", 1, nil), // single but PDB-covered → skip
			deploy("prod", "scaled", 3, nil),  // multi-replica → skip
			deploy("prod", "lonely", 1, nil),  // the only finding
		},
		PDBs: []policyv1.PodDisruptionBudget{pdb},
		Meta: srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.AffectedResources[0].Name != "lonely" {
		t.Errorf("flagged %q, want lonely", f.AffectedResources[0].Name)
	}
}

// srServiceWithPorts builds a Service that selects {app: name} and exposes the
// given named ports — used to distinguish a metrics/webhook-only endpoint from a
// real serving path.
func srServiceWithPorts(ns, name string, portNames ...string) corev1.Service {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-svc", Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": name}},
	}
	for i, pn := range portNames {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: pn, Port: int32(8000 + i)})
	}
	return svc
}

// FINDING [SingleReplicaNoPDB] severity-overclaim: a leader-elected/background
// controller (name matches controller/operator/cert-manager/argocd/… patterns)
// is single-replica BY DESIGN. Even when a (metrics/webhook) Service selects it,
// its loss is a brief reconcile/admission gap, not a user-visible outage →
// capped at Medium, with reframed wording.
func TestSingleReplica_Controller_NameMatch_IsMediumAndReframed(t *testing.T) {
	for _, name := range []string{"cert-manager", "argocd-applicationset-controller", "billing-operator", "flux-source-controller"} {
		inv := &collect.Inventory{
			Deployments: []appsv1.Deployment{deploy("prod", name, 1, nil)},
			Services:    []corev1.Service{serviceFor("prod", name)}, // selects it, but it is a controller
			Meta:        srMeta(),
		}
		f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
		if f.Severity != types.SeverityMedium {
			t.Errorf("controller %q severity = %q, want medium (single-replica by design)", name, f.Severity)
		}
		blob := strings.ToLower(f.Description + " " + f.WhyItMatters)
		if !strings.Contains(blob, "leader-elected") && !strings.Contains(blob, "controller") {
			t.Errorf("controller %q finding must reframe as leader-elected/controller, got: %q / %q", name, f.Description, f.WhyItMatters)
		}
		// The reframe must explicitly deny the outage ("not a user-visible
		// outage") rather than assert it ("causes a user-visible outage window").
		if !strings.Contains(blob, "not a user-visible outage") {
			t.Errorf("controller %q must explicitly NOT claim a user-visible outage: %q / %q", name, f.Description, f.WhyItMatters)
		}
		if !strings.Contains(blob, "gap") {
			t.Errorf("controller %q should frame the consequence as a brief gap: %q / %q", name, f.Description, f.WhyItMatters)
		}
	}
}

// FINDING [SingleReplicaNoPDB] severity-overclaim: a workload whose backing
// Service exposes ONLY metrics/webhook/health ports is not on a user-serving
// path even if its name is generic → capped at Medium, not High.
func TestSingleReplica_MetricsOnlyService_IsMedium(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "thing", 1, nil)},
		Services:    []corev1.Service{srServiceWithPorts("prod", "thing", "metrics", "webhook")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityMedium {
		t.Errorf("metrics/webhook-only Service severity = %q, want medium (not a serving path)", f.Severity)
	}
	// Must not affirmatively claim an outage; the metrics-only path reframes it as
	// "not a user-visible outage".
	why := strings.ToLower(f.WhyItMatters)
	if strings.Contains(why, "causes a user-visible outage window") || strings.Contains(why, "can cause a user-visible outage window") {
		t.Errorf("metrics-only workload must not assert a user-visible outage: %q", f.WhyItMatters)
	}
	ev := strings.ToLower(strings.Join(f.Evidence, " "))
	if !strings.Contains(ev, "metrics/webhook/health ports") {
		t.Errorf("metrics-only workload evidence must record the non-serving ports: %v", f.Evidence)
	}
}

// FINDING [SingleReplicaNoPDB] severity-overclaim: a real serving Service (named
// http port) on a generically-named workload in prod stays High — the
// controller/metrics heuristics must not over-temper a genuine front-door.
func TestSingleReplica_ServingPortProd_StaysHigh(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "checkout", 1, nil)},
		Services:    []corev1.Service{srServiceWithPorts("prod", "checkout", "http")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityHigh {
		t.Errorf("genuine serving single-replica in prod severity = %q, want high", f.Severity)
	}
}

// FINDING [SingleReplicaNoPDB] severity-overclaim: dev-tempering must not depend
// on the namespace NAME alone. A workload labelled environment=dev / tier=staging
// in a generic namespace is non-prod and must be tempered the same way (exposed
// serving path → Medium, not High). Both pod-template labels and the workload's
// own object-metadata labels count.
func TestSingleReplica_NonProdLabel_TempersExposedToMedium(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*appsv1.Deployment)
	}{
		{"pod-template environment=dev", func(d *appsv1.Deployment) {
			d.Spec.Template.Labels["environment"] = "dev"
		}},
		{"pod-template tier=staging", func(d *appsv1.Deployment) {
			d.Spec.Template.Labels["tier"] = "staging"
		}},
		{"object-meta environment=qa", func(d *appsv1.Deployment) {
			d.Labels = map[string]string{"environment": "qa"}
		}},
		{"app.kubernetes.io/env=test", func(d *appsv1.Deployment) {
			d.Spec.Template.Labels["app.kubernetes.io/env"] = "test"
		}},
	}
	for _, tc := range cases {
		// "generic" is NOT a dev namespace name, so only the label can temper it.
		d := deploy("generic", "api", 1, tc.mutate)
		inv := &collect.Inventory{
			Deployments: []appsv1.Deployment{d},
			Services:    []corev1.Service{srServiceWithPorts("generic", "api", "http")},
			Meta:        srMeta(),
		}
		f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
		if f.Severity != types.SeverityMedium {
			t.Errorf("%s: severity = %q, want medium (non-prod label tempers exposed serving)", tc.name, f.Severity)
		}
		ev := strings.ToLower(strings.Join(f.Evidence, " "))
		if !strings.Contains(ev, "non-production") {
			t.Errorf("%s: evidence must record the non-production label/name signal: %v", tc.name, f.Evidence)
		}
	}
}

// FINDING [SingleReplicaNoPDB] guard: a prod-labelled workload (environment=prod)
// on a serving path is NOT tempered — it stays High. The non-prod matcher must
// not match production values.
func TestSingleReplica_ProdLabel_StaysHigh(t *testing.T) {
	d := deploy("generic", "api", 1, func(d *appsv1.Deployment) {
		d.Spec.Template.Labels["environment"] = "production"
	})
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{d},
		Services:    []corev1.Service{srServiceWithPorts("generic", "api", "http")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.Severity != types.SeverityHigh {
		t.Errorf("environment=production serving single-replica severity = %q, want high", f.Severity)
	}
}

// No $ is ever billed by this reliability rule (policy #5).
func TestSingleReplica_NoDollarImpact(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("prod", "api", 1, nil)},
		Services:    []corev1.Service{serviceFor("prod", "api")},
		Meta:        srMeta(),
	}
	f := srOnly(t, SingleReplicaNoPDB{}.Evaluate(inv, Options{}))
	if f.DollarImpactMonthly != 0 {
		t.Errorf("reliability rule must not bill a dollar, got %v", f.DollarImpactMonthly)
	}
}
