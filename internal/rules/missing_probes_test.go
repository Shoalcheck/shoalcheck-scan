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

// mpDeploy builds a 2-replica Deployment with a single "main" container and
// app=<name> pod labels, then applies an optional mutator. Local to this file
// to avoid coupling to the shared test helpers.
func mpDeploy(ns, name string, mutate func(*appsv1.Deployment)) appsv1.Deployment {
	r := int32(2)
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &r,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
			},
		},
	}
	if mutate != nil {
		mutate(&d)
	}
	return d
}

func mpReadiness(d *appsv1.Deployment) {
	d.Spec.Template.Spec.Containers[0].ReadinessProbe = &corev1.Probe{}
}
func mpLiveness(d *appsv1.Deployment) {
	d.Spec.Template.Spec.Containers[0].LivenessProbe = &corev1.Probe{}
}
func mpPorts(d *appsv1.Deployment) {
	d.Spec.Template.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080, Name: "http"}}
}

func only(t *testing.T, fs []types.Finding) types.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want exactly 1 finding, got %d", len(fs))
	}
	return fs[0]
}

// --- tests ---------------------------------------------------------------

// Readiness missing + serves traffic (declares a port) => Medium, and the
// readiness/rollout impact IS asserted.
func TestMissingProbes_ReadinessOnTrafficWorkload_Medium(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "web", func(d *appsv1.Deployment) { mpLiveness(d); mpPorts(d) }), // readiness missing, has port
	}}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	if f.Severity != "medium" {
		t.Errorf("serving workload missing readiness should be medium, got %q", f.Severity)
	}
	if !strings.Contains(f.Description, "traffic can reach pods before they are ready") {
		t.Errorf("expected readiness/rollout impact in description, got: %s", f.Description)
	}
	if strings.Contains(f.Description, "never restarted") {
		t.Errorf("liveness IS configured here; liveness-hang claim must not appear: %s", f.Description)
	}
	if f.RemediationYAML != "" {
		t.Errorf("liveness is present; no liveness remediation YAML should be emitted")
	}
}

// Readiness missing but NO traffic (no ports, no Service) => Low, and the
// rollout-outage narrative must NOT be asserted (vacuous false positive guard).
func TestMissingProbes_ReadinessNoTraffic_LowAndNeutralWording(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "worker", mpLiveness), // readiness missing, no ports, no Service
	}}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	if f.Severity != "low" {
		t.Errorf("non-serving workload missing readiness should be low, got %q", f.Severity)
	}
	if strings.Contains(f.Description, "each rollout briefly drops requests") {
		t.Errorf("workload serves no traffic; rollout-outage claim is vacuous and must be suppressed: %s", f.Description)
	}
	if !strings.Contains(f.Description, "exposes no ports and sits behind no Service") {
		t.Errorf("expected neutralized readiness wording, got: %s", f.Description)
	}
}

// A Service selecting the pods counts as "serves traffic" even without ports.
func TestMissingProbes_BehindServiceCountsAsTraffic_Medium(t *testing.T) {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "app"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "api"}},
	}
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{mpDeploy("app", "api", mpLiveness)}, // no ports, but Service selects it
		Services:    []corev1.Service{svc},
	}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	if f.Severity != "medium" {
		t.Errorf("workload behind a Service should be medium, got %q", f.Severity)
	}
}

// Liveness-only gap on a serving workload => Low (no readiness outage path),
// liveness-hang claim asserted, readiness claim NOT asserted, and a SAFE
// liveness remediation skeleton (startupProbe + conservative thresholds) is
// attached and flagged as a template.
func TestMissingProbes_LivenessOnly_LowWithSafeRemediation(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "svc", func(d *appsv1.Deployment) { mpReadiness(d); mpPorts(d) }), // liveness missing
	}}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	if f.Severity != "low" {
		t.Errorf("liveness-only gap should be low, got %q", f.Severity)
	}
	if !strings.Contains(f.Description, "hung or deadlocked process is never restarted") {
		t.Errorf("expected liveness-hang impact, got: %s", f.Description)
	}
	if strings.Contains(f.Description, "ready to serve") {
		t.Errorf("readiness IS configured; readiness claim must not appear: %s", f.Description)
	}
	if f.RemediationYAML == "" {
		t.Fatalf("liveness gap should attach a remediation skeleton")
	}
	for _, want := range []string{"startupProbe", "failureThreshold", "TEMPLATE", "do NOT apply blind"} {
		if !strings.Contains(f.RemediationYAML, want) {
			t.Errorf("liveness remediation must contain %q for safety; got:\n%s", want, f.RemediationYAML)
		}
	}
}

// Every finding must carry the spec-scope caveat (probes may be injected on the
// running pod via webhooks/sidecars).
func TestMissingProbes_SpecScopeCaveatAlwaysPresent(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "x", mpLiveness),
	}}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	joined := strings.Join(f.Evidence, " ")
	if !strings.Contains(joined, "controller PodSpec") || !strings.Contains(joined, "admission webhooks") {
		t.Errorf("expected spec-scope caveat in evidence, got: %v", f.Evidence)
	}
}

// Confidence stays 1.0 (detection certainty), independent of impact wording.
func TestMissingProbes_ConfidenceIsDetectionCertainty(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "x", mpLiveness),
	}}
	f := only(t, MissingProbes{}.Evaluate(inv, Options{}))
	if f.Confidence != 1.0 {
		t.Errorf("confidence should remain 1.0 (probe presence is a literal spec fact), got %v", f.Confidence)
	}
}

// Fully-probed workload produces no finding.
func TestMissingProbes_FullyProbed_NoFinding(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		mpDeploy("app", "ok", func(d *appsv1.Deployment) { mpReadiness(d); mpLiveness(d) }),
	}}
	fs := MissingProbes{}.Evaluate(inv, Options{})
	if len(fs) != 0 {
		t.Errorf("fully-probed workload should yield no finding, got %d", len(fs))
	}
}
