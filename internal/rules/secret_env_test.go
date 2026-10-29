package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A SECRET REACHING A CONTAINER THROUGH THE ENVIRONMENT, READ WITHOUT READING ONE SECRET.
//
// The control exists in all three provider benchmarks and in the generic one (5.4.1), and
// docs/qa/2026-08-31-provider-benchmark-measurement.md calls it "the single best unbuilt row in the whole
// exercise" for one reason: it is a workload-spec fact. `env[].valueFrom.secretKeyRef` and
// `envFrom[].secretRef` are references BY NAME. No Secret is read, no value is seen, and this rule works
// unchanged on a cluster where Secrets are refused — which is every cluster this tool runs on, because
// internal/collect never lists them.
//
// WHAT IT IS ABOUT. An environment variable is inherited by every child process, appears in
// `kubectl describe pod` for anyone with pod read, and is copied into crash dumps and process listings. A
// mounted file is readable by the container too — the difference is the blast radius of a read that was
// never meant to include it.
func TestSecretInEnvVar(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			// A single variable from one key of one Secret.
			deploy("app", "keyed", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name: "DB_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}, Key: "password"}},
				}}
			}),
			// The whole Secret, every key, as variables.
			deploy("app", "wholesale", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "app-env"}},
				}}
			}),
			// A ConfigMap through the same mechanism is NOT this finding.
			deploy("app", "configmap-only", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name: "LOG_LEVEL",
					ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "level"}},
				}}
			}),
			// A Secret MOUNTED is the recommended shape and is not a finding.
			deploy("app", "mounted", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Volumes = []corev1.Volume{{
					Name: "creds", VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{SecretName: "db-creds"}}}}
				d.Spec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
					Name: "creds", MountPath: "/etc/creds", ReadOnly: true}}
			}),
		},
		Meta: collect.Meta{Collected: []string{"deployments", "statefulsets", "daemonsets"}},
	}

	fs := SecretInEnvVar{}.Evaluate(inv, Options{})
	got := map[string]types.Finding{}
	for _, f := range fs {
		got[f.AffectedResources[0].Name] = f
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (keyed, wholesale), got %d: %v", len(fs), names(fs))
	}
	if _, ok := got["configmap-only"]; ok {
		t.Error("a ConfigMap reaching the environment is not a secret in an environment variable")
	}
	if _, ok := got["mounted"]; ok {
		t.Error("a mounted Secret is the shape the control asks for and must not be reported")
	}

	// THE EVIDENCE NAMES THE VARIABLE AND THE SECRET, and never a value: there is no value here to name.
	keyed := got["keyed"]
	ev := strings.Join(keyed.Evidence, " | ")
	for _, want := range []string{"DB_PASSWORD", "db-creds", "password"} {
		if !strings.Contains(ev, want) {
			t.Errorf("the evidence does not name %q, so a reader cannot find the variable: %s", want, ev)
		}
	}
	if keyed.Category != types.CategorySecurity {
		t.Errorf("category is %q, want security", keyed.Category)
	}

	// A WHOLE-SECRET envFrom SAYS SO, because "every key of app-env" is a different fact from one variable.
	whole := strings.Join(got["wholesale"].Evidence, " | ")
	if !strings.Contains(whole, "app-env") || !strings.Contains(strings.ToLower(whole), "every key") {
		t.Errorf("envFrom evidence must say the whole Secret becomes variables: %s", whole)
	}

	// NO SECRET IS READ, AND THE FINDING SAYS SO SOMEWHERE A READER WILL SEE IT.
	all := keyed.Description + " " + keyed.WhyItMatters + " " + strings.Join(keyed.ClaimBoundaries, " ")
	if !strings.Contains(strings.ToLower(all), "value") {
		t.Errorf("the finding never says the value was not read; a reader has to know this is a reference "+
			"and not a disclosure: %s", all)
	}
}

// A DENIED WORKLOAD READ IS NOT AN ABSENCE OF SECRETS IN ENVIRONMENTS.
func TestSecretInEnvVar_SilentWhenWorkloadsWereNotCollected(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "keyed", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name: "DB_PASSWORD",
					ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}, Key: "password"}},
				}}
			}),
		},
		Meta: collect.Meta{Denied: []string{"deployments: forbidden"}},
	}
	if fs := (SecretInEnvVar{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("a run that could not list Deployments produced %d finding(s); silence is the only honest "+
			"output of a read that did not happen", len(fs))
	}
}

func names(fs []types.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.AffectedResources[0].Name)
	}
	return out
}
