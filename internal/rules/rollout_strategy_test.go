package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

func withRecreate(d *appsv1.Deployment) {
	d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
}

func withMaxUnavailable(v intstr.IntOrString) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		d.Spec.Strategy = appsv1.DeploymentStrategy{
			Type:          appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: &v},
		}
	}
}

func withPVCVolume(d *appsv1.Deployment) {
	d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-pvc"},
		},
	})
}

// serviceFor builds a Service selecting the labels the deploy() helper stamps
// on its pod template ({"app": <name>}).
func serviceFor(ns, name string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-svc", Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": name}},
	}
}

func TestRiskyRollout_Recreate(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "rec", 3, withRecreate),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "k8s.workload.risky-rollout-strategy" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "strategy.type=Recreate") {
		t.Errorf("evidence must cite the exact strategy: %v", f.Evidence)
	}
	// No PVC and no Service: the surge YAML is offered (with caveat) and the
	// confidence reflects UNVERIFIED impact, not field-read certainty.
	for _, want := range []string{"maxUnavailable: 0", "maxSurge: 1", "name: rec", "namespace: app", "kind: Deployment"} {
		if !strings.Contains(f.RemediationYAML, want) {
			t.Errorf("remediation YAML missing %q:\n%s", want, f.RemediationYAML)
		}
	}
	if !strings.Contains(f.RemediationYAML, "ReadWriteOnce") {
		t.Errorf("surge YAML must carry the Multi-Attach caveat:\n%s", f.RemediationYAML)
	}
	if f.Confidence != 0.6 {
		t.Errorf("confidence = %v, want 0.6 (impact unverified — no Service fronts it)", f.Confidence)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "no Service") {
		t.Errorf("evidence must note the serving path is unconfirmed: %v", f.Evidence)
	}
}

func TestRiskyRollout_RecreateFrontedByService(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "rec", 3, withRecreate)},
		Services:    []corev1.Service{serviceFor("app", "rec")},
	}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9 (a Service routes to it → real outage)", f.Confidence)
	}
	joined := strings.Join(f.Evidence, " ")
	// "serving path" was removed with the rest of the outcome language: a selector match is not
	// endpoint registration and endpoint registration is not traffic. The evidence must still name
	// the observed Service, and must say what the match does NOT prove.
	if !strings.Contains(joined, "Service") {
		t.Errorf("evidence must cite the observed Service: %v", f.Evidence)
	}
	if !strings.Contains(joined, "NOT proof") {
		t.Errorf("evidence must disclose what a selector match does not prove: %v", f.Evidence)
	}
	// A Service selecting this Deployment is an OBSERVED fact and stays. What the reader
	// experiences is not, and the same rule already says so in its own evidence — see
	// TestRiskyRolloutStrategy_AssertsNoOutcome for why the headline had to stop disagreeing
	// with the hedge printed beneath it.
	if strings.Contains(strings.ToLower(f.Description), "outage") {
		t.Errorf("fronted Deployment must not assert an outage: %q", f.Description)
	}
	if !strings.Contains(f.Description, "Service") {
		t.Errorf("the observed Service must still be named: %q", f.Description)
	}
}

func TestRiskyRollout_RecreateWithPVCWithholdsSurgeYAML(t *testing.T) {
	// A Recreate Deployment that mounts a PVC is the RWO / single-writer case
	// Recreate is chosen for. Handing it maxSurge:1 would deadlock the rollout
	// (Multi-Attach) — so the surge YAML must be WITHHELD, replaced by guidance.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "stateful-rec", 1, func(d *appsv1.Deployment) {
			withRecreate(d)
			withPVCVolume(d)
		}),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if strings.Contains(f.RemediationYAML, "maxSurge") {
		t.Errorf("must NOT emit a maxSurge fix for a PVC-backed workload:\n%s", f.RemediationYAML)
	}
	joined := strings.Join(f.Evidence, " ")
	if !strings.Contains(joined, "PersistentVolumeClaim") || !strings.Contains(joined, "Multi-Attach") {
		t.Errorf("evidence must warn about the Multi-Attach deadlock: %v", f.Evidence)
	}
}

func TestRiskyRollout_MaxUnavailable100Percent(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "blast", 4, withMaxUnavailable(intstr.FromString("100%"))),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(joined, "maxUnavailable=100%") {
		t.Errorf("evidence must cite the exact value: %v", fs[0].Evidence)
	}
	// 100% of 4 = 4 down, 0 left serving.
	if !strings.Contains(joined, "4 of 4 pods down") {
		t.Errorf("evidence must resolve the percentage to a pod count: %v", fs[0].Evidence)
	}
}

func TestRiskyRollout_MaxUnavailableNearTotalPercent(t *testing.T) {
	// 75% of 4 rounds DOWN to 3 pods down — only 1 of 4 left serving. This is
	// the near-total collapse the old >=100% gate silently passed.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "near", 4, withMaxUnavailable(intstr.FromString("75%"))),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for 75%%-of-4 (3 down), got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(joined, "3 of 4 pods down") {
		t.Errorf("evidence must resolve 75%% to 3 of 4 down: %v", fs[0].Evidence)
	}
}

func TestRiskyRollout_HalfPercentNotFlagged(t *testing.T) {
	// 50% of 4 = 2 down, 2 still serving — not a near-total collapse.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "half", 4, withMaxUnavailable(intstr.FromString("50%"))),
	}}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("50%%-of-4 (2 left serving) must not be flagged: %+v", fs)
	}
}

func TestRiskyRollout_MaxUnavailableIntGEReplicas(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "all-down", 3, withMaxUnavailable(intstr.FromInt32(3))),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	joined := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(joined, "maxUnavailable=3") || !strings.Contains(joined, "3 of 3 pods down") {
		t.Errorf("evidence must cite maxUnavailable and the resolved pod count: %v", fs[0].Evidence)
	}
}

func TestRiskyRollout_MaxUnavailableBareIntStringGEReplicas(t *testing.T) {
	// A string-typed maxUnavailable without a "%" suffix (e.g. "3") must be
	// treated like the int form, not silently skipped.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "strint", 3, withMaxUnavailable(intstr.FromString("3"))),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for bare-int-string maxUnavailable, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "maxUnavailable=3") {
		t.Errorf("evidence must cite the value: %v", fs[0].Evidence)
	}
}

func TestRiskyRollout_SingleReplicaMaxUnavailableSuppressed(t *testing.T) {
	// replicas=1 + explicit maxUnavailable=1 is a tautology: any rollout touches
	// the only pod regardless of strategy. That risk is owned by
	// SingleReplicaNoPDB, so this rule must NOT fire (no strategy defect here).
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "singleton", 1, withMaxUnavailable(intstr.FromInt32(1))),
		deploy("app", "singleton-pct", 1, withMaxUnavailable(intstr.FromString("100%"))),
	}}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("single-replica maxUnavailable must be suppressed (owned by SingleReplicaNoPDB): %+v", fs)
	}
}

func TestRiskyRollout_EmptyStrategyNotFlagged(t *testing.T) {
	// client-go leaves Strategy empty; the API server defaults it to
	// RollingUpdate 25%/25% — safe, must NOT be flagged.
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "defaulted", 3, nil),
		// Type set but rollingUpdate params left to server defaults — also safe.
		deploy("app", "typed-only", 3, func(d *appsv1.Deployment) {
			d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType}
		}),
	}}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("empty/defaulted strategy flagged: %+v", fs)
	}
}

func TestRiskyRollout_SafeRollingUpdateNotFlagged(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "safe-int", 3, withMaxUnavailable(intstr.FromInt32(1))),
		deploy("app", "safe-pct", 4, withMaxUnavailable(intstr.FromString("25%"))),
	}}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("safe rolling updates flagged: %+v", fs)
	}
}

func TestRiskyRollout_SystemNamespaceSkipped(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("kube-system", "sysd", 2, withRecreate),
	}}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default: %+v", fs)
	}
	if fs := (RiskyRolloutStrategy{}).Evaluate(inv, Options{IncludeSystem: true}); len(fs) != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", len(fs))
	}
}

func TestRiskyRollout_DistinctIDs(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "one", 2, withRecreate),
		deploy("app", "two", 2, withRecreate),
	}}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].ID == fs[1].ID || !strings.HasPrefix(fs[0].ID, "f-") {
		t.Fatalf("finding IDs must be distinct f-prefixed hashes: %q vs %q", fs[0].ID, fs[1].ID)
	}
}

// ---------------------------------------------------------------------------------------------
// RiskyRolloutStrategy may not assert an OUTCOME. This rule predates the drain and rollout
// families and was written before that line was drawn, so it asserted three things the snapshot
// cannot support — a "self-inflicted outage window", that "every request in that window fails or
// stalls", and a "zero-downtime" promise in its own title — while the SAME rule already carried
// the honest hedge "user-facing impact is NOT confirmed by the read-only scan". A rule that
// contradicts itself in one card is the defect; the hedge was right and the headline was wrong.
//
// The observable facts stay: which Service selects the Deployment, the replica arithmetic, and
// that Recreate deletes every replica before creating any. What goes is every claim about what
// users experience, which is unreadable from a snapshot for exactly the reasons node_drain.go
// states at length.
// ---------------------------------------------------------------------------------------------

var bannedRolloutStrategyPhrases = []string{
	"outage", "downtime", "fails or stalls", "2am", "self-inflicted",
	"request in that window", "users will", "user-visible",
}

func TestRiskyRolloutStrategy_AssertsNoOutcome(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "rec", 3, withRecreate),                                 // fronted, below
			deploy("app", "bare", 3, withRecreate),                                // not fronted
			deploy("app", "mu", 4, withMaxUnavailable(intstr.FromString("100%"))), // near-total
		},
		Services: []corev1.Service{serviceFor("app", "rec")},
	}
	fs := RiskyRolloutStrategy{}.Evaluate(inv, Options{IncludeSystem: true})
	if len(fs) == 0 {
		t.Fatal("fixture produced no findings — the phrase gate would pass vacuously")
	}
	for _, f := range fs {
		blob := strings.ToLower(strings.Join([]string{
			f.Title, f.Description, f.WhyItMatters,
			strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
		}, " "))
		for _, banned := range bannedRolloutStrategyPhrases {
			if strings.Contains(blob, banned) {
				t.Errorf("RiskyRolloutStrategy emits %q — the snapshot cannot support it.\n  finding: %s",
					banned, f.Title)
			}
		}
	}
}
