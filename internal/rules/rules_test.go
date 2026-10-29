package rules

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func deploy(ns, name string, replicas int32, mutate func(*appsv1.Deployment)) appsv1.Deployment {
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
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

func withFullSpec(d *appsv1.Deployment) {
	c := &d.Spec.Template.Spec.Containers[0]
	c.Resources.Requests = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("100m"),
		corev1.ResourceMemory: resource.MustParse("128Mi"),
	}
	c.ReadinessProbe = &corev1.Probe{}
	c.LivenessProbe = &corev1.Probe{}
}

func TestMissingRequests(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		deploy("app", "bad", 2, nil),
		deploy("app", "good", 2, withFullSpec),
		deploy("kube-system", "sysd", 2, nil), // excluded by default
	}}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (bad only), got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "k8s.workload.missing-resource-requests" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0].Name != "bad" {
		t.Errorf("affected = %+v", f.AffectedResources)
	}
	if !strings.Contains(f.RemediationYAML, "name: bad") || !strings.Contains(f.RemediationYAML, "cpu:") {
		t.Errorf("remediation YAML not workload-specific:\n%s", f.RemediationYAML)
	}
	if len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0], "main") {
		t.Errorf("evidence must name the container: %v", f.Evidence)
	}
}

func TestMissingRequests_IncludeSystem(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("kube-system", "sysd", 2, nil)}}
	if got := len(MissingRequests{}.Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", got)
	}
}

func TestMissingProbes(t *testing.T) {
	noReadiness := deploy("app", "half", 2, func(d *appsv1.Deployment) {
		d.Spec.Template.Spec.Containers[0].LivenessProbe = &corev1.Probe{}
	})
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{
		noReadiness,
		deploy("app", "good", 2, withFullSpec),
	}}
	fs := MissingProbes{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "readiness") {
		t.Errorf("evidence must say which probe is missing: %v", fs[0].Evidence)
	}
}

func TestSingleReplicaNoPDB(t *testing.T) {
	pdb := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "covered"}},
		},
	}
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "exposed", 1, nil),
			deploy("app", "covered", 1, nil), // has PDB → still flagged? no: rule is single-replica AND no PDB
			deploy("app", "scaled", 3, nil),  // not single → not flagged
		},
		PDBs: []policyv1.PodDisruptionBudget{pdb},
		// The rule fires on the ABSENCE of a PDB, so it must know the PDB list was actually read: an
		// inventory that never says what it looked at cannot support a claim about what is not there.
		Meta: collect.Meta{Collected: []string{"deployments", "poddisruptionbudgets", "services"}},
	}
	fs := SingleReplicaNoPDB{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (exposed only), got %d: %+v", len(fs), fs)
	}
	if fs[0].AffectedResources[0].Name != "exposed" {
		t.Errorf("flagged %q, want exposed", fs[0].AffectedResources[0].Name)
	}
}

func TestFindingIDsAreStable(t *testing.T) {
	inv := &collect.Inventory{Deployments: []appsv1.Deployment{deploy("app", "bad", 2, nil)}}
	a := MissingRequests{}.Evaluate(inv, Options{})[0].ID
	b := MissingRequests{}.Evaluate(inv, Options{})[0].ID
	if a != b || !strings.HasPrefix(a, "f-") {
		t.Errorf("IDs must be stable f-prefixed hashes: %q vs %q", a, b)
	}
}

func TestAllRegistry(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	// 35 non-PSS-table rules (15 original + PodSecurityAdmissionNotEnforced + the three Drain
	// Preflight rules in node_drain.go + Ground Truth's six in rotation.go/silent_failures.go +
	// Rollout Preflight's four in rollout_preflight.go + the five self-contradiction rules in
	// self_contradiction.go + the unattached-volume cost rule) plus one Rule per table-driven PSS
	// container check. Expressing it as
	// baseline+len(pssChecks) keeps the assertion correct when the PSS table grows.
	//
	// RAISED FROM 30 WITH THE REASON BESIDE IT: five rules were added by
	// docs/superpowers/specs/2026-08-28-b4-self-contradiction-design.md and one by
	// docs/superpowers/specs/2026-08-28-w3-unattached-volumes-design.md. A count changed without a
	// sentence is how the next person changes it blindly.
	//
	// RAISED TO 43 (2026-08-29): the reference-integrity family — DanglingServiceAccount, DanglingRoleRef and
	// DanglingScaleTarget — from Sweep 2 of the exhaustive-coverage epic. Nineteen census rows collapsed into
	// three rules, which is the ratio that census predicted and the reason it came before the build.
	//
	// RAISED TO 40 (2026-08-29): ZonePinnedVolume, ZoneLossFeasibility and NodeLossFeasibility, from
	// docs/superpowers/specs/2026-08-28-scheduling-feasibility-design.md §5 — the resilience half of B-5. The
	// cost half was refused in §4 and no rule here computes one.
	//
	// RAISED TO 37 (2026-08-28): RBACDangerousGrant, from
	// docs/superpowers/specs/2026-08-28-b1-role-bodies-design.md — Option C, approved in
	// docs/superpowers/briefs/2026-08-28-next-trace-target-and-b1.md §2. It reads Role and ClusterRole
	// bodies, which nine CIS controls had no evidence without.
	// RAISED TO 46 (2026-08-29): StuckCondition, DaemonSetMisscheduled and VolumeExpansionIncomplete, from
	// Sweep 3 of docs/superpowers/specs/2026-08-29-exhaustive-coverage-design.md — the spec-versus-status
	// family. Twelve unmined pairs in the census, three rules built; the replica-count group is held back
	// because it is the first family the Q1 demotion criterion applies to.
	// RAISED TO 48 (2026-08-29): SharedRWOVolume and AutoscalerFloorBelowBudget, from Sweep 4 — the
	// cross-object contradiction family. Four of that sweep's nine rows are deliberately unbuilt, each
	// with its reason recorded in contradiction.go's header.
	// RAISED TO 50 (2026-08-29): ImageDigestDrift and NodeVersionSkew, from §3 of the same spec — the
	// oblique routes around the image-scanner wall and the node-posture wall.
	// RAISED TO 54 (2026-08-30): Phase 1's reference-integrity additions — DanglingStorageClass,
	// DanglingIngressClass, DanglingPriorityClass and DanglingGoverningService. Each cleared through the
	// OVERLAP census (docs/qa/2026-08-30-phase1-overlap-census.md) against the shipped registry BEFORE it
	// was written, per F-2: a new rule overlapping a shipped rule's subject is a change to an existing
	// claim arriving sideways.
	// RAISED TO 55 (2026-08-30): PodNotReady, the overlap census's one kind-3 row — a different claim
	// about the same subject as condition-unchanged, separated by the time axis, with cross-references
	// in both directions so a reader does not count one problem twice.
	// RAISED TO 58 (2026-08-30): the declaration-validity family — ProbePortNotDeclared, DuplicateEnvVar
	// and ServiceTargetPortUndeclared, all overlap-empty rows from the Phase 1 census.
	// RAISED TO 61 (2026-08-30): the structure-and-ownership rules — SingleControlPlaneNode,
	// UnmanagedPod and PodCoveredByTwoPDBs.
	// RAISED TO 68 (2026-08-30): the last of Phase 1's buildable rows — ReplicasBelowDesired,
	// ContainerRestartTotal, ExternalTrafficPolicyConsequence, CronJobNoStartingDeadline,
	// DanglingBindingSubject, JobNoTTL and HPABurstExceedsAllocatable.
	// RAISED TO 71 (2026-08-30): Upgrade Preflight — DeprecatedAPIServed, CRDConversionWebhookUnbacked
	// and NodePoolCannotRoll.
	// RAISED TO 74 (2026-08-30): the temporal axis — AlertsFiring, ContainerThrottled and
	// ScrapeTargetsDown, the first rules in the registry that rest on the metrics source alone.
	// RAISED TO 79 (2026-09-10): SecretInEnvVar — a Secret reaching a container's environment, read from the
	// pod template's references and never from a Secret. Named as the highest-value unbuilt check in
	// docs/qa/2026-08-31-provider-benchmark-measurement.md §4.
	// RAISED TO 80 (2026-09-10): RBACBuiltinSubject — a binding naming system:masters, system:anonymous,
	// system:unauthenticated or system:authenticated. The same document's second-most-valuable group.
	// RAISED TO 81 (2026-10-19): NodeDrainUnmanaged — kubectl drain's own refusal of a pod no controller
	// manages, which the drain model had not checked; found by wiring the landing's per-node verdicts.
	// RAISED TO 82 (2026-10-27, v0.1.1): ClusterAdminUserOrGroup — cluster-admin bound to a User or a Group, which
	// no rule named until QA bound it to a person and the gate passed.
	const nonPSSTableRules = 82
	want := nonPSSTableRules + len(pssChecks)
	if want != 89 {
		t.Fatalf("expected 89 rules total (82 + %d pssChecks), arithmetic says %d", len(pssChecks), want)
	}
	if got := len(All()); got != want {
		t.Fatalf("registry has %d rules, want %d", got, want)
	}
	seen := map[string]bool{}
	for _, r := range All() {
		if r.ID() == "" || r.Version() == "" || seen[r.ID()] {
			t.Errorf("rule %q invalid or duplicate", r.ID())
		}
		seen[r.ID()] = true
	}
}

func TestFindingIDsDistinguishKinds(t *testing.T) {
	// A Deployment and a StatefulSet sharing ns/name must NOT collide —
	// duplicate IDs abort the whole audit at Validate().
	replicas := int32(2)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "redis", 2, nil)},
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "app"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "redis"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
				},
			},
		}},
	}
	fs := MissingRequests{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (deploy + sts), got %d", len(fs))
	}
	if fs[0].ID == fs[1].ID {
		t.Fatalf("Deployment and StatefulSet with same ns/name collided on ID %q", fs[0].ID)
	}
}
