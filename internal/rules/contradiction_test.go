package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// contradiction_test.go — Sweep 4. Two things the operator DECLARED that cannot both be satisfied.
//
// The wording matters and it is the difference from Sweep 2: a dangling reference is a typo or a deletion,
// and a contradiction is two decisions that were each reasonable on their own. Nothing here is anyone's
// mistake, so nothing here says so.

// bannedContradictionPhrases — every phrase claims an OUTCOME. A contradiction between two declarations is
// a fact about the declarations; what it produces at runtime depends on scheduling, on timing, and on
// whether the situation the arithmetic describes has been reached yet.
var bannedContradictionPhrases = []string{
	"is broken", "is down", "has failed", "will crash", "will deadlock", "cannot run",
	"data loss", "corruption", "outage", "users cannot",
	"misconfigured", "mistake", "wrong", "should never",
	"guaranteed", "certainly", "always fails",
}

func TestContradiction_ClaimsTheDeclarationsAndNotTheOutcome(t *testing.T) {
	out := allContradictionFindings(contradictionFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, p := range bannedContradictionPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — two declarations disagreeing is the claim, and what that "+
					"produces at runtime is not in the snapshot:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestContradiction_NeverCarriesDollars(t *testing.T) {
	for _, f := range allContradictionFindings(contradictionFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f — a contradiction between declarations has no price",
				f.ID, f.DollarImpactMonthly)
		}
	}
}

// The structural denial property, per B-136: no finding may name a resource of a kind this reading did not
// read. Whole-rule silence is NOT the property here either — these rules join several lists, and losing one
// of them must not silence the claims resting on the others.
func TestContradiction_NeverSpeaksAboutADeniedKind(t *testing.T) {
	objectKind := map[string]string{
		"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet",
		"persistentvolumeclaims": "PersistentVolumeClaim", "poddisruptionbudgets": "PodDisruptionBudget",
		"horizontalpodautoscalers": "HorizontalPodAutoscaler", "pods": "Pod",
	}
	rules := []struct {
		name string
		eval func(*collect.Inventory) []types.Finding
		deps []string
	}{
		{"SharedRWOVolume", func(i *collect.Inventory) []types.Finding {
			return (SharedRWOVolume{}).Evaluate(i, Options{IncludeSystem: true})
		}, (SharedRWOVolume{}).RequiredKinds()},
		{"AutoscalerFloorBelowBudget", func(i *collect.Inventory) []types.Finding {
			return (AutoscalerFloorBelowBudget{}).Evaluate(i, Options{IncludeSystem: true})
		}, (AutoscalerFloorBelowBudget{}).RequiredKinds()},
	}
	for _, r := range rules {
		if got := r.eval(contradictionFixture()); len(got) == 0 {
			t.Fatalf("%s is silent on its own fixture, so denying a list below would prove nothing", r.name)
		}
		for _, kind := range r.deps {
			want, known := objectKind[kind]
			if !known {
				t.Fatalf("%s declares %q and this test has no object-kind mapping for it", r.name, kind)
			}
			inv := contradictionFixture()
			inv.Meta.Collected = withoutKind(inv.Meta.Collected, kind)
			inv.Meta.Denied = append(inv.Meta.Denied, kind+": forbidden")
			for _, f := range r.eval(inv) {
				for _, ref := range f.AffectedResources {
					if ref.Kind == want {
						t.Errorf("%s named %s %s/%s with the %s list denied", r.name, ref.Kind,
							ref.Namespace, ref.Name, kind)
					}
				}
			}
		}
	}
}

// THE FIVE WAYS SharedRWOVolume WOULD BE WRONG.
func TestSharedRWOVolume_TheWaysItWouldBeWrong(t *testing.T) {
	t.Run("one replica sharing one volume is not sharing", func(t *testing.T) {
		inv := healthyContradictionFixture()
		inv.PVCs = append(inv.PVCs, rwoPVC("app", "single-data"))
		inv.Deployments = append(inv.Deployments, deployWithClaim("app", "single-writer", 1, "single-data"))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a StatefulSet's volumeClaimTemplates give each pod its own claim", func(t *testing.T) {
		// The controller synthesises the pod's volume from the template, so the POD TEMPLATE never names
		// the claim. Walking spec.template.spec.volumes is therefore correct by construction — this test
		// exists because that correctness is structural and invisible, and a later refactor that started
		// reading volumeClaimTemplates would report every StatefulSet in existence.
		inv := healthyContradictionFixture()
		inv.PVCs = append(inv.PVCs, rwoPVC("app", "data-ledger-0"), rwoPVC("app", "data-ledger-1"))
		inv.StatefulSets = append(inv.StatefulSets, appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "ledger"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: ptr32(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "ledger"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "db:1"}}},
				},
				VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{
					ObjectMeta: metav1.ObjectMeta{Name: "data"},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}},
				}},
			},
		})
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a claim that also allows ReadWriteMany can be mounted from many nodes", func(t *testing.T) {
		inv := healthyContradictionFixture()
		pvc := rwoPVC("app", "shared-cache")
		pvc.Spec.AccessModes = append(pvc.Spec.AccessModes, corev1.ReadWriteMany)
		inv.PVCs = append(inv.PVCs, pvc)
		inv.Deployments = append(inv.Deployments, deployWithClaim("app", "cache", 4, "shared-cache"))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a claim with no accessModes recorded is unknown, not ReadWriteOnce", func(t *testing.T) {
		inv := healthyContradictionFixture()
		pvc := rwoPVC("app", "untyped")
		pvc.Spec.AccessModes = nil
		inv.PVCs = append(inv.PVCs, pvc)
		inv.Deployments = append(inv.Deployments, deployWithClaim("app", "untyped-user", 3, "untyped"))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a DaemonSet that selects one node has one pod, which shares nothing", func(t *testing.T) {
		// B-142, FOUND BY §8.1'S ADVERSARIAL PASS, SEV-1. The first version treated every DaemonSet as
		// "many pods" because a DaemonSet's replica count is -1 by convention. A DaemonSet with a
		// nodeSelector matching one node — a GPU node, a dedicated ingress node — runs exactly one pod and
		// shares nothing, and on a SINGLE-NODE CLUSTER every DaemonSet with a volume would have fired.
		// B-133's shape exactly: reading a field correctly and reporting something false.
		inv := healthyContradictionFixture()
		inv.PVCs = append(inv.PVCs, rwoPVC("app", "gpu-cache"))
		inv.DaemonSets = append(inv.DaemonSets, dsWithClaim("app", "gpu-agent", "gpu-cache", 1))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a DaemonSet the controller placed on several nodes does share", func(t *testing.T) {
		// The paired positive, so the guard above cannot be satisfied by silencing DaemonSets entirely.
		inv := healthyContradictionFixture()
		inv.PVCs = append(inv.PVCs, rwoPVC("app", "agent-cache"))
		inv.DaemonSets = append(inv.DaemonSets, dsWithClaim("app", "agent", "agent-cache", 5))
		if got := (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 1 {
			t.Errorf("a DaemonSet on five nodes shares one ReadWriteOnce claim; got %d findings", len(got))
		}
	})

	t.Run("a DaemonSet whose controller has not written a count yet is unknown", func(t *testing.T) {
		inv := healthyContradictionFixture()
		inv.PVCs = append(inv.PVCs, rwoPVC("app", "new-cache"))
		inv.DaemonSets = append(inv.DaemonSets, dsWithClaim("app", "brand-new", "new-cache", 0))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a claim this reading did not find has no mode to read", func(t *testing.T) {
		inv := healthyContradictionFixture()
		inv.Deployments = append(inv.Deployments, deployWithClaim("app", "ghost-user", 3, "not-collected"))
		assertSilent(t, (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
}

// THE FIVE WAYS AutoscalerFloorBelowBudget WOULD BE WRONG.
func TestAutoscalerFloorBelowBudget_TheWaysItWouldBeWrong(t *testing.T) {
	t.Run("a percentage budget scales with the workload", func(t *testing.T) {
		// minAvailable: 50% resolves against however many pods exist, so it cannot contradict a FLOOR by
		// arithmetic — at two replicas it demands one, at ten it demands five. A rule that resolved the
		// percentage against the floor and compared would fire on every proportional budget in existence.
		//
		// THE FLOOR IS ZERO HERE ON PURPOSE, AND THE FIRST VERSION OF THIS TEST WAS VACUOUS WITHOUT IT.
		// intstr.IntValue() returns 0 for "50%", so at any floor above zero the comparison `floor > 0`
		// short-circuits and the case passes whether the type guard exists or not — verified by removing
		// the guard and watching the test still pass. At floor zero the accident stops helping and the
		// guard is the only thing standing between this rule and every proportional budget in existence.
		inv := healthyContradictionFixture()
		pct := intstr.FromString("50%")
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &pct, nil))
		h := hpaFor("app", "api-hpa", "api", 0)
		inv.HPAs = append(inv.HPAs, h)
		assertSilent(t, (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("an autoscaler that may reach zero contradicts any integer budget", func(t *testing.T) {
		// The counterpart to the case above, and the reason it can use a zero floor without the assertion
		// becoming meaningless: with an INTEGER budget, a floor of zero is the strongest contradiction
		// this rule can find, and it must fire.
		inv := healthyContradictionFixture()
		ma := intstr.FromInt32(2)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
		inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 0))
		if got := (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 1 {
			t.Errorf("a floor of zero under a budget of two is the strongest form of this contradiction; "+
				"got %d findings", len(got))
		}
	})

	t.Run("a maxUnavailable budget cannot be contradicted by a floor", func(t *testing.T) {
		inv := healthyContradictionFixture()
		mu := intstr.FromInt32(1)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", nil, &mu))
		inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 1))
		assertSilent(t, (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a budget covering two workloads has a denominator this rule cannot compute", func(t *testing.T) {
		// B-098 IS THE PRECEDENT: the denominator of a budget is the SET of pods it selects, not one
		// workload. Two workloads behind one budget means the floor at which it binds is the SUM of their
		// floors, and only one of them may have an autoscaler at all. Silence, rather than arithmetic over
		// half the inputs.
		inv := healthyContradictionFixture()
		inv.Deployments = append(inv.Deployments, appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-canary"},
			Spec: appsv1.DeploymentSpec{Replicas: ptr32(4), Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "api:1"}}},
			}},
		})
		ma := intstr.FromInt32(3)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
		inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 2))
		assertSilent(t, (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a bare pod behind the same budget raises a denominator this rule did not count", func(t *testing.T) {
		// B-143, FOUND BY §8.1. workloadsMatching counts WORKLOADS, so a pod carrying the budget's labels
		// with no controller at all was invisible to the denominator check — and at the autoscaler's floor
		// that pod still counts toward minAvailable, so the budget may be perfectly satisfiable. Same
		// lesson as B-098, one level further down: the denominator is the set of PODS the selector
		// matches, and a workload is only the usual way to produce them.
		inv := healthyContradictionFixture()
		ma := intstr.FromInt32(3)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
		inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 2))
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api-legacy-pinned",
				Labels: map[string]string{"app": "api"}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
		assertSilent(t, (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a floor above the budget is the ordinary correct case", func(t *testing.T) {
		inv := healthyContradictionFixture()
		ma := intstr.FromInt32(2)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
		inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 5))
		assertSilent(t, (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("an autoscaler with no minReplicas floors at one", func(t *testing.T) {
		// An unset minReplicas defaults to 1 at the API server, so a budget of minAvailable=1 over it IS a
		// contradiction. Reading nil as "no floor" would miss the tightest case there is.
		inv := healthyContradictionFixture()
		ma := intstr.FromInt32(1)
		inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
		h := hpaFor("app", "api-hpa", "api", 1)
		h.Spec.MinReplicas = nil
		inv.HPAs = append(inv.HPAs, h)
		if got := (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 1 {
			t.Errorf("an unset minReplicas defaults to 1 and must be read as 1; got %d findings", len(got))
		}
	})
}

func TestContradiction_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := contradictionFixture()
	for _, c := range []struct {
		name string
		got  []types.Finding
	}{
		{"SharedRWOVolume", (SharedRWOVolume{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"AutoscalerFloorBelowBudget", (AutoscalerFloorBelowBudget{}).Evaluate(inv, Options{IncludeSystem: true})},
	} {
		if len(c.got) == 0 {
			t.Errorf("%s found nothing on a fixture built to make it fire", c.name)
		}
	}
}

func TestContradiction_AConsistentClusterProducesNothing(t *testing.T) {
	for _, f := range allContradictionFindings(healthyContradictionFixture()) {
		t.Errorf("a cluster whose declarations agree produced %s: %s", f.RuleID, f.Title)
	}
}

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

func assertSilent(t *testing.T, got []types.Finding) {
	t.Helper()
	if len(got) != 0 {
		t.Errorf("expected silence, got %d finding(s); first: %s", len(got), got[0].Title)
	}
}

func ptr32(i int32) *int32 { return &i }

func rwoPVC(ns, name string) corev1.PersistentVolumeClaim {
	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}},
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
}

func deployWithClaim(ns, name string, replicas int32, claim string) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr32(replicas),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c", Image: "app:1",
						VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}}},
					Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}},
				},
			},
		},
	}
}

// dsWithClaim builds a DaemonSet mounting one shared claim, with the controller's own count of how many
// nodes it wants a pod on.
func dsWithClaim(ns, name, claim string, desired int32) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c", Image: "agent:1",
						VolumeMounts: []corev1.VolumeMount{{Name: "d", MountPath: "/d"}}}},
					Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}},
				},
			},
		},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: desired, NumberReady: desired},
	}
}

func pdbFor(ns, name, app string, minAvail, maxUnavail *intstr.IntOrString) policyv1.PodDisruptionBudget {
	return policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable:   minAvail,
			MaxUnavailable: maxUnavail,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
		},
	}
}

func hpaFor(ns, name, target string, minReplicas int32) autoscalingv2.HorizontalPodAutoscaler {
	return autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			MinReplicas: ptr32(minReplicas),
			MaxReplicas: 20,
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1", Kind: "Deployment", Name: target},
		},
	}
}

func contradictionKinds() []string {
	return []string{"deployments", "statefulsets", "daemonsets", "persistentvolumeclaims",
		"poddisruptionbudgets", "horizontalpodautoscalers", "pods"}
}

func healthyContradictionFixture() *collect.Inventory {
	return &collect.Inventory{
		Meta: collect.Meta{Collected: contradictionKinds(), StartedAt: fixedReading},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"},
			Spec: appsv1.DeploymentSpec{Replicas: ptr32(6), Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "api:1"}}},
			}},
		}},
	}
}

func contradictionFixture() *collect.Inventory {
	inv := healthyContradictionFixture()
	// SharedRWOVolume: three replicas of one Deployment mounting one ReadWriteOnce claim by name.
	inv.PVCs = append(inv.PVCs, rwoPVC("app", "uploads"))
	inv.Deployments = append(inv.Deployments, deployWithClaim("app", "uploader", 3, "uploads"))
	// AutoscalerFloorBelowBudget: the budget demands three and the autoscaler may go to two.
	ma := intstr.FromInt32(3)
	inv.PDBs = append(inv.PDBs, pdbFor("app", "api-pdb", "api", &ma, nil))
	inv.HPAs = append(inv.HPAs, hpaFor("app", "api-hpa", "api", 2))
	return inv
}

func allContradictionFindings(inv *collect.Inventory) []types.Finding {
	opts := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (SharedRWOVolume{}).Evaluate(inv, opts)...)
	out = append(out, (AutoscalerFloorBelowBudget{}).Evaluate(inv, opts)...)
	return out
}
