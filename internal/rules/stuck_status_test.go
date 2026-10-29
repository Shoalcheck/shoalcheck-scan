package rules

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// stuck_status_test.go — the tests for Sweep 3's spec-versus-status family.
//
// This family reads `status`, which is controller-owned and may be stale, so its tests carry two things
// no other family's do: a phrase list that forbids turning an observation into a duration, and a set of
// adversarial cases where the field is read CORRECTLY and the obvious conclusion is false.

// bannedStuckPhrases — every phrase here converts "this condition has read X since T" into a claim about
// what has been happening in between, and the snapshot cannot support any of them.
//
// The reason is in Sweep 3 §4: a condition's lastTransitionTime says when the controller last CHANGED ITS
// MIND, not how long the underlying situation has lasted — and a controller that stopped running leaves a
// stale timestamp that looks exactly like a stable one.
var bannedStuckPhrases = []string{
	"has been down for", "has been broken for", "has been failing for", "down for", "broken for",
	"outage", "downtime", "users cannot", "traffic is", "is unavailable to",
	"will fail", "will not recover", "is stuck forever", "never recovered",
	"guaranteed", "certainly", "must have been", "obviously",
}

func TestStuckStatus_ClaimsAnObservationAndNeverADuration(t *testing.T) {
	out := allStuckFindings(t, stuckFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, p := range bannedStuckPhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — status is controller-owned and may be stale; the supportable "+
					"form names both times and stops:\n%s", f.ID, p, blob)
			}
		}
	}
}

// BOTH TIMES, NAMED. Sweep 3 §4 fixes the supportable sentence shape exactly: "this condition has read X
// since T, and this reading was taken at T+n". A finding that names the transition without the reading is
// asserting a duration by implication.
func TestStuckCondition_NamesTheTransitionAndTheReading(t *testing.T) {
	out := (StuckCondition{}).Evaluate(stuckFixture(), Options{IncludeSystem: true})
	if len(out) == 0 {
		t.Fatal("no findings, so nothing was checked")
	}
	for _, f := range out {
		blob := strings.Join(f.Evidence, "\n")
		if !strings.Contains(blob, "lastTransitionTime") {
			t.Errorf("finding %s never names the transition time:\n%s", f.ID, blob)
		}
		if !strings.Contains(blob, "reading taken") {
			t.Errorf("finding %s never names when the reading was taken, so its age claim floats free:\n%s", f.ID, blob)
		}
	}
}

func TestStuckStatus_NeverCarryDollars(t *testing.T) {
	for _, f := range allStuckFindings(t, stuckFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f — a controller's status field has no price", f.ID, f.DollarImpactMonthly)
		}
	}
}

// THE DENIAL GUARD, AND IT IS A DIFFERENT GUARD FROM THE ONE THE PREVIOUS FAMILY NEEDED.
//
// The first version of this test asserted whole-rule silence — deny any one of StuckCondition's four
// kinds and the rule must say nothing at all — copied from dangling_test.go, where that IS the property.
// It failed, and it was wrong to assert. THIRTEENTH ASSERTION-SCOPING ERROR OF THE SESSION, and this one
// had a written answer sitting in the same package the whole time:
//
//	deps.go:26 — "This list gates the COMPARISON, not the run. Gating the run would mean a rule that walks
//	Deployments, StatefulSets and DaemonSets loses its real Deployment findings when only DaemonSets was
//	denied."
//
// The two families need different guards because their claims have different shapes. dangling.go asserts
// "X names Y and Y is not in the list", so a denied list FABRICATES the absence and the whole rule must
// fall silent. This family asserts "this field on this object reads X", and a denied pods list cannot make
// a Namespace's condition wrong. The property here is narrower and structural: NO FINDING MAY NAME A
// RESOURCE OF A KIND THIS READING DID NOT READ. For the two single-kind rules it reduces to total silence,
// which is asserted below by the same code rather than by a second copy of it.
func TestStuckStatus_NeverSpeaksAboutADeniedKind(t *testing.T) {
	// The kind name a collector step reads, and the Kind string its objects carry in AffectedResources.
	objectKind := map[string]string{
		"nodes": "Node", "namespaces": "Namespace", "deployments": "Deployment", "pods": "Pod",
		"daemonsets": "DaemonSet", "persistentvolumeclaims": "PersistentVolumeClaim",
	}
	rules := []struct {
		name string
		eval func(*collect.Inventory) []types.Finding
		deps []string
	}{
		{"StuckCondition",
			func(i *collect.Inventory) []types.Finding {
				return (StuckCondition{}).Evaluate(i, Options{IncludeSystem: true})
			}, (StuckCondition{}).RequiredKinds()},
		{"DaemonSetMisscheduled",
			func(i *collect.Inventory) []types.Finding {
				return (DaemonSetMisscheduled{}).Evaluate(i, Options{IncludeSystem: true})
			}, (DaemonSetMisscheduled{}).RequiredKinds()},
		{"VolumeExpansionIncomplete",
			func(i *collect.Inventory) []types.Finding {
				return (VolumeExpansionIncomplete{}).Evaluate(i, Options{IncludeSystem: true})
			}, (VolumeExpansionIncomplete{}).RequiredKinds()},
	}
	for _, r := range rules {
		if got := r.eval(stuckFixture()); len(got) == 0 {
			t.Fatalf("%s is silent on the fixture that plants its positive, so denying a list below "+
				"would prove nothing", r.name)
		}
		for _, kind := range r.deps {
			want, known := objectKind[kind]
			if !known {
				t.Fatalf("%s declares %q and this test has no object-kind mapping for it, so the "+
					"assertion below would pass without checking anything", r.name, kind)
			}
			inv := stuckFixture()
			inv.Meta.Collected = withoutKind(inv.Meta.Collected, kind)
			inv.Meta.Denied = append(inv.Meta.Denied, kind+": forbidden")
			for _, f := range r.eval(inv) {
				for _, ref := range f.AffectedResources {
					if ref.Kind == want {
						t.Errorf("%s named %s %s/%s with the %s list denied — it spoke about a list it "+
							"did not read", r.name, ref.Kind, ref.Namespace, ref.Name, kind)
					}
				}
			}
		}
	}
}

// The pod half of StuckCondition resolves a pod's owner up to its Deployment, so it declares `deployments`
// as a dependency without producing Deployment-kinded findings from that list. The guard above cannot see
// that, so the grouping degradation is asserted here on its own terms: with deployments denied, the pods
// are still reported, grouped by the ReplicaSet the reading could actually see.
func TestStuckCondition_LosingTheDeploymentListDegradesTheGroupingAndNotTheFinding(t *testing.T) {
	inv := stuckFixture()
	inv.Pods = append(inv.Pods, unschedulablePod("api-7d9f-aaa"), unschedulablePod("api-7d9f-bbb"))
	full := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true})

	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "deployments")
	inv.Meta.Denied = append(inv.Meta.Denied, "deployments: forbidden")
	degraded := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true})

	countPods := func(fs []types.Finding) int {
		n := 0
		for _, f := range fs {
			for _, ref := range f.AffectedResources {
				if ref.Kind == "Pod" {
					n++
				}
			}
		}
		return n
	}
	if countPods(full) != 2 {
		t.Fatalf("the fixture did not produce the two planted pods (%d), so the comparison below is empty",
			countPods(full))
	}
	if got := countPods(degraded); got != 2 {
		t.Errorf("denying the deployment list dropped pod findings: %d, want 2 — the pods were read, only "+
			"the name to group them under was not", got)
	}

	// AND THE GROUPING MUST ACTUALLY HAVE DEGRADED. Without this half the test asserts 2 == 2 against two
	// identical runs and would pass with the dependency ignored entirely — which is what the first version
	// did, because a denial faked in Meta leaves inv.Deployments populated and podGroup was resolving the
	// Deployment name from a list it had just declared unread.
	label := func(fs []types.Finding) string {
		for _, f := range fs {
			for _, ref := range f.AffectedResources {
				if ref.Kind == "Pod" && strings.HasPrefix(ref.Name, "api-7d9f") {
					return f.Title
				}
			}
		}
		return ""
	}
	if got := label(full); !strings.Contains(got, "Deployment app/api") {
		t.Errorf("with every list read, the pods were not grouped under their Deployment: %q", got)
	}
	if got := label(degraded); !strings.Contains(got, "ReplicaSet app/api-7d9f") {
		t.Errorf("with deployments denied, the group should fall back to the ReplicaSet the reading could "+
			"see, and instead the title was %q", got)
	}
}

// THE FIVE WAYS THIS FAMILY WOULD BE WRONG.
//
// Each case is a status field read CORRECTLY, where the obvious conclusion is false. This is B-133's
// standard: the DaemonSet nodeAffinity was read faithfully and the finding was still nonsense.
func TestStuckStatus_TheFiveWaysThisFamilyWouldBeWrong(t *testing.T) {
	old := metav1.NewTime(fixedReading.Add(-90 * 24 * time.Hour))

	t.Run("a Deployment scaled to zero is Available=False on purpose", func(t *testing.T) {
		inv := healthyStuckFixture()
		zero := int32(0)
		inv.Deployments = append(inv.Deployments, appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "paused-batch", Namespace: "app"},
			Spec:       appsv1.DeploymentSpec{Replicas: &zero},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, LastTransitionTime: old},
			}},
		})
		if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("reported a deliberately scaled-to-zero Deployment: %s", got[0].Title)
		}
	})

	t.Run("a Succeeded pod is Ready=False by design", func(t *testing.T) {
		inv := healthyStuckFixture()
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "backup-27438-xk2", Namespace: "app"},
			Status: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
				Conditions: []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionFalse, LastTransitionTime: old},
					{Type: corev1.ContainersReady, Status: corev1.ConditionFalse, LastTransitionTime: old},
				},
			},
		})
		if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("reported a completed pod, which every finished Job leaves behind: %s", got[0].Title)
		}
	})

	t.Run("an absent condition is unknown, never false", func(t *testing.T) {
		inv := healthyStuckFixture()
		inv.Nodes = append(inv.Nodes, corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-no-status"},
			// No conditions at all: a Node object whose kubelet has not reported yet, or a kind of node
			// this reading caught early. Zero value is UNKNOWN, and §2's discipline forbids reading it
			// as the unhealthy value.
		})
		if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("read a missing condition as an unhealthy one: %s", got[0].Title)
		}
	})

	t.Run("a condition with no lastTransitionTime cannot be aged", func(t *testing.T) {
		inv := healthyStuckFixture()
		inv.Nodes = append(inv.Nodes, corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-untimed"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
			}},
		})
		if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("claimed an age it could not read: %s", got[0].Title)
		}
	})

	t.Run("a PVC that is not Bound has no status.capacity to fall short of", func(t *testing.T) {
		inv := healthyStuckFixture()
		inv.PVCs = append(inv.PVCs, corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "waiting-claim", Namespace: "app"},
			Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("50Gi")},
			}},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
		})
		if got := (VolumeExpansionIncomplete{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("compared a request against a capacity that was never written: %s", got[0].Title)
		}
	})
}

// ONE OWNER PER FACT. Three rules already read specific conditions — silent_failures.go owns the HPA's
// ScalingLimited, pdb_blocks_drains.go owns disruptionsAllowed, rollout_preflight.go owns Node readiness
// for its own placement question. A general rule that also reported them would state one problem twice, at
// two severities, and a reader who sees that trusts neither.
func TestStuckCondition_LeavesConditionsAnotherRuleOwns(t *testing.T) {
	old := metav1.NewTime(fixedReading.Add(-90 * 24 * time.Hour))
	inv := healthyStuckFixture()
	inv.HPAs = append(inv.HPAs, autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "api-hpa", Namespace: "app"},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: "ScalingLimited", Status: corev1.ConditionTrue, LastTransitionTime: old},
			},
		},
	})
	if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
		t.Errorf("re-reported a condition silent_failures.go already owns: %s", got[0].Title)
	}
}

// A recent transition is not a stuck one — the whole family turns on the difference.
func TestStuckCondition_ARecentTransitionIsNotStuck(t *testing.T) {
	inv := healthyStuckFixture()
	inv.Nodes = append(inv.Nodes, corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-rebooting"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionFalse,
				LastTransitionTime: metav1.NewTime(fixedReading.Add(-3 * time.Minute))},
		}},
	})
	if got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
		t.Errorf("reported a node that went NotReady three minutes ago: %s", got[0].Title)
	}
}

// A provisioner that rounds UP gave more than was asked for, which is not a shortfall.
func TestVolumeExpansion_RoundingUpIsNotAShortfall(t *testing.T) {
	inv := healthyStuckFixture()
	inv.PVCs = append(inv.PVCs, corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "rounded-claim", Namespace: "app"},
		Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("3Gi")},
		}},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase:    corev1.ClaimBound,
			Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("4Gi")},
		},
	})
	if got := (VolumeExpansionIncomplete{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
		t.Errorf("read a rounded-up allocation as a shortfall: %s", got[0].Title)
	}
}

// B-141 — THE CLAIM AUDIT'S OWN FINDING, and no word list could have caught it.
//
// On a real AKS cluster this rule produced: "Cluster linen/pgsql-linen has read Ready=False since ...",
// with evidence "Cluster linen/pgsql-linen: status.conditions[Ready].status = False". Every word passed the
// banned-phrase test. The sentence is still false: what was read was a POD's condition, and "Cluster
// linen/pgsql-linen" is a CloudNativePG custom resource this product does not collect at all — its name was
// borrowed as a grouping label and then written as if it were the subject whose field we read.
//
// A reader would conclude we read that Cluster's status. We did not, and we cannot: it is a CRD outside
// RequiredKinds. THE OBJECT NAMED IN A `status.<field> = <value>` SENTENCE MUST BE THE OBJECT THE FIELD WAS
// READ FROM. The owner may appear as context and never as the subject.
func TestStuckCondition_NamesTheObjectItReadTheFieldFrom(t *testing.T) {
	yes := true
	old := metav1.NewTime(fixedReading.Add(-60 * 24 * time.Hour))
	inv := healthyStuckFixture()
	// A pod owned by a custom resource kind this product does not collect — the shape found on AKS.
	inv.Pods = append(inv.Pods, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "linen", Name: "pgsql-linen-1",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "postgresql.cnpg.io/v1", Kind: "Cluster", Name: "pgsql-linen", Controller: &yes,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse, LastTransitionTime: old,
				Reason: "ContainersNotReady"},
		}},
	})
	got := (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("expected the planted pod condition, got %d findings", len(got))
	}
	f := got[0]
	for _, e := range f.Evidence {
		if !strings.Contains(e, "status.conditions[") {
			continue
		}
		// The sentence that quotes a field must name the pod the field came from.
		if !strings.Contains(e, "pgsql-linen-1") {
			t.Errorf("the evidence quotes a status field against an object it was not read from:\n  %s", e)
		}
	}
	if !strings.Contains(f.Title, "pod") && !strings.Contains(f.Title, "Pod") {
		t.Errorf("the title makes a custom resource the subject of a pod's condition: %q", f.Title)
	}
}

func TestStuckStatus_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := stuckFixture()
	for _, c := range []struct {
		name string
		got  []types.Finding
	}{
		{"StuckCondition", (StuckCondition{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"DaemonSetMisscheduled", (DaemonSetMisscheduled{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"VolumeExpansionIncomplete", (VolumeExpansionIncomplete{}).Evaluate(inv, Options{IncludeSystem: true})},
	} {
		if len(c.got) == 0 {
			t.Errorf("%s found nothing on a fixture built to make it fire", c.name)
		}
	}
}

func TestStuckStatus_AHealthyClusterProducesNothing(t *testing.T) {
	for _, f := range allStuckFindings(t, healthyStuckFixture()) {
		t.Errorf("a cluster whose controllers all agree produced %s: %s", f.RuleID, f.Title)
	}
}

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

// fixedReading pins the reading time so an age comparison is deterministic. Every fixture below sets
// Meta.StartedAt to it, and readingTime() reads that rather than the wall clock.
var fixedReading = time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)

func stuckStatusKinds() []string {
	return []string{"nodes", "namespaces", "deployments", "statefulsets", "daemonsets", "pods",
		"persistentvolumeclaims", "horizontalpodautoscalers"}
}

func healthyStuckFixture() *collect.Inventory {
	one := int32(1)
	recent := metav1.NewTime(fixedReading.Add(-2 * time.Hour))
	return &collect.Inventory{
		Meta: collect.Meta{Collected: stuckStatusKinds(), StartedAt: fixedReading},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: recent},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse, LastTransitionTime: recent},
			}},
		}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app"}}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "app"},
			Spec:       appsv1.DeploymentSpec{Replicas: &one},
			Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, LastTransitionTime: recent},
			}},
		}},
		DaemonSets: []appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "log-agent", Namespace: "app"},
			Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberReady: 1},
		}},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "app"},
			Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			}},
			Status: corev1.PersistentVolumeClaimStatus{
				Phase:    corev1.ClaimBound,
				Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			},
		}},
	}
}

// stuckFixture plants exactly one positive per rule, on top of the healthy one.
func stuckFixture() *collect.Inventory {
	inv := healthyStuckFixture()
	old := metav1.NewTime(fixedReading.Add(-45 * 24 * time.Hour))

	// StuckCondition: a namespace that has been Terminating since six weeks ago, held by a finalizer.
	inv.Namespaces = append(inv.Namespaces, corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-reporting"},
		Status: corev1.NamespaceStatus{
			Phase: corev1.NamespaceTerminating,
			Conditions: []corev1.NamespaceCondition{
				{Type: corev1.NamespaceFinalizersRemaining, Status: corev1.ConditionTrue,
					LastTransitionTime: old, Reason: "SomeFinalizersRemain"},
			},
		},
	})

	// DaemonSetMisscheduled: the controller wrote down that pods are running where they should not be.
	inv.DaemonSets = append(inv.DaemonSets, appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "gpu-plugin", Namespace: "app"},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: 3, NumberReady: 3, NumberMisscheduled: 2,
		},
	})

	// VolumeExpansionIncomplete: a Bound claim that asked for 100Gi and holds 20Gi.
	inv.PVCs = append(inv.PVCs, corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics-store", Namespace: "app"},
		Spec: corev1.PersistentVolumeClaimSpec{Resources: corev1.VolumeResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Gi")},
		}},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase:    corev1.ClaimBound,
			Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("20Gi")},
			Conditions: []corev1.PersistentVolumeClaimCondition{
				{Type: corev1.PersistentVolumeClaimResizing, Status: corev1.ConditionTrue,
					LastTransitionTime: old},
			},
		},
	})
	return inv
}

// unschedulablePod is a pod owned by a ReplicaSet of Deployment "api", PodScheduled=False since long ago.
func unschedulablePod(name string) corev1.Pod {
	yes := true
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app", OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "api-7d9f", Controller: &yes},
		}},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable",
				LastTransitionTime: metav1.NewTime(fixedReading.Add(-30 * 24 * time.Hour)),
			}},
		},
	}
}

func allStuckFindings(t *testing.T, inv *collect.Inventory) []types.Finding {
	t.Helper()
	opts := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (StuckCondition{}).Evaluate(inv, opts)...)
	out = append(out, (DaemonSetMisscheduled{}).Evaluate(inv, opts)...)
	out = append(out, (VolumeExpansionIncomplete{}).Evaluate(inv, opts)...)
	return out
}
