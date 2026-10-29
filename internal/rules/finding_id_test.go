package rules

import (
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// finding_id_test.go — B-138. A DUPLICATE FINDING ID DOES NOT PRODUCE A WRONG REPORT, IT PRODUCES NO
// REPORT AT ALL.
//
// types.Validate rejects the assembled document, and cmd/shoalcheck treats that as a bug and exits. So a rule
// whose ID does not vary with everything its TITLE varies on takes the whole product down on any cluster
// carrying the shape — and until this file existed, nothing in `make ci` could see it. The golden fixture
// goes through validation, but only contains shapes someone thought to plant.
//
// FOUND ON A LIVE CLUSTER, NOT BY A TEST: three replicas sharing one ReadWriteOnce local volume, planted to
// exercise SharedRWOVolume, and `shoalcheck audit` refused to produce a document. ReadWriteOnce permits one NODE
// and many pods, so several pods on one pinned volume is ordinary rather than exotic.
//
// The fixture below is built for repetition on purpose — several pods per owner, several pods per volume,
// several replicas per claim — because that is the only shape that can expose an ID keyed on too little.
func TestFindingIDs_AreUniqueAcrossTheWholeRegistry(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	inv := repetitionFixture()
	type where struct{ rule, title string }
	seen := map[string]where{}
	total := 0
	for _, r := range All() {
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			total++
			if prev, dup := seen[f.ID]; dup {
				t.Errorf("duplicate finding ID %s — types.Validate rejects the document and the audit "+
					"produces nothing at all:\n  A: %s | %s\n  B: %s | %s",
					f.ID, prev.rule, prev.title, r.ID(), f.Title)
				continue
			}
			seen[f.ID] = where{r.ID(), f.Title}
		}
	}
	if total < 10 {
		t.Fatalf("the fixture produced %d findings, which is too few for this to have checked anything",
			total)
	}
	t.Logf("%d findings, %d distinct IDs", total, len(seen))
}

// repetitionFixture is a small cluster whose every shape is REPEATED: one owner with several pods, one
// volume mounted by several pods, one claim shared by several replicas. Nothing here is meant to be
// realistic — it exists so that any rule whose ID omits part of what its finding is about collides.
func repetitionFixture() *collect.Inventory {
	const node = "node-a"
	yes := true
	replicas := int32(3)

	inv := &collect.Inventory{
		Meta: collect.Meta{
			Collected: []string{"nodes", "namespaces", "deployments", "statefulsets", "daemonsets", "pods",
				"services", "endpointslices", "persistentvolumes", "persistentvolumeclaims",
				"poddisruptionbudgets", "horizontalpodautoscalers", "resourcequotas", "limitranges",
				"networkpolicies", "ingresses", "cronjobs", "serviceaccounts", "roles", "rolebindings",
				"clusterroles", "clusterrolebindings"},
			StartedAt: fixedReading,
		},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: node, Labels: map[string]string{
				"kubernetes.io/hostname":           node,
				"topology.kubernetes.io/zone":      "eu-central-1a",
				"node.kubernetes.io/instance-type": "m6i.xlarge",
			}},
			Spec: corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/i-0abc"},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi")},
				Capacity: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi")},
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(fixedReading)}},
			},
		}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app"}}},
		// ONE PersistentVolume PINNED TO ONE NODE, mounted by every pod below. This is the shape that
		// found B-138 on a live cluster.
		PVs: []corev1.PersistentVolume{{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-shared"},
			Spec: corev1.PersistentVolumeSpec{
				Capacity:    corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
				ClaimRef:    &corev1.ObjectReference{Namespace: "app", Name: "shared-claim"},
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "kubernetes.io/hostname",
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{node},
						}},
					}},
				}},
			},
			Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
		}},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "shared-claim"},
			Spec: corev1.PersistentVolumeClaimSpec{
				VolumeName:  "pv-shared",
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}},
			},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound,
				Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}},
		}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "sharer"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "sharer"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "sharer"}},
					Spec:       sharerPodSpec(),
				},
			},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "sharer"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "sharer"}},
		}},
	}

	// THREE pods, one owner, one volume — every per-pod loop in the tree runs three times over inputs
	// that differ only in the pod's own name.
	for i := 0; i < 3; i++ {
		inv.Pods = append(inv.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "app", Name: fmt.Sprintf("sharer-7564fd4896-%02d", i),
				Labels: map[string]string{"app": "sharer"},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "sharer-7564fd4896", Controller: &yes,
				}},
			},
			Spec: sharerPodSpec(),
			Status: corev1.PodStatus{Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(fixedReading)}}},
		})
	}
	for i := range inv.Pods {
		inv.Pods[i].Spec.NodeName = node
	}
	return inv
}

func sharerPodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		Containers: []corev1.Container{{
			Name: "c", Image: "app:latest",
			VolumeMounts: []corev1.VolumeMount{{Name: "shared", MountPath: "/data"}},
		}},
		Volumes: []corev1.Volume{{Name: "shared", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "shared-claim"}}}},
	}
}
