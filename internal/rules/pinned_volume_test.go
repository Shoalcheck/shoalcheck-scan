package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// pinned_volume_test.go — THE VOLUME IS THE SUBJECT, AND THE PODS ARE WHAT IT PINS.
//
// B-138 was a duplicate finding ID: the key was (node, volume) while every sentence named one POD, so two
// pods on one pinned volume produced two findings under one ID and types.Validate rejected the whole
// document. The first fix appended the pod to the key, which stopped the crash and left a shape nobody
// intended — one card per pod for a constraint that belongs to the volume.
//
// The founder's decision, 2026-08-29: the original key was right and the TEXT was the defect. One finding
// per (node, volume); the pods and their owners belong in the evidence. That also removes the duplicate-ID
// failure at its cause rather than at its symptom — one volume produces one finding however many pods
// mount it.

func TestNodePinnedVolume_IsOneFindingPerVolumeHoweverManyPodsMountIt(t *testing.T) {
	inv := threePodsOneVolumeFixture()
	got := (NodePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("three pods on one pinned volume produced %d findings, want 1", len(got))
	}
	f := got[0]

	// The subject is the volume and the node.
	if !strings.Contains(f.Title, "pv-shared") || !strings.Contains(f.Title, "node-a") {
		t.Errorf("the title does not name the volume and the node: %q", f.Title)
	}

	// Every pod that mounts it is named, with its owner — the evidence carries what the collapsed cards
	// used to carry, so this changes the number of cards and never the number of facts.
	blob := strings.Join(f.Evidence, "\n")
	for _, pod := range []string{"sharer-7564fd4896-00", "sharer-7564fd4896-01", "sharer-7564fd4896-02"} {
		if !strings.Contains(blob, pod) {
			t.Errorf("evidence does not name pod %s:\n%s", pod, blob)
		}
	}
	if !strings.Contains(blob, "Deployment") || !strings.Contains(blob, "sharer") {
		t.Errorf("evidence does not name the owner:\n%s", blob)
	}
	// The count is in the text, not left to be inferred from a list.
	if !strings.Contains(blob, "3 pod") && !strings.Contains(f.Description, "3 pod") {
		t.Errorf("neither the description nor the evidence states how many pods mount it:\n%s\n%s",
			f.Description, blob)
	}

	// AffectedResources carries the node, the volume and every pod.
	kinds := map[string]int{}
	for _, r := range f.AffectedResources {
		kinds[r.Kind]++
	}
	if kinds["Node"] != 1 || kinds["PersistentVolume"] != 1 || kinds["Pod"] != 3 {
		t.Errorf("AffectedResources = %v, want 1 Node, 1 PersistentVolume, 3 Pods", kinds)
	}
}

// The version bump is asserted because Gate 2 (RuleChanged) is what stops a comparison across this change
// from reporting a mass of findings as "no longer present" when the shape changed underneath them.
func TestNodePinnedVolume_VersionMovedWithTheShape(t *testing.T) {
	if v := (NodePinnedVolume{}).Version(); v == "1.0.0" {
		t.Errorf("the finding shape changed from per-pod to per-volume and RuleVersion is still %q — a "+
			"comparison across this change would report every old finding as resolved", v)
	}
}

// A second volume on the same node is a second finding: the collapse is per volume, not per node.
func TestNodePinnedVolume_CollapsesPerVolumeAndNotPerNode(t *testing.T) {
	inv := threePodsOneVolumeFixture()
	addSecondPinnedVolume(inv)
	got := (NodePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 2 {
		t.Fatalf("two pinned volumes on one node produced %d findings, want 2", len(got))
	}
	if got[0].ID == got[1].ID {
		t.Errorf("two volumes share one finding ID: %s", got[0].ID)
	}
}

func TestNodePinnedVolume_StillSaysWhatItCannotKnow(t *testing.T) {
	f := (NodePinnedVolume{}).Evaluate(threePodsOneVolumeFixture(), Options{IncludeSystem: true})[0]
	blob := strings.ToLower(strings.Join(append([]string{f.Description, f.WhyItMatters}, f.Evidence...), "\n"))
	// The refusal that has been in this rule since Drain Preflight shipped must survive the reshape.
	if !strings.Contains(blob, "does not say") && !strings.Contains(blob, "not distinguish") {
		t.Errorf("the reshape dropped the sentence saying this evidence does not distinguish a tolerant "+
			"workload from an intolerant one:\n%s", blob)
	}
}

// ── fixture ─────────────────────────────────────────────────────────────────────────────────────

func threePodsOneVolumeFixture() *collect.Inventory {
	inv := repetitionFixture()
	return inv
}

func addSecondPinnedVolume(inv *collect.Inventory) {
	const node = "node-a"
	inv.PVs = append(inv.PVs, corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-second"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:    corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("5Gi")},
			ClaimRef:    &corev1.ObjectReference{Namespace: "app", Name: "second-claim"},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{node},
					}},
				}},
			}},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	})
	inv.PVCs = append(inv.PVCs, corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "second-claim"},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName:  "pv-second",
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("5Gi")}},
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	})
	for i := range inv.Pods {
		inv.Pods[i].Spec.Volumes = append(inv.Pods[i].Spec.Volumes, corev1.Volume{
			Name: "second", VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "second-claim"}}})
	}
	_ = appsv1.Deployment{}
	_ = types.Finding{}
}
