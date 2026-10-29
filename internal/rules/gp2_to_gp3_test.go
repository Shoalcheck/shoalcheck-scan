package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

// gp2PV builds a bound AWS EBS PersistentVolume of the given size on the given class.
func gp2PV(name, class string, gib int64) corev1.PersistentVolume {
	return corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: class,
			Capacity:         corev1.ResourceList{corev1.ResourceStorage: *resource.NewQuantity(gib*1024*1024*1024, resource.BinarySI)},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com", VolumeHandle: "vol-" + name},
			},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
}

func awsClass(name, volType string) storagev1.StorageClass {
	return storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: name},
		Provisioner: "ebs.csi.aws.com",
		Parameters:  map[string]string{"type": volType},
	}
}

// TestGp2ToGp3_ThePriceIsTheDIFFERENCE is the whole rule in one assertion.
//
// The failure this pins is a five-fold over-claim: reporting the volume's monthly cost as the saving
// rather than the gap between the two rates. A 100 GiB gp2 volume does not stop costing money when it
// becomes gp3 — it costs the gp3 rate instead, and only the difference is recoverable.
func TestGp2ToGp3_ThePriceIsTheDIFFERENCE(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:          []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "2", "8Gi")},
		StorageClasses: []storagev1.StorageClass{awsClass("gp2", "gp2")},
		PVs:            []corev1.PersistentVolume{gp2PV("pv-a", "gp2", 100)},
	}
	got := Gp2WhereGp3IsCheaper{}.Evaluate(inv, Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	f := got[0]

	gp2Rate, ok1 := pricing.StorageMonthlyPerGB("aws", "eu-central-1", "gp2")
	gp3Rate, ok2 := pricing.StorageMonthlyPerGB("aws", "eu-central-1", "gp3")
	// NOT t.Skip. A skip here was honest for the hours before the gp2 rates landed and became a
	// silent pass the moment they did: if a future table drops gp2, the one assertion that pins the
	// rate DIFFERENCE would report success by not running. The rates are in this build; their absence
	// is a regression, not a reason to stand down.
	if !ok1 || !ok2 {
		t.Fatalf("this build has no gp2/gp3 rate pair for eu-central-1 (gp2 ok=%v, gp3 ok=%v) — "+
			"the rule cannot state a difference without both", ok1, ok2)
	}
	wantDelta := 100 * (gp2Rate - gp3Rate)
	if diff := f.DollarImpactMonthly - wantDelta; diff > 0.01 || diff < -0.01 {
		t.Errorf("DollarImpactMonthly = %.4f, want the RATE DIFFERENCE %.4f (×100 GiB). "+
			"A figure near %.4f means the volume's whole cost was reported as recoverable.",
			f.DollarImpactMonthly, wantDelta, 100*gp2Rate)
	}
}

// TestGp2ToGp3_OneFindingForTheWholeCluster pins the density decision. gp2 was the EKS default, so a
// per-volume finding would put one card per volume into a document that already carries over a
// hundred — and every card would name the same action.
func TestGp2ToGp3_OneFindingForTheWholeCluster(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:          []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "2", "8Gi")},
		StorageClasses: []storagev1.StorageClass{awsClass("gp2", "gp2")},
		PVs: []corev1.PersistentVolume{
			gp2PV("pv-a", "gp2", 100), gp2PV("pv-b", "gp2", 200), gp2PV("pv-c", "gp2", 50),
		},
	}
	got := Gp2WhereGp3IsCheaper{}.Evaluate(inv, Options{})
	if len(got) != 1 {
		t.Fatalf("want exactly 1 finding for 3 volumes, got %d", len(got))
	}
	ev := strings.Join(got[0].Evidence, "\n")
	for _, name := range []string{"pv-a", "pv-b", "pv-c"} {
		if !strings.Contains(ev, name) {
			t.Errorf("evidence does not name %s — the volumes must still be listed, just not as separate cards", name)
		}
	}
}

// TestGp2ToGp3_ClassNameIsNotTheType pins the reason StorageDiskTypeFor exists. A class NAMED gp3 that
// carries `type: gp2` must be read as gp2 — the name is a convention, parameters are what the
// provisioner acts on.
func TestGp2ToGp3_ClassNameIsNotTheType(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:          []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "2", "8Gi")},
		StorageClasses: []storagev1.StorageClass{awsClass("gp3", "gp2")}, // named gp3, IS gp2
		PVs:            []corev1.PersistentVolume{gp2PV("pv-a", "gp3", 100)},
	}
	if got := (Gp2WhereGp3IsCheaper{}).Evaluate(inv, Options{}); len(got) != 1 {
		t.Errorf("a class named gp3 carrying type=gp2 produced %d findings, want 1 — the name was trusted over the parameters", len(got))
	}
}

// TestGp2ToGp3_LargeVolumesDiscloseTheIOPSCatch. gp2 baseline IOPS is 3 per GiB, so at and above
// 1000 GiB a gp2 volume has MORE than gp3's free 3000 baseline. For those the move is not free
// performance — matching the IOPS costs extra — and the finding must say so or the "no trade-off"
// claim is false exactly where the money is largest.
func TestGp2ToGp3_LargeVolumesDiscloseTheIOPSCatch(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:          []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "2", "8Gi")},
		StorageClasses: []storagev1.StorageClass{awsClass("gp2", "gp2")},
		PVs:            []corev1.PersistentVolume{gp2PV("big", "gp2", 2000)},
	}
	got := (Gp2WhereGp3IsCheaper{}).Evaluate(inv, Options{})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	ev := strings.ToLower(strings.Join(got[0].Evidence, "\n"))
	if !strings.Contains(ev, "iops") {
		t.Errorf("a 2000 GiB gp2 volume has 6000 baseline IOPS against gp3's free 3000, and the evidence "+
			"never mentions IOPS:\n%s", strings.Join(got[0].Evidence, "\n"))
	}
}

// TestGp2ToGp3_SilentWithoutGp2 — the ordinary healthy cluster produces nothing.
func TestGp2ToGp3_SilentWithoutGp2(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:          []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "2", "8Gi")},
		StorageClasses: []storagev1.StorageClass{awsClass("gp3", "gp3")},
		PVs:            []corev1.PersistentVolume{gp2PV("pv-a", "gp3", 100)},
	}
	if got := (Gp2WhereGp3IsCheaper{}).Evaluate(inv, Options{}); len(got) != 0 {
		t.Errorf("an all-gp3 cluster produced %d finding(s), want silence", len(got))
	}
}
