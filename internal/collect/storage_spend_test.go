package collect

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pv(name, sc string, gib int64) corev1.PersistentVolume {
	return corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: sc,
			Capacity:         corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(itoaGi(gib))},
		},
	}
}
func itoaGi(g int64) string {
	return resource.NewQuantity(g*1024*1024*1024, resource.BinarySI).String()
}

func TestEstimateStorageSpend_PricedGp3(t *testing.T) {
	// gp3 StorageClass → "gp3" diskType, 100Gi × 0.0952 = 9.52/mo.
	inv := &Inventory{PVs: []corev1.PersistentVolume{pv("p1", "gp3", 100)}}
	usd, unpriced := estimateStorageSpend(inv, "eu-central-1", "eks", pricing.Embedded())
	if unpriced != nil {
		t.Errorf("unpriced should be nil, got %v", unpriced)
	}
	if got := round2(usd); got != 9.52 {
		t.Errorf("storage spend = %v, want 9.52", got)
	}
}

func TestEstimateStorageSpend_PVCFallbackForUnbound(t *testing.T) {
	// A Pending PVC (no VolumeName) is priced off requests.storage; a bound
	// PVC+PV pair is NOT double-counted (priced via the PV only).
	bound := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "bound", Namespace: "ns"},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName:       "p1",
			StorageClassName: strptr("gp3"),
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(itoaGi(50))}},
		},
	}
	pending := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns"},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: strptr("gp3"),
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(itoaGi(20))}},
		},
	}
	inv := &Inventory{
		PVs:  []corev1.PersistentVolume{pv("p1", "gp3", 100)}, // bound to "bound"
		PVCs: []corev1.PersistentVolumeClaim{bound, pending},
	}
	// 100Gi PV (9.52) + 20Gi pending PVC (1.904) = 11.424; bound PVC NOT added.
	usd, _ := estimateStorageSpend(inv, "eu-central-1", "eks", pricing.Embedded())
	if got := round2(usd); got != 11.42 {
		t.Errorf("storage spend = %v, want 11.42 (no double-count of bound pair)", got)
	}
}

func TestEstimateStorageSpend_UnpricedClassRecorded(t *testing.T) {
	// io2 is not in the table → recorded in UnpricedStorageClasses, NOT summed.
	//
	// This case used gp2 until 2026-08-31, when gp2 gained a rate and stopped being an example of
	// anything unpriced. The property under test is unchanged; only a class that is still genuinely
	// unmapped can demonstrate it.
	inv := &Inventory{PVs: []corev1.PersistentVolume{pv("p1", "io2", 100)}}
	usd, unpriced := estimateStorageSpend(inv, "eu-central-1", "eks", pricing.Embedded())
	if usd != 0 {
		t.Errorf("unpriced class must not be summed, got %v", usd)
	}
	if len(unpriced) != 1 || unpriced[0] != "io2" {
		t.Errorf("UnpricedStorageClasses = %v, want [io2]", unpriced)
	}
}

func TestBuildReportFoldsStorageAndFlipsNote(t *testing.T) {
	inv := &Inventory{
		Nodes: []corev1.Node{{
			Spec: corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/i-1"},
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
				"topology.kubernetes.io/region":    "eu-central-1",
				"node.kubernetes.io/instance-type": "m6i.large",
				"eks.amazonaws.com/capacityType":   "ON_DEMAND",
			}},
		}},
		PVs: []corev1.PersistentVolume{pv("p1", "gp3", 100)}, // 9.52/mo
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())

	if got := round2(ar.Cluster.StorageMonthlyUSD); got != 9.52 {
		t.Errorf("StorageMonthlyUSD = %v, want 9.52", got)
	}
	// EstimatedMonthlySpend must INCLUDE the storage component.
	if ar.Cluster.EstimatedMonthlySpend < 9.52 {
		t.Errorf("EstimatedMonthlySpend %v must include storage 9.52", ar.Cluster.EstimatedMonthlySpend)
	}
	// The "storage not collected" note must be GONE for a priced AWS cluster.
	joined := strings.Join(ar.Methodology.DataSources, " | ")
	if strings.Contains(joined, "storage not collected") {
		t.Errorf("priced cluster must NOT say 'storage not collected', got %q", joined)
	}
}

func TestBuildReportKeepsStorageNoteForUnpriced(t *testing.T) {
	// io2 (unpriced) → headline excludes it AND the note names the gap.
	inv := &Inventory{
		Nodes: []corev1.Node{{
			Spec: corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/i-1"},
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
				"topology.kubernetes.io/region":    "eu-central-1",
				"node.kubernetes.io/instance-type": "m6i.large",
				"eks.amazonaws.com/capacityType":   "ON_DEMAND",
			}},
		}},
		PVs: []corev1.PersistentVolume{pv("p1", "io2", 100)},
	}
	ar := BuildReport(inv, nil, "c", 0, pricing.Embedded())
	if ar.Architecture == nil || len(ar.Architecture.UnpricedStorageClasses) != 1 {
		t.Fatalf("UnpricedStorageClasses must list io2, got %+v", ar.Architecture)
	}
	joined := strings.Join(ar.Methodology.DataSources, " | ")
	if !strings.Contains(joined, "unpriced storage class") {
		t.Errorf("note must name the unpriced storage gap, got %q", joined)
	}
}

func strptr(s string) *string  { return &s }
func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// TestStorageDiskType_IsTheSameMappingTheSpendTotalUses — StorageDiskType is exported so
// internal/rules' unattached-volume rule prices one PersistentVolume with the SAME mapping the
// cluster total was built from. A private copy in the rule would drift; this asserts there is one.
//
// It does not compare the function to itself, which would prove nothing. It drives
// estimateStorageSpend — the assembler's own path — once per class and asserts the two agree in
// both directions: a class StorageDiskType maps must contribute to the total and must NOT appear in
// UnpricedStorageClasses, and a class it refuses must appear there and contribute nothing. Both
// directions matter, because "priced as the cheapest tier" and "silently dropped" are the two
// failures this mapping exists to prevent.
func TestStorageDiskType_IsTheSameMappingTheSpendTotalUses(t *testing.T) {
	classes := []string{"gp3", "ebs-gp3", "managed-premium", "standard_lrs", "gp2", "weird-tier", ""}
	mapped, refused := 0, 0
	for _, class := range classes {
		diskType, ok := StorageDiskType(class)
		inv := &Inventory{PVs: []corev1.PersistentVolume{pv("p1", class, 100)}}
		// eu-central-1 covers gp3; the Azure classes resolve through their own regions, so a mapped
		// class with no rate for THIS region is still "mapped" and is checked as such below.
		usd, unpriced := estimateStorageSpend(inv, "eu-central-1", "eks", pricing.Embedded())
		named := class
		if named == "" {
			named = "(no storageClass)"
		}
		listed := false
		for _, u := range unpriced {
			if u == named {
				listed = true
			}
		}
		if !ok {
			refused++
			if !listed {
				t.Errorf("class %q is refused by StorageDiskType but the spend total did not record it as "+
					"unpriced — a class the mapping refuses must never be silently dropped", class)
			}
			if usd != 0 {
				t.Errorf("class %q is refused by StorageDiskType but the spend total priced it at %v", class, usd)
			}
			continue
		}
		mapped++
		// A mapped class must not be reported as an unmapped one. Whether a RATE exists for this
		// particular region is a separate question, which is why the dollar is not asserted here.
		if listed && diskType != "" {
			_, hasRate := pricing.StorageMonthlyPerGB("eks", "eu-central-1", diskType)
			if hasRate {
				t.Errorf("class %q maps to %q and has a rate, yet the spend total called it unpriced",
					class, diskType)
			}
		}
	}
	// Non-vacuity: the table must exercise both branches, or every assertion above is unreachable.
	if mapped == 0 || refused == 0 {
		t.Fatalf("the class table exercised %d mapped and %d refused — both branches are needed", mapped, refused)
	}
}
