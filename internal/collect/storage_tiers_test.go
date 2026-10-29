package collect

import (
	"math"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

func azureInv(classes []storagev1.StorageClass, pvs ...corev1.PersistentVolume) *Inventory {
	return &Inventory{
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{
				"topology.kubernetes.io/region": "westeurope", "node.kubernetes.io/instance-type": "Standard_D4s_v5"}},
			Spec: corev1.NodeSpec{ProviderID: "azure:///sub/x"},
		}},
		StorageClasses: classes,
		PVs:            pvs,
		Meta:           Meta{ServerVersion: "v1.30.2"},
	}
}

// TestEstimateStorageSpend_AzureIsBilledByTierNotByGiB pins the correction: three claims of 100, 129 and
// 4 GiB on Premium_LRS are billed as P10 + P15 + P1, not as 233 GiB times a rate. The per-GB model under-
// reported the small one about eighteen-fold and mis-sized the middle one.
func TestEstimateStorageSpend_AzureIsBilledByTierNotByGiB(t *testing.T) {
	inv := azureInv(nil, pv("a", "managed-premium", 100), pv("b", "managed-premium", 129), pv("c", "managed-premium", 4))
	total, unpriced := estimateStorageSpend(inv, "westeurope", "azure", pricing.Embedded())
	if len(unpriced) != 0 {
		t.Fatalf("unpriced = %v, want none", unpriced)
	}
	_, p10, _ := pricing.AzureDiskTier("westeurope", "Premium_LRS", 100)
	_, p15, _ := pricing.AzureDiskTier("westeurope", "Premium_LRS", 129)
	_, p1, _ := pricing.AzureDiskTier("westeurope", "Premium_LRS", 4)
	if want := p10 + p15 + p1; math.Abs(total-want) > 0.01 {
		t.Errorf("Azure storage total = %.2f, want P10+P15+P1 = %.2f (a figure proportional to 233 GiB means the "+
			"per-GB approximation is back)", total, want)
	}
}

// TestEstimateStorageSpend_ZRSClassesPriceAsTheirOwnTier — the class object says ZRS, and ZRS is dearer.
func TestEstimateStorageSpend_ZRSClassesPriceAsTheirOwnTier(t *testing.T) {
	zrs := storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "fast-zrs"}, Provisioner: "disk.csi.azure.com",
		Parameters: map[string]string{"skuName": "Premium_ZRS"}}
	inv := azureInv([]storagev1.StorageClass{zrs}, pv("a", "fast-zrs", 100))
	total, unpriced := estimateStorageSpend(inv, "westeurope", "azure", pricing.Embedded())
	_, lrs, _ := pricing.AzureDiskTier("westeurope", "Premium_LRS", 100)
	_, wantZRS, ok := pricing.AzureDiskTier("westeurope", "Premium_ZRS", 100)
	if !ok {
		t.Skip("this build carries no Premium_ZRS tiers for westeurope")
	}
	if len(unpriced) != 0 || math.Abs(total-wantZRS) > 0.01 || wantZRS <= lrs {
		t.Errorf("Premium_ZRS 100GiB -> total %.2f unpriced=%v, want the ZRS P10 price %.2f (> LRS %.2f)", total, unpriced, wantZRS, lrs)
	}
}

// TestEstimateStorageSpend_AboveTheLargestTierIsUnpriced — never "priced as P80".
func TestEstimateStorageSpend_AboveTheLargestTierIsUnpriced(t *testing.T) {
	inv := azureInv(nil, pv("huge", "managed-premium", 40000))
	total, unpriced := estimateStorageSpend(inv, "westeurope", "azure", pricing.Embedded())
	if total != 0 || len(unpriced) != 1 {
		t.Errorf("a 40,000 GiB claim priced %.2f with unpriced=%v; it exceeds every published tier and must be recorded, not rounded", total, unpriced)
	}
}
