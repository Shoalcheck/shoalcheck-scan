package pricing

import "testing"

func TestStorageMonthlyPerGB(t *testing.T) {
	// AWS gp3 generalises from the existing EBS table.
	gp3, ok := StorageMonthlyPerGB("aws", "eu-central-1", "gp3")
	if !ok || gp3 != 0.0952 {
		t.Errorf("aws/eu-central-1/gp3 = %v ok=%v, want 0.0952", gp3, ok)
	}
	// Azure Premium SSD priced.
	// Azure is a TIER, not a rate, since 2026-09-02: StorageMonthlyPerGB says ok=false for it on purpose, and
	// the tier path is the one that prices — asserted here so the change of model cannot regress silently.
	if _, ok := StorageMonthlyPerGB("aks", "westeurope", "Premium_LRS"); ok {
		t.Error("aks/westeurope/Premium_LRS has a per-GB rate — Azure bills managed disks by tier, and a per-GB number here is the old approximation")
	}
	if tier, prem, ok := AzureDiskTier("westeurope", "Premium_LRS", 100); !ok || tier != "P10" || prem <= 0 {
		t.Errorf("aks/westeurope/Premium_LRS 100GiB -> %q $%.2f ok=%v, want P10 at a positive price", tier, prem, ok)
	}
	// Unknown disk type → ok=false (never priced as cheapest tier).
	if v, ok := StorageMonthlyPerGB("aks", "westeurope", "Mystery_LRS"); ok || v != 0 {
		t.Errorf("unknown disk type must be ok=false, got %v ok=%v", v, ok)
	}
	// GCP storage not modelled → ok=false.
	if _, ok := StorageMonthlyPerGB("gke", "europe-west3", "pd-balanced"); ok {
		t.Error("gcp storage must be ok=false (not modelled)")
	}
}

func TestEgressPerGB(t *testing.T) {
	aws, ok := EgressPerGB("aws", "eu-central-1")
	if !ok || aws <= 0 {
		t.Errorf("aws/eu-central-1 egress = %v ok=%v, want >0", aws, ok)
	}
	if _, ok := EgressPerGB("aws", "moon-base-1"); ok {
		t.Error("uncovered region egress must be ok=false")
	}
}
