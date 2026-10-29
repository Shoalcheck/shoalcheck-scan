package pricing

import "testing"

// TestBundle_StatesWhichTablesItCarries — a bundle without the newer tables is not an error, it is a MIXED
// state: those tables come from the embedded snapshot. Carries() is how a run can say so instead of naming
// one source for everything.
func TestBundle_StatesWhichTablesItCarries(t *testing.T) {
	old := []byte(`{"version":"2026-09","nodeHourlyUSD":{"aws":{"eu-central-1":{"m6i.large":0.1152}}}}`)
	p, err := FromBundle(old, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	c := p.(bundleProvider).Carries()
	for k, v := range c {
		if v {
			t.Errorf("a payload with only node rates claims to carry %s", k)
		}
	}
	// And a payload that lacks EBS falls through to the embedded table rather than answering nothing.
	if _, ok := p.StorageMonthlyPerGB("aws", "eu-central-1", "gp3"); !ok {
		t.Error("an old bundle with no EBS table made gp3 unpriced — it must fall back to the embedded rate")
	}
	newer := []byte(`{"version":"2026-09","nodeHourlyUSD":{"aws":{"eu-central-1":{"m6i.large":0.1152}}},` +
		`"ebsGBMonthUSD":{"eu-central-1":{"gp3":0.2}},"extendedSupportHourlyUSD":{"aws":1.0}}`)
	p2, err := FromBundle(newer, "bundle")
	if err != nil {
		t.Fatal(err)
	}
	c2 := p2.(bundleProvider).Carries()
	if !c2["ebs"] || !c2["extended-support"] || c2["azure-disk-tiers"] || c2["aws-shapes"] {
		t.Errorf("carries = %v, want ebs and extended-support only", c2)
	}
	if v, ok := p2.StorageMonthlyPerGB("aws", "eu-central-1", "gp3"); !ok || v != 0.2 {
		t.Errorf("gp3 from the bundle = %v ok=%v, want 0.2 — the bundle's EBS table must win over the embedded one", v, ok)
	}
	if v, ok := p2.ExtendedSupportHourly("aws"); !ok || v != 1.0 {
		t.Errorf("extended support from the bundle = %v ok=%v, want 1.0", v, ok)
	}
}
