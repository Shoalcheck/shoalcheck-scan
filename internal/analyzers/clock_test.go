package analyzers

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// clock_test.go — an analyzer that consults the wall clock cannot be replayed.
//
// certmanager decided from time.Now() whether a certificate was expired or merely expiring soon, so ONE
// stored inventory produced different findings on different days. That is precisely the property the
// re-derivability claim is about, and this package was the only producer package where it was broken:
// internal/rules has anchored to Meta.StartedAt since rotation.go was written.

func certInventory(t *testing.T, startedAt time.Time, notAfter string) *collect.Inventory {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	cert := unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]interface{}{"namespace": "prod", "name": "api-tls"},
		"spec":     map[string]interface{}{"issuerRef": map[string]interface{}{"kind": "ClusterIssuer", "name": "le"}},
		"status": map[string]interface{}{
			"notAfter":   notAfter,
			"conditions": []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}},
		},
	}}
	inv := &collect.Inventory{
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: {cert}},
	}
	inv.Meta.StartedAt = startedAt
	// Exactly the key collectStack() records; the denial guard matches it verbatim.
	inv.Meta.Collected = append(inv.Meta.Collected, "cr:"+gvr.GroupResource().String())
	return inv
}

// A certificate that was four days from expiry WHEN THE READING WAS TAKEN is four days from expiry every
// time that reading is evaluated — not "expired" because months have passed since.
func TestCertManager_MeasuresAgainstTheReadingClock(t *testing.T) {
	reading := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	inv := certInventory(t, reading, reading.Add(4*24*time.Hour).Format(time.RFC3339))

	got := (CertManagerExpiry{}).Analyze(inv)
	if len(got) != 1 {
		t.Fatalf("want one finding, got %d", len(got))
	}
	// Pre-fix this said EXPIRED: the wall clock is long past January 2026, so the branch flipped even though
	// the reading itself recorded a certificate with four days left. Matched case-insensitively — the two
	// titles differ in case as well as in words, and a case-sensitive probe would pass for the wrong reason.
	title := strings.ToLower(got[0].Title)
	if strings.Contains(title, "expired") {
		t.Errorf("the wall clock decided the branch: a certificate valid at the reading is reported expired\n  title: %s", got[0].Title)
	}
	if !strings.Contains(title, "expir") {
		t.Errorf("a certificate four days from expiry at the reading produced an unrelated finding: %q", got[0].Title)
	}

	// NON-VACUITY, both directions. A certificate already expired AT THE READING must still read expired,
	// so this test cannot be satisfied by an analyzer that simply never says "expired".
	past := certInventory(t, reading, reading.Add(-10*24*time.Hour).Format(time.RFC3339))
	if p := (CertManagerExpiry{}).Analyze(past); len(p) != 1 || !strings.Contains(strings.ToLower(p[0].Title), "expired") {
		t.Errorf("a certificate expired at the reading was not reported as expired: %+v", p)
	}
	// And a certificate far beyond the window at the reading produces nothing, so "one finding" above is not
	// simply what this analyzer always returns.
	far := certInventory(t, reading, reading.Add(300*24*time.Hour).Format(time.RFC3339))
	if f := (CertManagerExpiry{}).Analyze(far); len(f) != 0 {
		t.Errorf("a healthy certificate produced %d finding(s): %+v", len(f), f)
	}
}

// The same inventory, evaluated twice, cannot depend on how much wall-clock time passed in between.
func TestCertManager_TwoEvaluationsAgree(t *testing.T) {
	reading := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	inv := certInventory(t, reading, reading.Add(4*24*time.Hour).Format(time.RFC3339))
	first := (CertManagerExpiry{}).Analyze(inv)
	time.Sleep(2 * time.Millisecond)
	second := (CertManagerExpiry{}).Analyze(inv)
	if len(first) != len(second) {
		t.Fatalf("%d findings then %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID || first[i].Title != second[i].Title || first[i].Description != second[i].Description {
			t.Errorf("finding %d differs between two evaluations of one inventory:\n  %s\n  %s", i, first[i].Title, second[i].Title)
		}
	}
}
