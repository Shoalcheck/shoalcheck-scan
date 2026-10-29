package analyzers

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// certObj builds an unstructured cert-manager Certificate. ready/issuing drive
// status.conditions; notAfter is set verbatim (caller controls type to exercise
// the NestedString discipline). issuer is set as spec.issuerRef.NAME with a
// ClusterIssuer kind, so tests can assert the name is dropped from Evidence but
// the kind survives (the redaction-safety fix).
func certObj(ns, name, issuer string, ready, issuing bool, notAfter interface{}) unstructured.Unstructured {
	conds := []interface{}{}
	if ready {
		conds = append(conds, map[string]interface{}{"type": "Ready", "status": "True"})
	} else {
		conds = append(conds, map[string]interface{}{"type": "Ready", "status": "False"})
	}
	if issuing {
		conds = append(conds, map[string]interface{}{"type": "Issuing", "status": "True"})
	}
	status := map[string]interface{}{"conditions": conds}
	if notAfter != nil {
		status["notAfter"] = notAfter
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]interface{}{"namespace": ns, "name": name},
		"spec":       map[string]interface{}{"issuerRef": map[string]interface{}{"name": issuer, "kind": "ClusterIssuer"}},
		"status":     status,
	}}
}

func certInv(objs ...unstructured.Unstructured) *collect.Inventory {
	gvr := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	return &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvr: objs},
		Meta:         collect.Meta{Collected: []string{"cr:" + gvr.GroupResource().String()}},
	}
}

func TestCertManagerExpiringSoon(t *testing.T) {
	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	inv := certInv(certObj("prod", "api-tls", "letsencrypt", true, false, soon))
	fs := CertManagerExpiry{}.Analyze(inv)
	if len(fs) != 1 {
		t.Fatalf("want 1 expiring finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "stack.certmanager.expiring" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("3-days-out severity = %q, want high", f.Severity)
	}
	if f.DollarImpactMonthly != 0 {
		t.Errorf("stack finding must carry no fabricated dollars, got %v", f.DollarImpactMonthly)
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, soon) || !strings.Contains(ev, "prod/api-tls") {
		t.Errorf("evidence must cite ns/name and the literal notAfter: %v", f.Evidence)
	}
	// Redaction safety: the issuer KIND is cited, the issuer NAME is NOT (it can
	// carry CA/domain identifiers and would survive --redact as free text).
	if !strings.Contains(ev, "ClusterIssuer") {
		t.Errorf("evidence must cite the issuer kind: %v", f.Evidence)
	}
	if strings.Contains(ev, "letsencrypt") {
		t.Errorf("evidence must NOT contain the issuerRef NAME (redaction leak): %v", f.Evidence)
	}
}

func TestCertManagerExpiredIsCritical(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	fs := CertManagerExpiry{}.Analyze(certInv(certObj("prod", "old-tls", "ca", true, false, past)))
	if len(fs) != 1 || fs[0].Severity != types.SeverityCritical {
		t.Fatalf("expired cert must be one Critical finding, got %+v", fs)
	}
}

func TestCertManagerNotYetIssued(t *testing.T) {
	// Ready=False + Issuing present + empty notAfter → "not yet issued", never a
	// fabricated expiry date, never a panic.
	fs := CertManagerExpiry{}.Analyze(certInv(certObj("prod", "pending-tls", "ca", false, true, nil)))
	if len(fs) != 1 {
		t.Fatalf("want 1 not-yet-issued finding, got %d", len(fs))
	}
	body := strings.ToLower(fs[0].Title + " " + fs[0].Description)
	if !strings.Contains(body, "not yet issued") && !strings.Contains(body, "issuance") {
		t.Errorf("must phrase as not-yet-issued/issuance-failing: %q", fs[0].Title)
	}
}

func TestCertManagerNonStringNotAfterNoPanic(t *testing.T) {
	// A non-string notAfter (e.g. an int from a malformed CR) must not panic and
	// must not be treated as a parsed expiry — NestedString discipline.
	fs := CertManagerExpiry{}.Analyze(certInv(certObj("prod", "weird-tls", "ca", true, false, 12345)))
	for _, f := range fs {
		if f.Severity == types.SeverityCritical || f.Severity == types.SeverityHigh {
			t.Errorf("must not derive an expiry severity from a non-string notAfter: %+v", f)
		}
	}
}

func TestCertManagerHealthyNoFinding(t *testing.T) {
	far := time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if fs := (CertManagerExpiry{}).Analyze(certInv(certObj("prod", "fine-tls", "ca", true, false, far))); len(fs) != 0 {
		t.Errorf("healthy cert 90d out must produce no finding, got %+v", fs)
	}
}

func TestCertManagerDeniedListNoFabrication(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	inv := &collect.Inventory{
		PresentGVRs:  collect.GVRSet{gvr: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{}, // empty
		Meta:         collect.Meta{Denied: []string{"cr:" + gvr.GroupResource().String() + ": forbidden"}},
	}
	if fs := (CertManagerExpiry{}).Analyze(inv); len(fs) != 0 {
		t.Errorf("denied Certificate list must not fabricate an all-clear or a finding, got %+v", fs)
	}
}

// Plan 2026-09-03 Task 2: the two expiry findings carry the date they read as a structured Deadline — the day
// part of status.notAfter and the field's name — so the calendar block is assembled from the field, not from
// parsing the evidence sentence. Not-yet-issued read no date and carries none.
func TestCertManager_ExpiryFindingsCarryTheDateTheyRead(t *testing.T) {
	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-3 * 24 * time.Hour).UTC().Format(time.RFC3339)
	inv := certInv(
		certObj("prod", "api-tls", "letsencrypt", true, false, soon),
		certObj("prod", "old-tls", "letsencrypt", true, false, past),
		certObj("prod", "new-tls", "letsencrypt", false, true, nil),
	)
	fs := CertManagerExpiry{}.Analyze(inv)
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	byName := map[string]types.Finding{}
	for _, f := range fs {
		byName[f.AffectedResources[0].Name] = f
	}
	for name, want := range map[string]string{"api-tls": soon[:10], "old-tls": past[:10]} {
		d := byName[name].Deadline
		if d == nil || d.Date != want || d.Field != "status.notAfter" {
			t.Errorf("%s: deadline %+v, want {%s status.notAfter}", name, d, want)
		}
	}
	if byName["new-tls"].Deadline != nil {
		t.Errorf("a not-yet-issued certificate has no date to carry, got %+v", byName["new-tls"].Deadline)
	}
	if deadlineFrom("2026-09") != nil {
		t.Error("a value too short to carry a day produced a deadline")
	}
}
