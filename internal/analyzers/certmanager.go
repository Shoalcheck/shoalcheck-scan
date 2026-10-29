package analyzers

import (
	"fmt"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func (CertManagerExpiry) ID() string { return "stack.certmanager.expiry" }
func (CertManagerExpiry) FindingIDs() []string {
	return []string{"stack.certmanager.expiring", "stack.certmanager.not-issued"}
}
func (CertManagerExpiry) Version() string { return "1.0.0" }
func (CertManagerExpiry) RequiredGVRs() []schema.GroupVersionResource {
	return certManagerGVRs()
}

// expiryWindowDays: certificates due within this many days are flagged High.
// Named in Evidence so the threshold is auditable, never a hidden constant.
const expiryWindowDays = 14

// Analyze reads cert-manager Certificate status (never the backing Secret) and
// emits expiry/issuance findings. Observed expiry is stated as FACT (the date
// came from the CR status); not-yet-issued is phrased without inventing a date.
func (a CertManagerExpiry) Analyze(inv *collect.Inventory) []types.Finding {
	const (
		group    = "cert-manager.io"
		resource = "certificates"
	)
	// DENIAL GUARD: never assert observed-absence/all-clear off a denied list.
	if !listSucceeded(inv, group, resource) {
		return nil
	}
	objs := stackObjects(inv, group, resource)
	// The reading's own clock, so a stored inventory says the same thing whenever it is evaluated. Every
	// window below — expired, and the expiry window — is measured against it.
	now := readingTime(inv)

	var out []types.Finding
	for _, c := range objs {
		ns, _, _ := unstructured.NestedString(c.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(c.Object, "metadata", "name")
		// We cite only the issuer KIND (Issuer/ClusterIssuer), never the issuerRef
		// NAME: the name embeds company/CA/domain identifiers and is NOT a
		// structured field redact.gatherIdentifiers harvests, so emitting it free-
		// text would let it survive --redact. The kind is enough to triage and
		// carries no PII. Default to "Issuer" (cert-manager's own default when the
		// kind is omitted) so the line is never empty.
		issuerKind, found, _ := unstructured.NestedString(c.Object, "spec", "issuerRef", "kind")
		if !found || issuerKind == "" {
			issuerKind = "Issuer"
		}

		ready, issuing := readyIssuing(c.Object)
		notAfter, hasNotAfter, _ := unstructured.NestedString(c.Object, "status", "notAfter")

		switch {
		case ready && hasNotAfter:
			t, err := time.Parse(time.RFC3339, notAfter)
			if err != nil {
				continue // malformed date string — do not invent a verdict
			}
			daysLeft := int(t.Sub(now).Hours() / 24)
			if t.Before(now) {
				out = append(out, a.expired(ns, name, issuerKind, notAfter))
			} else if daysLeft <= expiryWindowDays {
				out = append(out, a.expiringSoon(ns, name, issuerKind, notAfter, daysLeft))
			}
		case !ready && issuing:
			out = append(out, a.notYetIssued(ns, name, issuerKind))
		}
		// Ready && !hasNotAfter, or non-string notAfter (NestedString returns
		// found=false), or healthy/far-out cert → no finding.
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// readyIssuing scans status.conditions[] for type=="Ready"/"Issuing" using
// NestedSlice + NestedString — never a raw []interface{} assertion.
func readyIssuing(obj map[string]interface{}) (ready, issuing bool) {
	conds, found, err := unstructured.NestedSlice(obj, "status", "conditions")
	if !found || err != nil {
		return false, false
	}
	for _, ci := range conds {
		cm, ok := ci.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _, _ := unstructured.NestedString(cm, "type")
		st, _, _ := unstructured.NestedString(cm, "status")
		switch typ {
		case "Ready":
			ready = st == "True"
		case "Issuing":
			issuing = st == "True"
		}
	}
	return ready, issuing
}

func (a CertManagerExpiry) expired(ns, name, issuerKind, notAfter string) types.Finding {
	return types.Finding{
		ID:           findingID("stack.certmanager.expiring", "Certificate", ns, name),
		IDBasis:      &types.ResourceRef{Kind: "Certificate", Namespace: ns, Name: name},
		RuleID:       "stack.certmanager.expiring",
		Deadline:     deadlineFrom(notAfter),
		RuleVersion:  a.Version(),
		Title:        fmt.Sprintf("Certificate %s/%s has EXPIRED", ns, name),
		Description:  fmt.Sprintf("cert-manager Certificate %s/%s reports status.notAfter=%s, which is in the past. TLS handshakes using this certificate fail until it is renewed.", ns, name, notAfter),
		WhyItMatters: "An expired serving certificate breaks TLS for every client of the endpoint it backs — an observed, current outage condition, not a projection.",
		Evidence: []string{
			fmt.Sprintf("%s/%s: status.notAfter=%s (past)", ns, name, notAfter),
			fmt.Sprintf("spec.issuerRef.kind=%s (issuer name omitted — may carry CA/domain identifiers)", issuerKind),
			"read from CR status only — the backing Secret was never read",
		},
		Severity:          types.SeverityCritical,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortMedium,
		Confidence:        0.9, // date observed, not modeled
		Provenance:        provenance(),
	}
}

func (a CertManagerExpiry) expiringSoon(ns, name, issuerKind, notAfter string, daysLeft int) types.Finding {
	return types.Finding{
		ID:           findingID("stack.certmanager.expiring", "Certificate", ns, name),
		IDBasis:      &types.ResourceRef{Kind: "Certificate", Namespace: ns, Name: name},
		RuleID:       "stack.certmanager.expiring",
		Deadline:     deadlineFrom(notAfter),
		RuleVersion:  a.Version(),
		Title:        fmt.Sprintf("Certificate %s/%s expires in %d %s", ns, name, daysLeft, map[bool]string{true: "day", false: "days"}[daysLeft == 1]),
		Description:  fmt.Sprintf("cert-manager Certificate %s/%s reports status.notAfter=%s — within the %d-day expiry window. If renewal does not complete, TLS for the backed endpoint will fail at that timestamp.", ns, name, notAfter, expiryWindowDays),
		WhyItMatters: "A certificate nearing expiry is a scheduled outage unless renewal succeeds before notAfter; cert-manager renewal can silently stall on issuer/ACME errors.",
		Evidence: []string{
			fmt.Sprintf("%s/%s: status.notAfter=%s (%s out; window=%d days)", ns, name, notAfter, nWord(daysLeft, "day", "days"), expiryWindowDays),
			fmt.Sprintf("spec.issuerRef.kind=%s (issuer name omitted — may carry CA/domain identifiers)", issuerKind),
			"read from CR status only — the backing Secret was never read",
		},
		Severity:          types.SeverityHigh,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortMedium,
		Confidence:        0.9,
		Provenance:        provenance(),
	}
}

func (a CertManagerExpiry) notYetIssued(ns, name, issuerKind string) types.Finding {
	return types.Finding{
		ID:           findingID("stack.certmanager.not-issued", "Certificate", ns, name),
		IDBasis:      &types.ResourceRef{Kind: "Certificate", Namespace: ns, Name: name},
		RuleID:       "stack.certmanager.not-issued",
		RuleVersion:  a.Version(),
		Title:        fmt.Sprintf("Certificate %s/%s is not yet issued — issuance may be failing", ns, name),
		Description:  fmt.Sprintf("cert-manager Certificate %s/%s has status Ready=False with an active Issuing condition and no status.notAfter — the certificate has never been issued. Any endpoint relying on it has no valid TLS material.", ns, name),
		WhyItMatters: "A Certificate stuck issuing means the workload depending on it cannot serve TLS; this is an observed not-ready state, not a future risk.",
		Evidence: []string{
			fmt.Sprintf("%s/%s: status.conditions Ready=False, Issuing present, status.notAfter empty", ns, name),
			fmt.Sprintf("spec.issuerRef.kind=%s (issuer name omitted — may carry CA/domain identifiers)", issuerKind),
			"read from CR status only — the backing Secret was never read",
		},
		Severity:          types.SeverityHigh,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: ns, Name: name}},
		EstimatedEffort:   types.EffortMedium,
		Confidence:        0.8,
		Provenance:        provenance(),
	}
}

// deadlineFrom is the structured date beside the prose that quotes it: the day part of status.notAfter, so the
// calendar block can list this certificate without parsing an evidence sentence. A value too short to carry a day
// yields nil rather than a guess — the finding still stands on its prose.
func deadlineFrom(notAfter string) *types.Deadline {
	if len(notAfter) < 10 {
		return nil
	}
	return &types.Deadline{Date: notAfter[:10], Field: "status.notAfter"}
}
