package collect

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The report is a document the operator may forward. The methodology note used to carry the API's OWN error
// text verbatim, and that text contains two things it must never publish: the API server URL and port when the
// cluster is unreachable, and the authenticated identity on a permission failure. Neither is an identifier the
// redactor gathers, so both survived --redact — in the section that exists to explain the report's limits.
//
// It also called both of those "access denied", so a network failure was reported as a permission problem in a
// document whose own session trace said zero requests were refused.
func TestDeniedSources_CarryNoErrorTextAndNameTheRightCause(t *testing.T) {
	cases := []struct {
		entry    string
		wantKind string
		wantWhy  string
		mustNot  []string
	}{
		{
			entry:    `poddisruptionbudgets: poddisruptionbudgets.policy is forbidden: User "system:serviceaccount:default:shoalcheck-limited" cannot list resource "poddisruptionbudgets" in API group "policy" at the cluster scope`,
			wantKind: "poddisruptionbudgets",
			wantWhy:  "not permitted",
			mustNot:  []string{"system:serviceaccount", "shoalcheck-limited", "User \""},
		},
		{
			entry:    `server-resources: Get "https://prod-api.acmebank.internal:6443/api?timeout=32s": dial tcp 10.0.4.7:6443: connect: connection refused`,
			wantKind: "server-resources",
			wantWhy:  "not reachable",
			mustNot:  []string{"acmebank", "6443", "10.0.4.7", "https://"},
		},
		{
			entry:    `pods: Get "https://k/api/v1/pods": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`,
			wantKind: "pods",
			wantWhy:  "timed out",
			mustNot:  []string{"https://", "Client.Timeout"},
		},
		{
			entry:    `cr:certificates.cert-manager.io: the server could not find the requested resource`,
			wantKind: "cr:certificates.cert-manager.io",
			wantWhy:  "not served by this cluster",
			mustNot:  []string{"could not find the requested"},
		},
	}

	for _, c := range cases {
		got := deniedSourceNote([]string{c.entry})
		if !strings.Contains(got, c.wantKind) {
			t.Errorf("%q: the note does not name the kind:\n  %s", c.wantKind, got)
		}
		if !strings.Contains(got, c.wantWhy) {
			t.Errorf("%q: want cause %q, got:\n  %s", c.wantKind, c.wantWhy, got)
		}
		for _, forbidden := range c.mustNot {
			if strings.Contains(got, forbidden) {
				t.Errorf("%q: the note publishes %q:\n  %s", c.wantKind, forbidden, got)
			}
		}
		if strings.Contains(got, "access denied") {
			t.Errorf("%q: the note still says \"access denied\" for every cause:\n  %s", c.wantKind, got)
		}
	}
}

// And the whole-report path: a real BuildReport must not leak either, since that is where it would ship.
func TestBuildReport_MethodologyCarriesNoErrorText(t *testing.T) {
	inv := &Inventory{Meta: Meta{
		ServerVersion: "v1.31.0",
		Collected:     []string{"nodes"},
		Denied: []string{
			`pods: pods is forbidden: User "system:serviceaccount:kube-system:probe" cannot list resource "pods"`,
			`services: Get "https://prod.acmebank.internal:6443/api/v1/services": dial tcp: connection refused`,
		},
	}}
	ar := BuildReport(inv, nil, "c", 0, nil)
	blob := strings.Join(ar.Methodology.DataSources, " | ")
	for _, forbidden := range []string{"acmebank", "6443", "system:serviceaccount", "connection refused", "is forbidden"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("Methodology.DataSources publishes %q:\n  %s", forbidden, blob)
		}
	}
	// The kinds themselves must still be named — suppressing the leak must not suppress the disclosure.
	for _, kind := range []string{"pods", "services"} {
		if !strings.Contains(blob, kind) {
			t.Errorf("the note no longer names %q, so the coverage gap is now invisible:\n  %s", kind, blob)
		}
	}
	var _ = types.Methodology{}
}
