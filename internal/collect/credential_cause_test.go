package collect

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A CREDENTIAL THE SERVER REJECTED IS ITS OWN CAUSE, AND SO IS ONE THAT COULD NOT BE OBTAINED.
//
// An expired token's run printed "nothing could be read from prod-eu: every list failed (28 lists could not be
// read)": client-go words a 401 on discovery and on the version as "the server has asked for the client to provide
// credentials", which no branch of CauseOf matched, and an exec plugin that failed or an untrusted certificate fell
// through the same way. Each has one thing to do about it, so each is a cause of its own. The strings below are
// client-go's own, as a live run against an expired token, a broken credential plugin and a wrong CA printed them.
func TestCauseOf_CredentialFailuresAreNamed(t *testing.T) {
	cases := map[string]string{
		"the server has asked for the client to provide credentials": "credentials not accepted",
		"Unauthorized": "credentials not accepted",
		`Get "https://127.0.0.1:54129/api?timeout=32s": the server has asked for the client to provide credentials`:                                             "credentials not accepted",
		"getting credentials: exec: executable aws failed with exit code 255":                                                                                   "credentials could not be obtained",
		"getting credentials: exec: executable kubelogin not found\n\nIt looks like you are trying to use a client-go credential plugin that is not installed.": "credentials could not be obtained",
		`Get "https://10.0.0.1:6443/api?timeout=32s": tls: failed to verify certificate: x509: certificate signed by unknown authority`:                         "certificate not accepted",
		"x509: certificate has expired or is not yet valid: current time 2026-10-21T01:00:00Z is after 2026-10-01T00:00:00Z":                                    "certificate not accepted",
		// Unchanged: a 403 is a permission, and a refused connection is reachability.
		`pods is forbidden: User "system:serviceaccount:x:y" cannot list resource "pods" in API group "" at the cluster scope`: "not permitted",
		`Get "https://127.0.0.1:1/api": dial tcp 127.0.0.1:1: connect: connection refused`:                                     "not reachable",
	}
	for in, want := range cases {
		got := CauseOf(in)
		if got != want {
			t.Errorf("CauseOf(%q) = %q, want %q", in, got, want)
		}
		if !types.KnownCause(got) {
			t.Errorf("%q is not in the measured set, so a reading carrying it would lose it on reload", got)
		}
	}
}
