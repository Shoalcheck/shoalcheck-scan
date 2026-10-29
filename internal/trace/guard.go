package trace

import (
	"errors"
	"net/url"
	"strings"
)

// THE NEVER-READ GUARD.
//
// The published ClusterRole has no rule for Secrets, ConfigMaps, pod logs, exec or attach, and
// TestRBACContractMatchesCollector keeps the role and the collector in step. That holds the claim only
// while the operator runs with our role. A reader who runs the binary with their own cluster-admin
// kubeconfig — most of them, on a first try — is trusting that no code path asks. This guard turns that
// trust into a refusal: every client this binary builds goes through this transport (the transport-gate
// in make ci holds that), and a request for one of these kinds is refused here, before it is sent.
//
// Suggested by an engineer we asked for an opinion (2026-10-29): wrap the client so Secrets cannot be read,
// and publish that code as evidence. This package is in the Apache-2.0 subset, so the evidence is the code.
//
// A refused request was never issued, so it is NOT recorded: the tally is checked against the API
// server's own audit log, and a row the server never saw would make them disagree.
var ErrNeverRead = errors.New("refused before it left the process: this binary never reads")

// neverRead are the kinds whose contents are the credential, the connection string or the customer data
// itself. Matched by resource name in any API group, so a CRD that reuses the name is refused too: a
// false refusal is a missing finding, a false pass is a leaked secret.
var neverRead = map[string]bool{
	"secrets":    true,
	"configmaps": true,
}

// neverReadSub are subresources that read inside a running workload or mint a credential.
var neverReadSub = map[string]bool{
	"pods/log":              true,
	"pods/exec":             true,
	"pods/attach":           true,
	"serviceaccounts/token": true,
}

// refusal names the kind a request to the API server must never read, or returns "" when it may go. It
// names only the kind, never the namespace or the object: the error reaches logs and reports.
func refusal(target Target, u *url.URL) string {
	if target != TargetAPIServer || u == nil {
		return ""
	}
	var segs []string
	for _, s := range strings.Split(strings.ToLower(u.Path), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	var rest []string
	switch {
	case len(segs) >= 2 && segs[0] == "api":
		rest = segs[2:]
	case len(segs) >= 3 && segs[0] == "apis":
		rest = segs[3:]
	default:
		return ""
	}
	if len(rest) > 0 && rest[0] == "watch" {
		rest = rest[1:]
	}
	// /namespaces/{ns}/{resource}... is namespaced; /namespaces/{name} alone is the Namespace object.
	if len(rest) >= 3 && rest[0] == "namespaces" {
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return ""
	}
	if neverRead[rest[0]] {
		return rest[0]
	}
	if len(rest) >= 3 && neverReadSub[rest[0]+"/"+rest[2]] {
		return rest[0] + "/" + rest[2]
	}
	return ""
}
