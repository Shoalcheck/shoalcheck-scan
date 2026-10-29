package pipeline

import "strings"

// friendlyClusterName derives a short, human-readable cluster display name from
// a raw kube context. EKS contexts are full ARNs and GKE contexts are
// underscore-joined triples — both render as ugly truncated names in the
// sidebar/header — so we strip them to the bare cluster name. Everything else
// (AKS contexts like "aks-shop-dev-westus3-01", kind/minikube names, hand-set
// names) is already friendly and returned unchanged.
//
// The function is pure and total: it never panics and never returns "", so it
// is safe to feed directly into Options.ClusterName (the empty input falls back
// to "cluster", matching Run's own fallback).
// FriendlyClusterName is friendlyClusterName for the one-line commands: a --context maps to the reading the
// audit of that context saved, because both derive the cluster's name here and nowhere else.
func FriendlyClusterName(context string) string { return friendlyClusterName(context) }

func friendlyClusterName(context string) string {
	if context == "" {
		return "cluster"
	}

	// EKS: arn:aws:eks:<region>:<acct>:cluster/<name> → <name>.
	// Match the resource segment so a non-cluster ARN (e.g. .../nodegroup/ng-1)
	// is left as-is rather than mangled.
	if strings.HasPrefix(context, "arn:aws:eks:") {
		if i := strings.Index(context, ":cluster/"); i >= 0 {
			if name := context[i+len(":cluster/"):]; name != "" {
				return name
			}
		}
		// Malformed ARN (no ":cluster/" or an empty name): better to show the
		// raw context than an empty or misleading name.
		return context
	}

	// GKE: gke_<project>_<region>_<name> → <name> (the last underscore segment).
	if strings.HasPrefix(context, "gke_") {
		if i := strings.LastIndex(context, "_"); i >= 0 {
			if name := context[i+1:]; name != "" {
				return name
			}
		}
		// Trailing/empty final segment: fall back to the raw context.
		return context
	}

	return context
}
