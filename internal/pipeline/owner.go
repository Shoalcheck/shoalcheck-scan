package pipeline

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// owner.go — WHO OWNS THIS FINDING, when the operator has told us where to look.
//
// A queue nobody owns is a queue nobody works (reading-surface spec §6.3). The blocker on that ticket for
// three weeks was real but was the wrong shape: it read "which label names a team is a choice no convention
// settles", and that is true — Kubernetes has no owner label, the ecosystem has half a dozen habits
// (`team`, `owner`, `squad`, `app.kubernetes.io/part-of`) and picking one for everybody would be wrong for
// most of them.
//
// SO THE PRODUCT DOES NOT PICK. `--owner-label` names the key, the operator supplies it because they are the
// only person who knows their own convention, and with no flag there is no owner and nothing is invented. A
// finding's owner is then arithmetic: the value of that label on the namespace the finding is in.
//
// WHAT THIS DELIBERATELY DOES NOT DO. It does not guess. An unlabelled namespace produces no owner rather
// than a fallback to a namespace name dressed up as a team, because "owned by payments" and "in the payments
// namespace" are different statements and a queue that conflates them routes work to people who never agreed
// to it. A cluster-scoped finding has no namespace and therefore no owner, which is a fact rather than a gap.

// attachOwner resolves each finding's owner from the namespace label the operator named. A key of "" leaves
// every finding unowned, which is the state of every reading taken before somebody passed the flag.
func attachOwner(findings []types.Finding, namespaces []corev1.Namespace, key string) {
	if key == "" {
		return
	}
	byNS := make(map[string]string, len(namespaces))
	for _, ns := range namespaces {
		if v := ns.Labels[key]; v != "" {
			byNS[ns.Name] = v
		}
	}
	if len(byNS) == 0 {
		return
	}
	for i := range findings {
		ns := findingNamespace(findings[i])
		if ns == "" {
			continue // cluster-scoped: no namespace, so no owner, and that is a fact rather than a gap
		}
		findings[i].Owner = byNS[ns]
	}
}

// findingNamespace is the namespace a finding is about — the first affected resource that names one. It
// prefers the id's own basis where there is one, because that is the resource the finding is keyed on, and
// falls back to the first affected resource for a reading written before IDBasis existed.
func findingNamespace(f types.Finding) string {
	if f.IDBasis != nil && f.IDBasis.Namespace != "" {
		return f.IDBasis.Namespace
	}
	for _, r := range f.AffectedResources {
		if r.Namespace != "" {
			return r.Namespace
		}
	}
	return ""
}

// ownerCoverage counts how many findings an owner label resolved, out of how many could have had one. It is
// what the methodology block states, because "12 of 134 findings have an owner" is the honest form and
// "routed to 4 teams" alone would let a reader assume the rest were covered.
func ownerCoverage(findings []types.Finding) (owned, ownable int) {
	for _, f := range findings {
		if findingNamespace(f) == "" {
			continue
		}
		ownable++
		if f.Owner != "" {
			owned++
		}
	}
	return owned, ownable
}
