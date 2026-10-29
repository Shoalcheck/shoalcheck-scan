package types

import (
	"fmt"
	"regexp"
	"strings"
)

// UnreadKind is one resource kind whose list did not come back, with the cause measured for it.
//
// THE CAUSES ARE A CLOSED SET and they are the words every surface prints: not permitted · not served by
// this cluster · not reachable · timed out · cause not recorded · could not be read. The classification
// itself is internal/collect's — it holds the API error — and the SENTENCE is built and read here, in the
// leaf package both the collector and every renderer can see.
//
// Why the sentence at all: Methodology.DeniedKinds carries names only, deliberately (its own comment says
// the error text belongs in the human-readable sentence, and that text carries the API server's address on a
// network failure and the caller's identity on a permission one). The note in DataSources is therefore the
// only place a cause survives into a SAVED reading — and every surface that renders one was inventing a
// cause instead: "Grant the read-only role", "Refused by the API server", "denied by RBAC", over clusters
// that had never been reached.
//
// Producer and parser live together because a format written in one package and read in another drifts.
type UnreadKind struct {
	Kind  string `json:"kind"`
	Cause string `json:"cause"`
}

// CauseNotRecorded is the honest answer for a reading whose methodology carries no note — one written before
// the note existed, or by a build that did not write it. Never the commonest cause: guessing "not permitted"
// there is the same invention this type exists to remove.
const CauseNotRecorded = "cause not recorded"

// KnownCause reports whether s is one of the causes this project measures (six, and since 2026-10-21 the three
// credential causes: a credential the server did not accept, one that could not be obtained, a certificate the
// client would not trust; and the two a large cluster produces: a list cut short part-way, and one the server kept
// throttling). A string outside the set came
// from a sentence that is not the denial note — the same DataSources slice carries the pricing basis and the
// names of unpriced StorageClasses, which are the customer's.
func KnownCause(s string) bool { return knownCause[s] }

var knownCause = map[string]bool{
	"not permitted": true, "not served by this cluster": true, "not reachable": true,
	"timed out": true, CauseNotRecorded: true, "could not be read": true,
	"credentials not accepted": true, "credentials could not be obtained": true, "certificate not accepted": true,
	"cut short": true, "throttled": true,
}

// UnreadNote formats the methodology sentence that carries the causes. It is the ONLY writer of this
// sentence and UnreadKinds is its only reader.
func UnreadNote(kinds []UnreadKind) string {
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s (%s)", k.Kind, k.Cause))
	}
	return fmt.Sprintf("Partial collection — %d resource kind(s) could not be read: %s. "+
		"Nothing is claimed about them; the cause of each is in the run log.", len(parts), strings.Join(parts, ", "))
}

var (
	unreadNoteRe = regexp.MustCompile(`(?s)resource kind\(s\) could not be read: (.*?)\. Nothing is claimed`)
	unreadPairRe = regexp.MustCompile(`([^,()]+) \(([^()]+)\)`)
)

// UnreadKinds pairs every kind in DeniedKinds with the cause recorded for it.
//
// THE FIELD FIRST. Methodology.Unread carries the pairs directly and is what every reading written since
// 2026-09-10 has. The note-parsing path below it exists for readings saved before that field did: it is a
// fallback for old files, not the mechanism. When the field is present the note is not consulted at all,
// so rephrasing the sentence can no longer silently empty the causes.
//
// The order is DeniedKinds' own; a kind neither source mentions gets CauseNotRecorded.
func (m Methodology) UnreadKinds() []UnreadKind {
	if len(m.DeniedKinds) == 0 {
		return nil
	}
	if len(m.Unread) > 0 {
		byKind := make(map[string]string, len(m.Unread))
		for _, u := range m.Unread {
			if knownCause[u.Cause] {
				byKind[u.Kind] = u.Cause
			}
		}
		out := make([]UnreadKind, 0, len(m.DeniedKinds))
		for _, k := range m.DeniedKinds {
			why := byKind[k]
			if why == "" {
				why = CauseNotRecorded
			}
			out = append(out, UnreadKind{Kind: k, Cause: why})
		}
		return out
	}
	found := map[string]string{}
	for _, src := range m.DataSources {
		sub := unreadNoteRe.FindStringSubmatch(src)
		if sub == nil {
			continue
		}
		for _, kv := range unreadPairRe.FindAllStringSubmatch(sub[1], -1) {
			kind, why := strings.TrimSpace(kv[1]), strings.TrimSpace(kv[2])
			if knownCause[why] {
				found[kind] = why
			}
		}
	}
	out := make([]UnreadKind, 0, len(m.DeniedKinds))
	for _, k := range m.DeniedKinds {
		why := found[k]
		if why == "" {
			why = CauseNotRecorded
		}
		out = append(out, UnreadKind{Kind: k, Cause: why})
	}
	return out
}

// Read reports whether one resource kind's list came back in this reading.
//
// A COUNT IS A CLAIM ABOUT THE KIND IT COUNTS. "This audit examined 0 nodes and 0 pods across 0 namespaces"
// was printed on a live reading where 34 of 35 kinds were refused and exactly one came back: every one of
// those zeros is the size of a list nobody read. The first version of that fix keyed on "nothing was
// collected at all", which this reading is not — one kind is not nothing, and it is not enough to state a
// node count either.
//
// Kind names are the collector's own strings ("nodes", "pods", "namespaces"), so a caller asking about a
// kind this build never requests gets false, which is the honest answer to "was it read".
func (m Methodology) Read(kind string) bool {
	for _, k := range m.CollectedKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// ReadAll reports whether every named kind came back. Empty input is true: a claim resting on nothing is
// not blocked by this.
func (m Methodology) ReadAll(kinds ...string) bool {
	for _, k := range kinds {
		if !m.Read(k) {
			return false
		}
	}
	return true
}

// UnreadAmong returns the named kinds this reading did not read, in the order given, so a sentence can name
// exactly what is missing rather than saying "some".
func (m Methodology) UnreadAmong(kinds ...string) []string {
	var out []string
	for _, k := range kinds {
		if !m.Read(k) {
			out = append(out, k)
		}
	}
	return out
}

// KubernetesOwnGroup reports whether an API group is one the Kubernetes project itself ships.
//
// A CLOSED LIST, AND IT IS NOT A VENDOR ALLOWLIST. These groups are present on every cluster in the world;
// they identify nobody and they are nobody's operator. `*.k8s.io` alone is unreliable in both directions —
// `metrics.k8s.io` is upstream and `cert-manager.k8s.io` was somebody's — and the BARE-WORD groups are the
// ones that slip through a suffix test: apps, batch, policy, autoscaling, extensions.
//
// It lives here, in the leaf, because two packages need the same answer and had different ones.
// internal/redact excludes these from the identifier harvest (registering `apps` rewrote the sentence "most
// apps never use" and made `apps/v1` unreadable). internal/collect excluded only "" and *.k8s.io when
// listing an operator's group, so a fleet comparison of two real clusters reported
// "operators.installed: apps, autoscaling, batch, policy" for a docker-desktop with no operator on it.
// KubernetesOwnRBACName reports whether a name is one the Kubernetes project itself ships for an RBAC
// object: the four default ClusterRoles, and everything under the system: and kubeadm: prefixes.
//
// WHY IT EXISTS, AND WHY IT IS A CLOSED SET. A redacted reading said "the built-in ClusterRole res-adca44 by
// name only" — a token where cluster-admin belongs, in a sentence whose own word "built-in" means the name
// is public. These names exist identically on every cluster in the world, so tokenising one protects nobody
// and costs the auditor the sentence. It is the same argument KubernetesOwnGroup makes for API groups, and
// it goes no further than the set below: a customer's own ClusterRole is an identifier like any other.
func KubernetesOwnRBACName(name string) bool {
	switch name {
	case "cluster-admin", "admin", "edit", "view":
		return true
	}
	return strings.HasPrefix(name, "system:") || strings.HasPrefix(name, "kubeadm:")
}

// KubernetesOwnNamespace reports whether a namespace is one Kubernetes reserves for itself. Objects in them
// ship with every cluster and identify nobody — the same closed-set argument KubernetesOwnGroup makes.
func KubernetesOwnNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func KubernetesOwnGroup(g string) bool {
	switch g {
	case "", "apps", "batch", "policy", "autoscaling", "extensions", "networking.k8s.io",
		"rbac.authorization.k8s.io", "storage.k8s.io", "scheduling.k8s.io", "coordination.k8s.io",
		"discovery.k8s.io", "certificates.k8s.io", "admissionregistration.k8s.io", "apiextensions.k8s.io",
		"apiregistration.k8s.io", "authentication.k8s.io", "authorization.k8s.io", "events.k8s.io",
		"flowcontrol.apiserver.k8s.io", "node.k8s.io", "metrics.k8s.io", "resource.k8s.io", "k8s.io":
		return true
	}
	return false
}
