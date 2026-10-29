// Package apiremoval holds the Kubernetes API-removal schedule: which group/version a release stops
// serving.
//
// THE SECOND PERMANENT MAINTENANCE OBLIGATION, ACCEPTED DELIBERATELY (engine-ceiling spec §11 Q2). The
// first is pricing. A table that ages is a liability — it is wrong quietly, and a stale one produces a
// confident sentence about a release that has already happened — so it is accepted only because the
// alternative is worse: an upgrade finding computed from no schedule at all is not a weaker claim, it is
// a guess.
//
// WHAT MAKES IT SAFE IS THAT IT IS STAMPED AND ITS STALENESS IS A GATE. AsOf is compared against the
// build's own horizon by TestAPIRemoval_TableIsNotStale, on the shape scripts/update-pricing.py
// established, and internal/refdata carries it as a bundle dataset so an operator can refresh it without
// a new binary.
//
// SOURCE. The upstream deprecated-API migration guide,
// https://kubernetes.io/docs/reference/using-api/deprecation-guide/ — the only authoritative list, and
// the reason no entry here is inferred from a version number's shape.
package apiremoval

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// asOf is the date the table below was last reconciled against the upstream guide. It is deliberately a
// DATE rather than a Kubernetes version: the guide is edited between releases, and a version stamp would
// claim currency the table may not have.
const asOf = "2026-08-30"

// AsOf reports when this table was last reconciled with the upstream guide.
func AsOf() string { return asOf }

// Removal is one group/version and the release that stops serving it.
type Removal struct {
	// GroupVersion is the served identifier exactly as discovery reports it — "apps/v1beta2",
	// "batch/v1beta1", "v1" for the core group.
	GroupVersion string
	// RemovedIn is the Kubernetes minor release that removes it, as "1.32".
	RemovedIn string
	// Replacement is the group/version to move to, or "" where the guide names none.
	Replacement string
	// Kinds are the kinds affected, for the finding's evidence. Empty means the whole group/version.
	Kinds []string

	// ReintroducedIn is the release at which this group/version STARTS BEING SERVED AGAIN, for different
	// kinds, as "1.28" — or "" for the ordinary case where it never returns.
	//
	// B-155, found on a live v1.28 cluster during the §8 sweep. A group/version string is not a stable
	// identity across releases: `admissionregistration.k8s.io/v1beta1` was removed in 1.22 carrying
	// MutatingWebhookConfiguration and came back in 1.28 carrying ValidatingAdmissionPolicy, and
	// `storage.k8s.io/v1beta1` lost its original types in 1.22 and CSIStorageCapacity in 1.27. Matching on
	// the string alone reads the second life as the first, so a server correctly serving the NEW kinds is
	// measured against the OLD removal.
	//
	// The entry applies only to servers BELOW this version. Above it, the string means something else and
	// this row has nothing to say about it.
	ReintroducedIn string
}

// appliesBelow reports whether this removal is about the group/version as a server at major.minor serves
// it. An entry with no ReintroducedIn always applies.
func (r Removal) appliesBelow(major, minor int) bool {
	if r.ReintroducedIn == "" {
		return true
	}
	rMaj, rMin, ok := parseMinor(r.ReintroducedIn)
	if !ok {
		// AN UNPARSEABLE REINTRODUCTION DISARMS THE ROW rather than being ignored. A row we cannot reason
		// about is a row that must not produce a warning: the failure mode of a spurious upgrade warning
		// is an operator chasing a removal that does not exist.
		return false
	}
	return major < rMaj || (major == rMaj && minor < rMin)
}

// parseMinor reads "1.28" into comparable integers. A major below 1 is rejected: "0.0.0-master+$Format:%H$"
// is what an unstamped build reports, and comparing against it would make every removal look imminent.
func parseMinor(s string) (major, minor int, ok bool) {
	m := minorRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(m[1])
	b, e2 := strconv.Atoi(m[2])
	if e1 != nil || e2 != nil || a < 1 {
		return 0, 0, false
	}
	return a, b, true
}

var minorRe = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// Applicable is For, narrowed to the removals that are about this group/version AS A SERVER AT
// major.minor SERVES IT. This is what a rule should call; For is the raw table lookup and is kept for
// tests and for callers with no server version in hand.
func Applicable(groupVersion string, major, minor int) []Removal {
	var out []Removal
	for _, r := range For(groupVersion) {
		if r.appliesBelow(major, minor) {
			out = append(out, r)
		}
	}
	return out
}

// table is the schedule. ONLY REMOVALS THE UPSTREAM GUIDE STATES, never a version inferred from a
// deprecation notice: a deprecated version is still served, sometimes for many releases, and reporting a
// deprecation as a removal would be the overclaim this whole epic is built to avoid.
var table = []Removal{
	// Removed in 1.22 — the largest single removal, and still the most common finding on old clusters.
	{GroupVersion: "apiextensions.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "apiextensions.k8s.io/v1",
		Kinds: []string{"CustomResourceDefinition"}},
	{GroupVersion: "apiregistration.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "apiregistration.k8s.io/v1",
		Kinds: []string{"APIService"}},
	{GroupVersion: "admissionregistration.k8s.io/v1beta1", RemovedIn: "1.22",
		Replacement: "admissionregistration.k8s.io/v1",
		Kinds:       []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"},
		// Beta again from 1.28 for ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding. See
		// Removal.ReintroducedIn and B-155: a real v1.28 cluster serves this and is entirely current.
		ReintroducedIn: "1.28"},
	{GroupVersion: "rbac.authorization.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "rbac.authorization.k8s.io/v1",
		Kinds: []string{"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}},
	{GroupVersion: "certificates.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "certificates.k8s.io/v1",
		Kinds: []string{"CertificateSigningRequest"}},
	{GroupVersion: "coordination.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "coordination.k8s.io/v1",
		Kinds: []string{"Lease"}},
	{GroupVersion: "networking.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "networking.k8s.io/v1",
		Kinds: []string{"Ingress", "IngressClass"}},
	{GroupVersion: "extensions/v1beta1", RemovedIn: "1.22", Replacement: "networking.k8s.io/v1",
		Kinds: []string{"Ingress"}},
	{GroupVersion: "scheduling.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "scheduling.k8s.io/v1",
		Kinds: []string{"PriorityClass"}},
	{GroupVersion: "storage.k8s.io/v1beta1", RemovedIn: "1.22", Replacement: "storage.k8s.io/v1",
		Kinds: []string{"CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"},
		// CSIStorageCapacity arrived at this same group/version in 1.24 and is removed in 1.27, which is
		// the row below. From 1.24 on, a server serving storage.k8s.io/v1beta1 is serving that.
		ReintroducedIn: "1.24"},

	// Removed in 1.25.
	{GroupVersion: "batch/v1beta1", RemovedIn: "1.25", Replacement: "batch/v1",
		Kinds: []string{"CronJob"}},
	{GroupVersion: "discovery.k8s.io/v1beta1", RemovedIn: "1.25", Replacement: "discovery.k8s.io/v1",
		Kinds: []string{"EndpointSlice"}},
	{GroupVersion: "events.k8s.io/v1beta1", RemovedIn: "1.25", Replacement: "events.k8s.io/v1",
		Kinds: []string{"Event"}},
	{GroupVersion: "autoscaling/v2beta1", RemovedIn: "1.25", Replacement: "autoscaling/v2",
		Kinds: []string{"HorizontalPodAutoscaler"}},
	{GroupVersion: "policy/v1beta1", RemovedIn: "1.25", Replacement: "policy/v1",
		Kinds: []string{"PodDisruptionBudget", "PodSecurityPolicy"}},
	{GroupVersion: "node.k8s.io/v1beta1", RemovedIn: "1.25", Replacement: "node.k8s.io/v1",
		Kinds: []string{"RuntimeClass"}},

	// Removed in 1.26.
	{GroupVersion: "flowcontrol.apiserver.k8s.io/v1beta1", RemovedIn: "1.26",
		Replacement: "flowcontrol.apiserver.k8s.io/v1beta3",
		Kinds:       []string{"FlowSchema", "PriorityLevelConfiguration"}},
	{GroupVersion: "autoscaling/v2beta2", RemovedIn: "1.26", Replacement: "autoscaling/v2",
		Kinds: []string{"HorizontalPodAutoscaler"}},

	// Removed in 1.27.
	{GroupVersion: "storage.k8s.io/v1beta1", RemovedIn: "1.27", Replacement: "storage.k8s.io/v1",
		Kinds: []string{"CSIStorageCapacity"}},

	// Removed in 1.29.
	{GroupVersion: "flowcontrol.apiserver.k8s.io/v1beta2", RemovedIn: "1.29",
		Replacement: "flowcontrol.apiserver.k8s.io/v1",
		Kinds:       []string{"FlowSchema", "PriorityLevelConfiguration"}},

	// Removed in 1.32.
	{GroupVersion: "flowcontrol.apiserver.k8s.io/v1beta3", RemovedIn: "1.32",
		Replacement: "flowcontrol.apiserver.k8s.io/v1",
		Kinds:       []string{"FlowSchema", "PriorityLevelConfiguration"}},
}

// All returns the schedule, sorted by removing release then group/version, so a report's order is stable
// across runs and two readings of one cluster diff by eye.
func All() []Removal {
	out := append([]Removal(nil), table...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].RemovedIn != out[j].RemovedIn {
			return out[i].RemovedIn < out[j].RemovedIn
		}
		return out[i].GroupVersion < out[j].GroupVersion
	})
	return out
}

// For returns every scheduled removal of a served group/version. A group/version can appear more than
// once — storage.k8s.io/v1beta1 lost different kinds in 1.22 and 1.27 — so this returns a slice and the
// caller reports the EARLIEST, which is the one that matters.
func For(groupVersion string) []Removal {
	var out []Removal
	for _, r := range table {
		if r.GroupVersion == groupVersion {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemovedIn < out[j].RemovedIn })
	return out
}
