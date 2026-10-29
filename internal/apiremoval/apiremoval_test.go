package apiremoval

import (
	"testing"
	"time"
)

// staleAfter is how long the table may go un-reconciled before the build fails.
//
// A YEAR, AND THE NUMBER IS AN ARGUMENT. Kubernetes ships three minor releases a year, and the
// deprecation guide is edited between them. A table older than a year has certainly missed a removal, and
// a MISSED removal is the dangerous direction: the rule then says nothing about a group/version that is
// about to stop being served, which reads exactly like a clean cluster.
const staleAfter = 365 * 24 * time.Hour

// TestAPIRemoval_TableIsNotStale is the gate that makes the second maintenance obligation survivable. A
// table that ages silently is the defect; this makes it age loudly.
func TestAPIRemoval_TableIsNotStale(t *testing.T) {
	stamped, err := time.Parse("2006-01-02", AsOf())
	if err != nil {
		t.Fatalf("AsOf() is not a date: %q", AsOf())
	}
	if age := time.Since(stamped); age > staleAfter {
		t.Errorf("the API-removal table was last reconciled with the upstream guide %.0f days ago "+
			"(%s), past the %.0f-day floor. Kubernetes ships three minor releases a year, so a table "+
			"this old has missed a removal — and a MISSED removal makes the rule silent about a "+
			"group/version that is about to stop being served, which reads exactly like a clean cluster.\n"+
			"      Reconcile against https://kubernetes.io/docs/reference/using-api/deprecation-guide/ "+
			"and move asOf.", age.Hours()/24, AsOf(), staleAfter.Hours()/24)
	}
}

// Every entry must be shaped like a schedule entry. A malformed one produces a finding naming a release
// that does not exist, which is worse than no finding.
func TestAPIRemoval_EveryEntryIsWellFormed(t *testing.T) {
	all := All()
	if len(all) < 10 {
		t.Fatalf("the table holds %d entries; it is meant to carry the upstream guide's removals and "+
			"anything this short means it was truncated", len(all))
	}
	seen := map[string]bool{}
	for _, r := range all {
		if r.GroupVersion == "" || r.RemovedIn == "" {
			t.Errorf("entry %+v has an empty group/version or release", r)
		}
		// "1.22" — a minor release, never a patch and never a v-prefix, because the comparison is done
		// against a parsed major.minor and a stray "v" would silently never match.
		if r.RemovedIn[0] == 'v' {
			t.Errorf("%s: RemovedIn is %q — the comparison parses major.minor, so a v-prefix never "+
				"matches and the entry would be silently dead", r.GroupVersion, r.RemovedIn)
		}
		if r.Replacement == r.GroupVersion {
			t.Errorf("%s: replacement is itself", r.GroupVersion)
		}
		key := r.GroupVersion + "@" + r.RemovedIn
		if seen[key] {
			t.Errorf("duplicate entry %s", key)
		}
		seen[key] = true
	}
}

// A group/version removed in two releases must return the EARLIEST first — storage.k8s.io/v1beta1 lost
// different kinds in 1.22 and 1.27, and reporting the later one would understate the urgency.
func TestAPIRemoval_ForReturnsTheEarliestFirst(t *testing.T) {
	got := For("storage.k8s.io/v1beta1")
	if len(got) < 2 {
		t.Fatalf("storage.k8s.io/v1beta1 has %d entries; the table records two removals for it and this "+
			"test exists to pin the ordering between them", len(got))
	}
	if got[0].RemovedIn != "1.22" {
		t.Errorf("For returned %s first, want the earliest (1.22)", got[0].RemovedIn)
	}
}

// A served version this product does not know is NOT a removal. Returning something for an unknown
// group/version would let the rule invent a schedule.
func TestAPIRemoval_AnUnknownGroupVersionHasNoSchedule(t *testing.T) {
	for _, gv := range []string{"apps/v1", "v1", "acme.example/v1alpha1", ""} {
		if got := For(gv); len(got) != 0 {
			t.Errorf("For(%q) returned %d entries — a group/version the guide does not list has no "+
				"scheduled removal, and inventing one is the overclaim this epic exists to avoid", gv, len(got))
		}
	}
}

// B-155 — A GROUP/VERSION CAN BE REMOVED AND THEN REINTRODUCED FOR DIFFERENT KINDS, and keying a removal
// on the group/version string alone reads the second life as the first one.
//
// FOUND ON A LIVE CLUSTER, not by reasoning: the §8 honesty sweep ran an independent recount against three
// real AKS clusters and `aks-shop-prod-westus3-01`, a v1.28.15 server, reported
// `admissionregistration.k8s.io/v1beta1` as served — with `kubectl get apiservices` confirming it is a
// Local built-in, not an aggregated re-registration.
//
// Both facts are true and they are about different kinds:
//
//	admissionregistration.k8s.io/v1beta1  removed in 1.22   MutatingWebhookConfiguration, ValidatingWebhookConfiguration
//	admissionregistration.k8s.io/v1beta1  BETA from 1.28    ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding
//
// The safety valve held — the entry landed in the already-past bucket and no upgrade warning was printed —
// but the disclosure sentence would have told the operator that this reading's schedule may be wrong, on a
// cluster where the served version is entirely current. `storage.k8s.io/v1beta1` has the same shape:
// removed in 1.22 for the older types and again in 1.27 for CSIStorageCapacity.
func TestRemovals_AReintroducedGroupVersionDoesNotMatchItsOldRemoval(t *testing.T) {
	// A 1.28 server serving admissionregistration.k8s.io/v1beta1 is serving ValidatingAdmissionPolicy.
	// The 1.22 removal must not apply to it.
	for _, r := range For("admissionregistration.k8s.io/v1beta1") {
		if r.RemovedIn == "1.22" && r.appliesBelow(1, 28) {
			t.Error("the 1.22 removal of admissionregistration.k8s.io/v1beta1 still applies at 1.28, " +
				"where that group/version carries ValidatingAdmissionPolicy instead")
		}
		if r.RemovedIn == "1.22" && !r.appliesBelow(1, 21) {
			t.Error("the 1.22 removal stopped applying at 1.21, where it is genuinely the webhook types")
		}
	}
	if got := Applicable("admissionregistration.k8s.io/v1beta1", 1, 28); len(got) != 0 {
		t.Errorf("a v1.28 server serving admissionregistration.k8s.io/v1beta1 matched %d removal(s); "+
			"that group/version was reintroduced in 1.28 for ValidatingAdmissionPolicy", len(got))
	}
	// NON-VACUITY, and it is the half that matters: below the reintroduction the removal DOES apply, so a
	// fix that simply deleted the entry would fail here.
	if got := Applicable("admissionregistration.k8s.io/v1beta1", 1, 21); len(got) != 1 {
		t.Errorf("a v1.21 server serving admissionregistration.k8s.io/v1beta1 matched %d removal(s), "+
			"want 1 — there it really is the webhook configuration types", len(got))
	}
	// And an ordinary entry is unaffected in both directions.
	if got := Applicable("flowcontrol.apiserver.k8s.io/v1beta3", 1, 28); len(got) != 1 {
		t.Errorf("flowcontrol.apiserver.k8s.io/v1beta3 at 1.28 matched %d, want 1", len(got))
	}
	if got := Applicable("apps/v1", 1, 28); len(got) != 0 {
		t.Errorf("apps/v1 matched %d removal(s)", len(got))
	}
}

// storage.k8s.io/v1beta1 is the second instance of the same shape, and it is the one that proves this is a
// class rather than a special case: removed in 1.22 for the original types, and again in 1.27 for
// CSIStorageCapacity, which was introduced at that group/version in 1.24.
func TestRemovals_TheSecondReintroducedGroupVersionBehavesTheSameWay(t *testing.T) {
	at125 := Applicable("storage.k8s.io/v1beta1", 1, 25)
	if len(at125) != 1 || at125[0].RemovedIn != "1.27" {
		t.Fatalf("a v1.25 server serving storage.k8s.io/v1beta1 is serving CSIStorageCapacity, whose "+
			"removal is 1.27; got %+v", at125)
	}
}
