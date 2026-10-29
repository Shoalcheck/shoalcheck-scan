package pipeline

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// owner_test.go — a queue nobody owns is a queue nobody works, and a queue routed by a guess is worse.

func ns(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func nsFinding(id, namespace string) types.Finding {
	return types.Finding{
		ID: id, RuleID: "k8s.workload.no-probes",
		IDBasis:           &types.ResourceRef{Kind: "Deployment", Namespace: namespace, Name: "api"},
		AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: namespace, Name: "api"}},
	}
}

func TestAttachOwner_ResolvesFromTheLabelTheOperatorNamed(t *testing.T) {
	spaces := []corev1.Namespace{
		ns("payments", map[string]string{"team": "wallet"}),
		ns("shop", map[string]string{"team": "storefront", "squad": "other"}),
		ns("legacy", nil), // no label: no owner, and nothing invented
	}
	fs := []types.Finding{nsFinding("f-1", "payments"), nsFinding("f-2", "shop"), nsFinding("f-3", "legacy")}

	attachOwner(fs, spaces, "team")
	for i, want := range []string{"wallet", "storefront", ""} {
		if fs[i].Owner != want {
			t.Errorf("finding %d owner %q, want %q", i+1, fs[i].Owner, want)
		}
	}

	// A DIFFERENT KEY IS A DIFFERENT ANSWER, which is the whole reason the operator names it.
	fs2 := []types.Finding{nsFinding("f-1", "payments"), nsFinding("f-2", "shop")}
	attachOwner(fs2, spaces, "squad")
	if fs2[0].Owner != "" || fs2[1].Owner != "other" {
		t.Errorf("the squad key resolved to %q / %q", fs2[0].Owner, fs2[1].Owner)
	}
}

// NO FLAG MEANS NO OWNER. The product does not pick a key, so with none named nothing is resolved — and
// nothing falls back to a namespace name dressed as a team.
func TestAttachOwner_WithoutAKeyNothingIsInvented(t *testing.T) {
	spaces := []corev1.Namespace{ns("payments", map[string]string{"team": "wallet"})}
	fs := []types.Finding{nsFinding("f-1", "payments")}
	attachOwner(fs, spaces, "")
	if fs[0].Owner != "" {
		t.Errorf("an owner appeared with no label named: %q", fs[0].Owner)
	}
	// And a key nobody carries resolves nothing rather than erroring or guessing.
	attachOwner(fs, spaces, "owner")
	if fs[0].Owner != "" {
		t.Errorf("an unused key produced %q", fs[0].Owner)
	}
}

// A CLUSTER-SCOPED FINDING HAS NO NAMESPACE, so it has no owner — a fact, not a gap, and it must not be
// counted against the coverage figure either.
func TestOwnerCoverage_CountsOnlyWhatCouldHaveAnOwner(t *testing.T) {
	cluster := types.Finding{ID: "f-c", RuleID: "k8s.reliability.single-control-plane",
		IDBasis: &types.ResourceRef{Kind: "Cluster", Name: "single-control-plane"}}
	fs := []types.Finding{nsFinding("f-1", "payments"), nsFinding("f-2", "legacy"), cluster}
	attachOwner(fs, []corev1.Namespace{ns("payments", map[string]string{"team": "wallet"})}, "team")

	owned, ownable := ownerCoverage(fs)
	if ownable != 2 {
		t.Errorf("ownable %d, want 2 — the cluster-scoped finding has no namespace to read a label from", ownable)
	}
	if owned != 1 {
		t.Errorf("owned %d, want 1", owned)
	}
	// NON-VACUITY: with no label named, nothing is owned but the denominator is unchanged, so a reader can
	// still see how much of the reading COULD be routed.
	clean := []types.Finding{nsFinding("f-1", "payments"), cluster}
	attachOwner(clean, nil, "")
	if o, n := ownerCoverage(clean); o != 0 || n != 1 {
		t.Errorf("with no label named, coverage is %d of %d, want 0 of 1", o, n)
	}
}

// The namespace comes from the id's own basis when there is one, because that is the resource the finding is
// keyed on — an aggregate finding names many resources and the first of them need not be the one it is about.
func TestFindingNamespace_PrefersTheIDBasis(t *testing.T) {
	f := types.Finding{
		IDBasis:           &types.ResourceRef{Kind: "Namespace", Namespace: "payments", Name: "jobs-without-ttl"},
		AffectedResources: []types.ResourceRef{{Kind: "Job", Namespace: "shop", Name: "nightly"}},
	}
	if got := findingNamespace(f); got != "payments" {
		t.Errorf("namespace %q, want the basis's payments", got)
	}
	// And falls back for a reading written before IDBasis existed.
	old := types.Finding{AffectedResources: []types.ResourceRef{{Kind: "Job", Namespace: "shop", Name: "nightly"}}}
	if got := findingNamespace(old); got != "shop" {
		t.Errorf("namespace %q, want shop from the affected resource", got)
	}
}
