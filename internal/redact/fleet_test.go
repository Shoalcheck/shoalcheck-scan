package redact

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func minimalReport(name string) *types.AuditReport {
	return &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: name},
		Summary:       types.Summary{},
	}
}

// A REDACTED FLEET OF TWO CLUSTERS DID NOT VALIDATE, WHICH MEANS IT DID NOT EXIST.
//
// redact.Report set Cluster.Name to the constant "cluster". A fleet is two or more clusters by definition,
// FleetReport.Validate rejects a duplicate name — "Cluster.Name is the stable key for the switcher", says
// the type — so `shoalcheck fleet --redact` produced an invalid document the moment it audited a second cluster.
// The feature that makes a reading shareable was unusable on the reading that most needs sharing.
func TestRedact_FleetClustersStayDistinct(t *testing.T) {
	a, b := Report(minimalReport("acme-prod-eu")), Report(minimalReport("acme-prod-us"))
	if a.Cluster.Name == b.Cluster.Name {
		t.Fatalf("both clusters redacted to %q: a fleet keyed on this name cannot tell them apart, and "+
			"FleetReport.Validate rejects the duplicate outright", a.Cluster.Name)
	}
	for _, n := range []string{a.Cluster.Name, b.Cluster.Name} {
		if strings.Contains(n, "acme") {
			t.Errorf("the original name survives in %q", n)
		}
		if n == "" {
			t.Error("a cluster with no name fails validation for a different reason")
		}
	}
	// STABLE, because a token that moved between runs would make two readings of one cluster incomparable.
	if again := Report(minimalReport("acme-prod-eu")); again.Cluster.Name != a.Cluster.Name {
		t.Errorf("the same cluster tokenized to %q and then %q", a.Cluster.Name, again.Cluster.Name)
	}

	fr := &types.FleetReport{SchemaVersion: "v1", Clusters: []*types.AuditReport{a, b}}
	if err := fr.Validate(); err != nil {
		t.Errorf("a redacted two-cluster fleet does not validate: %v", err)
	}
}

// AND THE CONTEXTS IT COULD NOT READ ARE NOT "a local name the operator chose".
//
// SkippedCluster.Context said so and left the string verbatim. In practice a kubeconfig context is written
// by cloud tooling and carries the account, the region and the cluster: an EKS context is
// `arn:aws:eks:<region>:<account-id>:cluster/<name>`, a GKE one is `gke_<project>_<zone>_<cluster>`. The
// cluster's own name is redacted two fields away, and printing the context that contains it is not a
// coherent position.
func TestRedact_FleetSkippedContextsAreTokenized(t *testing.T) {
	fr := &types.FleetReport{
		SchemaVersion: "v1",
		Clusters:      []*types.AuditReport{Report(minimalReport("acme-prod-eu"))},
		Skipped: []types.SkippedCluster{
			{Context: "arn:aws:eks:us-east-1:069874459391:cluster/acme-onprem", Reason: "not permitted"},
			{Context: "gke_acmebank-prod_europe-west1_payments", Reason: "not reachable"},
		},
	}
	out := Fleet(fr)

	for _, s := range out.Skipped {
		for _, leak := range []string{"acme", "069874459391", "acmebank", "us-east-1", "europe-west1"} {
			if strings.Contains(s.Context, leak) {
				t.Errorf("a skipped context still carries %q: %s", leak, s.Context)
			}
		}
		if s.Context == "" {
			t.Error("a skipped context was blanked rather than tokenized: the reader has to be able to tell " +
				"two unreachable clusters apart, and an empty string says one was not asked for")
		}
	}
	// THE REASON IS THIS PRODUCT'S OWN VOCABULARY and must survive intact.
	if out.Skipped[0].Reason != "not permitted" || out.Skipped[1].Reason != "not reachable" {
		t.Errorf("a classified reason was rewritten: %+v", out.Skipped)
	}
	// Two different contexts stay two different tokens.
	if out.Skipped[0].Context == out.Skipped[1].Context {
		t.Error("two skipped contexts collapsed to one token")
	}
	// The input is not mutated.
	if !strings.Contains(fr.Skipped[0].Context, "069874459391") {
		t.Error("Fleet mutated its input")
	}
}

// THE SAME LIST IS REACHED TWICE, AND BOTH HAVE TO SAY THE SAME NAME.
//
// FleetDivergence.Unreached is built from the same skipped slice before redaction runs. Tokenizing one and
// not the other leaks the context on the divergence screen AND makes two surfaces of one document disagree
// about what an unreachable cluster is called.
func TestRedact_FleetDivergenceUnreachedMatchesSkipped(t *testing.T) {
	const ctx = "gke_acmebank-prod_europe-west1_payments"
	fr := &types.FleetReport{
		SchemaVersion: "v1",
		Clusters:      []*types.AuditReport{Report(minimalReport("acme-prod-eu"))},
		Skipped:       []types.SkippedCluster{{Context: ctx, Reason: "not reachable"}},
		Divergence: &types.FleetDivergence{
			Unreached: []types.SkippedCluster{{Context: ctx, Reason: "not reachable"}},
		},
	}
	out := Fleet(fr)
	if out.Divergence == nil || len(out.Divergence.Unreached) != 1 {
		t.Fatalf("divergence lost its unreached list: %+v", out.Divergence)
	}
	got := out.Divergence.Unreached[0].Context
	if strings.Contains(got, "acmebank") || strings.Contains(got, "europe-west1") {
		t.Errorf("the divergence screen still names the context: %q", got)
	}
	if got != out.Skipped[0].Context {
		t.Errorf("two surfaces name one unreachable cluster differently: %q and %q",
			got, out.Skipped[0].Context)
	}
	if fr.Divergence.Unreached[0].Context != ctx {
		t.Error("Fleet mutated its input's divergence")
	}
}
