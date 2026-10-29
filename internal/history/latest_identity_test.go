package history

import (
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// LATEST MUST RETURN A READING OF THIS CLUSTER, NOT THE NEWEST FILE IN A DIRECTORY.
//
// The store keys a directory on slug(Cluster.Name) with no identity check, so two clusters that report the
// same display name — "production" in two orgs, "kind" on two machines whose dotfiles sync — share one
// directory. The LISTING is honest about that already: ClusterRef.DistinctUIDs counts every snapshot's UID
// and the row says "this directory holds readings of N different clusters … so its runs are not one
// timeline". The SELECTION was not: List returns every .json in the directory and Latest takes the newest
// of them, whichever cluster wrote it.
//
// Downstream, `shoalcheck audit` and the app ask Latest for "the prior reading" and hand it to the comparison
// gates, which refuse on a ClusterUID mismatch — so no wrong DIFF is produced. What is produced is a
// refusal whose reason is somebody else's cluster, and a caller that does not run the gates (a "latest of
// this cluster" lookup) gets a stranger's reading outright.
//
// A caller that knows which cluster it is asking about should get that cluster.
func TestLatest_ReturnsThisClustersReadingNotTheNewestFile(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	const name = "production"
	mine, theirs := "uid-mine-0001", "uid-theirs-0002"

	// Mine is older; theirs is newer. Both land in slug("production").
	older := report(name, mine, 2)
	if _, err := s.Save(older, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	newer := report(name, theirs, 7)
	if _, err := s.Save(newer, time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	// The mixture is real and the listing says so — asserted here so this test fails loudly if the store
	// ever starts separating them, rather than silently proving nothing.
	refs, err := s.Clusters()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].DistinctUIDs != 2 {
		t.Fatalf("expected one directory holding two cluster identities; got %+v", refs)
	}

	at := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)

	// The identity-blind call is what shipped: it returns the newest file, which is the other cluster.
	if ar, _, ok, err := s.LatestOf(name, "", at); err != nil {
		t.Fatal(err)
	} else if !ok || ar.Methodology.RunBasis.ClusterUID != theirs {
		t.Fatalf("Latest is expected to return the newest file regardless of identity; got ok=%v uid=%v",
			ok, ar.Methodology.RunBasis)
	}

	// LatestOf, given the identity the caller already holds, returns THIS cluster's reading.
	ar, when, ok, err := s.LatestOf(name, mine, at)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("LatestOf found nothing for a cluster with a saved reading in that directory")
	}
	if got := ar.Methodology.RunBasis.ClusterUID; got != mine {
		t.Errorf("LatestOf returned uid %q, want %q — a caller asking for its own cluster got a stranger's", got, mine)
	}
	if !when.Equal(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("LatestOf returned the reading at %s", when)
	}

	// AN UNKNOWN IDENTITY IS NOT A DIFFERENT ONE. A reading whose kube-system UID could not be read has
	// no identity to match on, so the honest behaviour is the identity-blind one — never "no prior".
	blind, _, ok, err := s.LatestOf(name, "", at)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || blind.Methodology.RunBasis.ClusterUID != theirs {
		t.Errorf("LatestOf with no identity did not fall back to the newest reading: ok=%v", ok)
	}

	// AND A SNAPSHOT CARRIES ITS IDENTITY, so a caller can tell without loading the whole file.
	snaps, err := s.List(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("List returned %d snapshot(s)", len(snaps))
	}
	seen := map[string]bool{}
	for _, sn := range snaps {
		seen[sn.ClusterUID] = true
	}
	if !seen[mine] || !seen[theirs] {
		t.Errorf("List's snapshots do not carry their cluster identity: %+v", snaps)
	}
}

var _ = types.AuditReport{}

// A SNAPSHOT WITH NO RECORDED IDENTITY IS STILL THIS CLUSTER'S PRIOR.
//
// A reading taken while kube-system was denied records no ClusterUID. Skipping it when the caller does have
// an identity would be the flinch this product exists to refuse: it would turn "this snapshot's identity was
// never read" into "this snapshot is of a different cluster", and the visible result would be "no prior
// reading" — an absence reported as a fact.
//
// The honest chain is: eligible here, then refused downstream WITH ITS REASON. Gate 0 (diff.go) refuses to
// compare two readings when a ClusterUID is missing and names that as the cause, so the operator learns
// "a prior exists and could not be confirmed to be this cluster" instead of "there is no prior".
func TestLatestOf_AnUnrecordedIdentityIsNotADifferentCluster(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	const name = "production"
	const mine = "uid-mine-0001"

	if _, err := s.Save(report(name, mine, 2), time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	// Newer, and its kube-system read was denied, so it carries no identity.
	if _, err := s.Save(report(name, "", 5), time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	ar, when, ok, err := s.LatestOf(name, mine, at)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("LatestOf reported no prior reading; the newest snapshot merely has no identity recorded, " +
			"which is not the same as being another cluster")
	}
	if uid := ar.Methodology.RunBasis.ClusterUID; uid != "" {
		t.Errorf("expected the identity-less snapshot (the newest); got uid %q", uid)
	}
	if !when.Equal(time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("LatestOf skipped the newest eligible snapshot and answered with %s", when)
	}
}

// A DIFFERENT CLUSTER IS SKIPPED EVEN WHEN IT IS THE ONLY THING IN THE DIRECTORY.
//
// Then there is genuinely no prior reading of this cluster, and "no prior" is the true answer — the case
// that separates "filter" from "fall back to the newest whatever it is".
func TestLatestOf_OnlyAStrangersReadingMeansNoPrior(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	const name = "production"
	if _, err := s.Save(report(name, "uid-theirs-0002", 7), time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := s.LatestOf(name, "uid-mine-0001", time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("LatestOf returned a reading of a different cluster as this cluster's prior")
	}
}
