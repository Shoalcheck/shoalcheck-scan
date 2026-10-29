package pipeline

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A cluster nothing could be read from is not a cluster with no problems.
//
// Collect returns NO error when every list fails — it records the failures and hands back an empty inventory —
// so an unreachable cluster produced a perfectly successful report with zero findings, was appended to the fleet
// as an audited member, and folded into the fleet totals as a clean one. The skip was a line on stderr, which
// nobody keeps, so the HTML showed three clusters where five were asked for with nothing to distinguish
// unreachable from clean.
//
// Asserted at the source, because reproducing a five-cluster fleet with two unreachable members needs five
// clusters. The two properties being pinned are one-line decisions each.
func TestRunFleet_DoesNotCountAnUnreadableClusterAsAudited(t *testing.T) {
	src := readSource(t, "pipeline.go")

	if !strings.Contains(src, "NothingRead(ar) != nil") {
		t.Error("the fleet loop does not check whether anything was actually read, so an unreachable cluster " +
			"is still counted as an audited member")
	}
	// The reason must be classified, never the raw error: a Go error from client-go carries the API server URL.
	if !strings.Contains(src, "collect.ClassifyCause(err.Error())") {
		t.Error("a fleet skip reason is not classified, so the report would carry the API's own error text")
	}
	if strings.Contains(src, `Reason: err.Error()`) {
		t.Error("a fleet skip reason is the raw error text")
	}
}

// THE SKIP LIST TRAVELS IN THE DOCUMENT — asserted on behaviour, not on a spelling.
//
// This used to be a source grep for the literal `fr.Skipped = skipped`, which is a fact about one line
// rather than about the document. When the assignment moved into assembleFleet on 2026-08-30 (the divergence
// surface needs the skip list too, and a field set AFTER assembly is a field the assembler cannot use) the
// grep failed on a refactor that preserved the property exactly. A gate that fires on a non-defect teaches
// the next person to weaken it.
//
// assembleFleet is unit-testable without a cluster, so the property is now observable where it lives.
func TestAssembleFleet_CarriesTheSkipListIntoTheDocument(t *testing.T) {
	fr, err := assembleFleet(
		[]*types.AuditReport{syntheticReport(t, "a", 1), syntheticReport(t, "b", 1)},
		[]types.SkippedCluster{{Context: "eu-prod", Reason: "not reachable"}}, false)
	if err != nil {
		t.Fatalf("assembleFleet: %v", err)
	}
	if len(fr.Skipped) != 1 || fr.Skipped[0].Context != "eu-prod" {
		t.Fatalf("the skip list did not reach the document: %+v", fr.Skipped)
	}
	// And a fleet with no skips carries an EMPTY list rather than a placeholder — a reader must be able to
	// tell "nothing was skipped" from "one entry we could not describe".
	clean, err := assembleFleet([]*types.AuditReport{syntheticReport(t, "a", 1), syntheticReport(t, "b", 1)}, nil, false)
	if err != nil {
		t.Fatalf("assembleFleet: %v", err)
	}
	if len(clean.Skipped) != 0 {
		t.Errorf("a fleet with no skips carries %d entry/entries", len(clean.Skipped))
	}
}

// One classifier, so a network failure is never described two different ways in one document.
func TestClassifyCause_IsSharedWithTheDenialPath(t *testing.T) {
	cases := map[string]string{
		`Get "https://prod.acme.internal:6443/api": dial tcp: connect: connection refused`: "not reachable",
		`pods is forbidden: User "system:serviceaccount:x:y" cannot list`:                  "not permitted",
		`context deadline exceeded`: "timed out",
	}
	for in, want := range cases {
		got := collect.ClassifyCause(in)
		if got != want {
			t.Errorf("ClassifyCause(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, "acme") || strings.Contains(got, "serviceaccount") || strings.Contains(got, "6443") {
			t.Errorf("the classified cause carries the error text: %q", got)
		}
	}
}

// readSource reads a file from this package for the source-level assertions above.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// The all-failed message must be usable. It was built from errors.Join(failures...), and a cluster can now be
// skipped WITHOUT an error — the "nothing could be read" case returns none — so with every cluster skipped that
// way the slice was empty, Join returned nil, and %w rendered the literal "%!w(<nil>)" as the entire explanation.
// Found by running it, not by a test, which is why it is a test now.
func TestRunFleet_AllSkippedMessageNamesEachContext(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	// Port 1 is reserved and refuses instantly, so this needs no cluster and no network.
	body := `apiVersion: v1
kind: Config
clusters: [{name: dead, cluster: {server: "http://127.0.0.1:1"}}]
users: [{name: none, user: {}}]
contexts:
  - {name: dead-a, context: {cluster: dead, user: none}}
  - {name: dead-b, context: {cluster: dead, user: none}}
current-context: dead-a
`
	if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	_, err := RunFleet(context.Background(), FleetOptions{
		Kubeconfig: kc,
		Contexts:   []string{"dead-a", "dead-b"},
		Log:        io.Discard,
	})
	if err == nil {
		t.Fatal("a fleet where nothing could be read returned no error")
	}
	msg := err.Error()
	if strings.Contains(msg, "%!w") || strings.Contains(msg, "<nil>") {
		t.Errorf("the message is a formatting artefact rather than an explanation: %q", msg)
	}
	for _, want := range []string{"dead-a", "dead-b", "nothing could be read"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not mention %q: %q", want, msg)
		}
	}
}

// Every binary that runs an audit must record it. shoalcheck-scan is the OSS one — the binary whose SOURCE people read
// before they trust it — so it is the last place that should emit a report making a read-only claim with no
// measurement behind it. It was built without a recorder while both other binaries had one.
//
// Asserted at the source: the alternative is a test that runs the scan binary against a cluster, and the property
// being pinned is one line in each of three files.
func TestEveryAuditBinaryInstallsTheRecorder(t *testing.T) {
	for _, f := range []string{
		"../../cmd/shoalcheck/main.go",
		"../../cmd/shoalcheck-scan/main.go",
		"../../cmd/shoalcheck-app/app.go",
	} {
		src := readSource(t, f)
		if !strings.Contains(src, "collect.WithTransportRecorder") {
			t.Errorf("%s builds a collector without a request recorder, so its report would claim read-only "+
				"behaviour with nothing measuring it", f)
		}
		if !strings.Contains(src, "Recorder:") {
			t.Errorf("%s does not pass a recorder into the pipeline, so no session-trace appendix is produced", f)
		}
	}
}
