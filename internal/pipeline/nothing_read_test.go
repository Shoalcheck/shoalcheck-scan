package pipeline

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A RUN THAT READ NOTHING IS NOT A READING, and every surface has to be able to ask that one question the same
// way. Fleet asked it with an inline length test; `audit` never asked it at all, so an unreachable cluster or an
// expired token produced a "0 findings" document at exit 0 and cost a licence slot. NothingRead is the one
// predicate, here, so the CLI, the fleet loop and the app cannot answer it differently.
func TestNothingRead_TheClassesOfRun(t *testing.T) {
	cases := []struct {
		name      string
		collected []string
		unread    []types.UnreadKind
		nothing   bool
		cause     string
	}{
		{name: "unreachable: nothing at all came back", collected: nil,
			unread:  []types.UnreadKind{{Kind: "server-resources", Cause: "not reachable"}, {Kind: "nodes", Cause: "not reachable"}, {Kind: "pods", Cause: "not reachable"}},
			nothing: true, cause: "could not be reached"},
		{name: "every list refused: only discovery answered", collected: []string{"server-resources"},
			unread:  []types.UnreadKind{{Kind: "nodes", Cause: "not permitted"}, {Kind: "pods", Cause: "not permitted"}},
			nothing: true, cause: "not permitted"},
		{name: "timed out", collected: nil,
			unread:  []types.UnreadKind{{Kind: "nodes", Cause: "timed out"}},
			nothing: true, cause: "did not answer in time"},
		{name: "a narrow identity still read something", collected: []string{"server-resources", "nodes"},
			unread:  []types.UnreadKind{{Kind: "pods", Cause: "not permitted"}},
			nothing: false},
		{name: "a full reading", collected: []string{"server-resources", "nodes", "pods"}, nothing: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ar := &types.AuditReport{Cluster: types.ClusterInfo{Name: "prod-eu"},
				Methodology: types.Methodology{CollectedKinds: c.collected, Unread: c.unread}}
			err := NothingRead(ar)
			if (err != nil) != c.nothing {
				t.Fatalf("NothingRead = %v, want nothing-read=%v", err, c.nothing)
			}
			if err == nil {
				return
			}
			var nr *NothingReadError
			if !errors.As(err, &nr) {
				t.Fatalf("the refusal is not a *NothingReadError, so a caller cannot tell it from a failed run: %T", err)
			}
			msg := err.Error()
			for _, want := range []string{"prod-eu", c.cause} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not say %q: %q", want, msg)
				}
			}
			// The words a reader must never be left with: a run that read nothing found nothing, and says so.
			for _, banned := range []string{"0 findings", "no findings", "0 problems"} {
				if strings.Contains(strings.ToLower(msg), banned) {
					t.Errorf("the refusal reads like a clean result (%q): %q", banned, msg)
				}
			}
		})
	}
}

// The fleet loop asks the shared question, so a cluster that only answered discovery is skipped exactly as an
// unreachable one is — it used to be counted as audited, because discovery succeeding made the list non-empty.
func TestRunFleet_UsesTheSharedPredicate(t *testing.T) {
	src := readSource(t, "pipeline.go")
	if !strings.Contains(src, "NothingRead(ar)") {
		t.Error("the fleet loop decides 'nothing was read' inline instead of through NothingRead, so the fleet and " +
			"the single-cluster audit can disagree about the same cluster")
	}
}

// End to end against a refused connection: Run hands back a report (Collect never errors on failed lists), and
// NothingRead is what turns it into a refusal. Port 1 refuses at once, so this needs no cluster and no network.
func TestNothingRead_AnUnreachableRunIsRefused(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	body := `apiVersion: v1
kind: Config
clusters: [{name: dead, cluster: {server: "http://127.0.0.1:1"}}]
users: [{name: none, user: {}}]
contexts: [{name: dead, context: {cluster: dead, user: none}}]
current-context: dead
`
	if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	col, err := collect.New(kc, "dead")
	if err != nil {
		t.Fatal(err)
	}
	ar, err := Run(context.Background(), Options{Collector: col, Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	nr := NothingRead(ar)
	if nr == nil {
		t.Fatalf("a run against a refused connection was accepted as a reading: %d findings, collected %v",
			len(ar.Findings), ar.Methodology.CollectedKinds)
	}
	if !strings.Contains(nr.Error(), "could not be reached") {
		t.Errorf("the refusal does not name the cause: %q", nr.Error())
	}
}

// A rejected credential says what to do about it — the sentence the CLI and the scanner print for an expired token.
func TestNothingRead_ARejectedCredentialSaysSignInAgain(t *testing.T) {
	ar := &types.AuditReport{Cluster: types.ClusterInfo{Name: "prod-eu"}, Methodology: types.Methodology{
		Unread: []types.UnreadKind{{Kind: "nodes", Cause: "credentials not accepted"}, {Kind: "pods", Cause: "credentials not accepted"}}}}
	err := NothingRead(ar)
	if err == nil || !strings.Contains(err.Error(), "did not accept these credentials (401)") || !strings.Contains(err.Error(), "sign in again") {
		t.Errorf("an expired token's refusal does not say what to do: %v", err)
	}
}
