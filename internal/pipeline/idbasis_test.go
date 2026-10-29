package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// idbasis_test.go — THE RECIPE NOW APPLIES TO EVERY FINDING, AND THIS IS THE PROOF.
//
// The published derivation is f- + sha256(RuleID|Kind|Namespace|Name)[:12]. Until 2026-09-07 a reader could
// apply it to a per-object finding and not to an aggregate one, because an aggregate's id was minted from a
// synthesized reference the finding never published — job-no-ttl hashes (Namespace, ns, "jobs-without-ttl")
// while its affected resources are the individual Jobs. Measured over the golden: 105 of 134 checkable, 29
// not, across 21 rules.
//
// THERE IS NO EXCEPTION LIST IN THIS FILE, DELIBERATELY. The previous test carried one and the list was the
// admission that the claim was smaller than it sounded. A rule that mints an id without publishing its basis
// fails here, by name, and the fix is one line at the mint site.

// recompute is the recipe exactly as it is published, with nothing this package knows added to it.
func recompute(ruleID string, b types.ResourceRef) string {
	h := sha256.Sum256([]byte(ruleID + "|" + b.Kind + "|" + b.Namespace + "|" + b.Name))
	return "f-" + hex.EncodeToString(h[:])[:12]
}

func TestEveryFindingID_IsRecomputableFromItsPublishedBasis(t *testing.T) {
	col := collect.NewWithClient(fakeClientsetWithWorkloads(t))
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "test", Log: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertRecomputable(t, "a live run", ar.Findings, 5)
}

// The same recipe over the shipped fixture, which spreads across far more rules than a hand-built inventory
// fires. A claim about "every finding" has to be checked against a cluster-shaped set.
func TestGoldenFindingIDs_AreRecomputableFromTheirPublishedBasis(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatalf("read the golden: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse the golden: %v", err)
	}
	// A reading written before the field existed carries no basis, and that is not a defect in the reading —
	// it is why the fixture is regenerated. Skip the test with a reason rather than failing on history.
	var withBasis int
	for _, f := range ar.Findings {
		if f.IDBasis != nil {
			withBasis++
		}
	}
	if withBasis == 0 {
		t.Skip("the golden predates Finding.IDBasis; regenerate it (make fixture) to bring it under this gate")
	}
	assertRecomputable(t, "the golden", ar.Findings, 100)
}

func assertRecomputable(t *testing.T, what string, findings []types.Finding, floor int) {
	t.Helper()
	if len(findings) < floor {
		t.Fatalf("%s produced %d finding(s), below the floor of %d; this gate would read as coverage it does "+
			"not have", what, len(findings), floor)
	}
	missing, wrong := map[string]bool{}, []string{}
	for _, f := range findings {
		if f.IDBasis == nil {
			missing[f.RuleID] = true
			continue
		}
		if got := recompute(f.RuleID, *f.IDBasis); got != f.ID {
			wrong = append(wrong, fmt.Sprintf("%s (%s): the recipe over %s/%s/%s gives %s",
				f.ID, f.RuleID, f.IDBasis.Kind, f.IDBasis.Namespace, f.IDBasis.Name, got))
		}
	}
	if len(missing) > 0 {
		var ids []string
		for id := range missing {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("%s: %d rule(s) mint an id without publishing its basis, so a reader cannot check them — "+
			"add IDBasis at the mint site:\n  %s", what, len(ids), strings.Join(ids, "\n  "))
	}
	for _, w := range wrong {
		t.Errorf("%s: %s", what, w)
	}
	t.Logf("%s: %d finding(s), every id recomputable from what the finding itself publishes", what, len(findings))
}

// NON-VACUITY. The recipe must actually be the recipe: a wrong basis has to produce a wrong id, or the
// assertions above would pass over any pair of values.
func TestRecompute_IsSensitiveToEverySlot(t *testing.T) {
	base := types.ResourceRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	id := recompute("k8s.workload.no-probes", base)
	for _, alt := range []struct {
		name string
		rule string
		ref  types.ResourceRef
	}{
		{"a different rule", "k8s.workload.runs-as-root", base},
		{"a different kind", "k8s.workload.no-probes", types.ResourceRef{Kind: "StatefulSet", Namespace: "shop", Name: "api"}},
		{"a different namespace", "k8s.workload.no-probes", types.ResourceRef{Kind: "Deployment", Namespace: "prod", Name: "api"}},
		{"a different name", "k8s.workload.no-probes", types.ResourceRef{Kind: "Deployment", Namespace: "shop", Name: "web"}},
	} {
		if recompute(alt.rule, alt.ref) == id {
			t.Errorf("%s produced the same id, so that slot is not in the hash", alt.name)
		}
	}
}
