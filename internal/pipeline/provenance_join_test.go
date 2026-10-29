package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// THE JOIN THE DESIGN ROUND CALLED AN UNNAMED BLOCKER.
//
// A finding's basis names collector STEP names. A session-trace row names an apiGroup/resource tuple. Nothing in
// the tree connected them, and the design direction that made per-claim provenance its centrepiece never mentioned
// it — which matters because the join has no partial value: half-done means chips that resolve for workload rules
// and dangle for a third of the findings, a document advertising a join it cannot make.
//
// The spec's answer was a hand-written twenty-line table. That is not needed and would have been worse:
// CollectedResources() already holds the pairing and is already asserted against deploy/rbac.yaml AND against the
// collector's own step() calls. A second table would drift from the grants; a derivation cannot.
//
// This test is the completeness half. Every kind any rule or analyzer declares a dependency on must resolve, or the
// join dangles exactly where the design promises it will not.
func TestProvenanceJoin_EveryDeclaredKindResolvesToATuple(t *testing.T) {
	deps := FindingDependencies()
	if len(deps) == 0 {
		t.Fatal("no producers declare dependencies, so this guard would be vacuous")
	}

	unresolved := map[string][]string{}
	checked := 0
	for id, d := range deps {
		for _, kind := range d.Kinds {
			checked++
			tuple, ok := collect.StepToTuple(kind)
			if !ok || tuple == "" {
				unresolved[kind] = append(unresolved[kind], id)
				continue
			}
			// The tuple must be the shape a trace row carries: exactly one slash, or the non-resource marker.
			if tuple != "nonResourceURL" && strings.Count(tuple, "/") != 1 {
				t.Errorf("kind %q resolves to %q, which is not an apiGroup/resource tuple", kind, tuple)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d kind references were checked; the registries declare far more", checked)
	}
	for kind, ids := range unresolved {
		t.Errorf("kind %q does not resolve to a trace tuple, so provenance would dangle for %d producer(s) "+
			"including %s", kind, len(ids), ids[0])
	}
}

// And the reverse direction, which is the one that silently rots: a step the collector runs but that nothing can
// name. Reported rather than failed — some steps exist for the architecture rather than for a rule — but reported
// loudly enough to notice.
func TestProvenanceJoin_KnownShapesResolveCorrectly(t *testing.T) {
	cases := map[string]string{
		"pods":                            "core/pods",
		"deployments":                     "apps/deployments",
		"poddisruptionbudgets":            "policy/poddisruptionbudgets",
		"endpointslices":                  "discovery.k8s.io/endpointslices",
		"clusterrolebindings":             "rbac.authorization.k8s.io/clusterrolebindings",
		"horizontalpodautoscalers":        "autoscaling/horizontalpodautoscalers",
		"server-resources":                "nonResourceURL",
		"cr:certificates.cert-manager.io": "cert-manager.io/certificates",
		"cr:applications.argoproj.io":     "argoproj.io/applications",
	}
	for step, want := range cases {
		got, ok := collect.StepToTuple(step)
		if !ok {
			t.Errorf("%q did not resolve at all", step)
			continue
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", step, got, want)
		}
	}
	// A step that does not exist must say so rather than inventing a tuple.
	if tuple, ok := collect.StepToTuple("widgets"); ok {
		t.Errorf("an unknown step resolved to %q instead of reporting that it cannot be named", tuple)
	}
}
