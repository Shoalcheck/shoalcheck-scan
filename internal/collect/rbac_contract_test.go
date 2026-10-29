package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"
)

// clusterRole is the minimal shape we parse out of deploy/rbac.yaml.
type clusterRole struct {
	Kind  string `json:"kind"`
	Rules []struct {
		APIGroups []string `json:"apiGroups"`
		Resources []string `json:"resources"`
		Verbs     []string `json:"verbs"`
	} `json:"rules"`
}

func loadAuditorRole(t *testing.T) clusterRole {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rbac.yaml"))
	if err != nil {
		t.Fatalf("read deploy/rbac.yaml: %v", err)
	}
	// The file has two YAML docs (ClusterRole + commented binding); the binding
	// is fully commented, so only the ClusterRole doc is live.
	for _, doc := range strings.Split(string(data), "\n---\n") {
		var cr clusterRole
		if err := yaml.Unmarshal([]byte(doc), &cr); err != nil {
			continue
		}
		if cr.Kind == "ClusterRole" {
			return cr
		}
	}
	t.Fatal("no ClusterRole document found in deploy/rbac.yaml")
	return clusterRole{}
}

// roleGrants flattens the ClusterRole into a set of "group/resource" + verb set.
func roleGrants(cr clusterRole) (grants map[string]map[string]bool) {
	grants = map[string]map[string]bool{}
	for _, r := range cr.Rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				key := g + "/" + res
				if grants[key] == nil {
					grants[key] = map[string]bool{}
				}
				for _, v := range r.Verbs {
					grants[key][v] = true
				}
			}
		}
	}
	return grants
}

// TestRBACContractMatchesCollector is the drift gate: the published ClusterRole
// must grant exactly what CollectedResources() declares — no more, no less.
func TestRBACContractMatchesCollector(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(CollectedResources()); n < 40 {
		t.Fatalf("the registry holds %d collected resource(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	grants := roleGrants(loadAuditorRole(t))

	want := map[string]bool{}
	for _, ra := range CollectedResources() {
		key := ra.APIGroup + "/" + ra.Resource
		want[key] = true
		rg, ok := grants[key]
		if !ok {
			t.Errorf("collector reads %q but the ClusterRole does not grant it", key)
			continue
		}
		for _, v := range ra.Verbs {
			if !rg[v] {
				t.Errorf("collector needs verb %q on %q; ClusterRole missing it", v, key)
			}
		}
		// The role must not grant verbs the collector doesn't use.
		for v := range rg {
			if v != "get" && v != "list" {
				t.Errorf("ClusterRole grants disallowed verb %q on %q (read-only contract)", v, key)
			}
		}
	}
	// The role must not grant access to anything the collector doesn't read.
	for key := range grants {
		if !want[key] {
			t.Errorf("ClusterRole grants %q which the collector never reads — over-broad", key)
		}
	}
}

// TestRBACContractForbidsSensitive locks the security contract: secrets and
// configmaps must never appear in the role, and only get/list verbs are allowed.
func TestRBACContractForbidsSensitive(t *testing.T) {
	cr := loadAuditorRole(t)
	for _, r := range cr.Rules {
		for _, res := range r.Resources {
			if res == "secrets" || res == "configmaps" {
				t.Errorf("ClusterRole must NEVER grant %q", res)
			}
			if strings.Contains(res, "/") { // subresources like pods/exec, pods/log
				t.Errorf("ClusterRole must not grant subresource %q", res)
			}
		}
		for _, v := range r.Verbs {
			if v != "get" && v != "list" {
				t.Errorf("ClusterRole verb %q violates read-only contract (only get/list)", v)
			}
		}
	}
}

// TestCollectedResourcesMatchActualCollection asserts the declared resource
// list equals what Collect() actually lists against a fake cluster — so the
// permission preview can't lie about what the collector does.
func TestCollectedResourcesMatchActualCollection(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
	// A DYNAMIC CLIENT IS PART OF THE ALWAYS-ON SET NOW. customresourcedefinitions is read through it
	// rather than through a typed clientset — see collect/crd.go for why — so a harness without one makes
	// that step land in Denied and this contract test fail for a reason that has nothing to do with the
	// contract. The fake serves no CRDs, which is the correct empty result rather than a missing read.
	crdGVR := schema.GroupVersionResource{
		Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{crdGVR: "CustomResourceDefinitionList"})
	inv, err := NewWithClients(cs, dyn, nil).Collect(t.Context(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	declared := map[string]bool{}
	for _, ra := range CollectedResources() {
		if ra.Opportunistic {
			continue // CRD reads run only when present; the fake serves none
		}
		declared[ra.Resource] = true
	}
	collected := map[string]bool{}
	for _, k := range inv.Meta.Collected {
		if strings.HasPrefix(k, "cr:") {
			continue // opportunistic CR reads are not part of the always-on set
		}
		collected[k] = true
	}
	if len(declared) != len(collected) {
		da, ca := keys(declared), keys(collected)
		t.Errorf("declared %d always-on resources %v but Collect listed %d %v", len(da), da, len(ca), ca)
	}
	for r := range declared {
		if !collected[r] {
			t.Errorf("declared always-on resource %q was not actually collected", r)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestRBACDocsTelemetryOutOfBand_NoNewVerbs is the Phase 2 contract: the manifest
// documents that mesh/CNI TELEMETRY is read OUT-OF-BAND via the Prometheus HTTP
// query API (not the K8s API), so the observed service map adds no K8s access —
// and the default auditor role grants neither services/proxy nor pods/portforward
// (those are the app-connect OPT-IN, never in the default read-only role).
// Reading mesh/operator CRDs (e.g. peerauthentications) IS legitimately granted
// for the Phase-3 stack analyzers — a separate, intentional concern this test
// does NOT forbid. We check the granted rules, not raw substrings, because the
// header legitimately NAMES forbidden resources in its "does NOT include" list.
func TestRBACDocsTelemetryOutOfBand_NoNewVerbs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rbac.yaml"))
	if err != nil {
		t.Fatalf("read rbac.yaml: %v", err)
	}
	if !strings.Contains(string(data), "Prometheus HTTP query") {
		t.Errorf("rbac.yaml must document out-of-band telemetry reads")
	}
	grants := roleGrants(loadAuditorRole(t))
	for key := range grants {
		for _, forbidden := range []string{"services/proxy", "pods/portforward"} {
			if strings.Contains(key, forbidden) {
				t.Errorf("default auditor role must not grant %q (app-connect is opt-in; telemetry is out-of-band)", key)
			}
		}
	}
}

// deploy/rbac.yaml is the file a security reviewer opens FIRST, and its header states how many kinds the
// collector reads. That number drifted: it said 18 while CollectedResources() listed 19, and the missing one was
// endpointslices — a kind the same file grants three sections lower. Prose that contradicts the grants beneath it
// is worse than no prose, because a reviewer who notices stops trusting the rest of the document.
//
// TestRBACContractMatchesCollector already pins the GRANTS against the code. This pins the SENTENCE, because a
// comment nothing checks is a comment that rots.
func TestRBACYAMLHeaderCountsTheKindsCorrectly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "rbac.yaml"))
	if err != nil {
		t.Fatalf("read deploy/rbac.yaml: %v", err)
	}
	header := string(raw)

	always := 0
	for _, r := range CollectedResources() {
		if !r.Opportunistic {
			always++
		}
	}
	if always == 0 {
		t.Fatal("CollectedResources reports no always-collected kinds, so this test would check nothing")
	}

	want := fmt.Sprintf("the %d core kinds it reads", always)
	if !strings.Contains(header, want) {
		claimed := "no such sentence"
		if m := regexp.MustCompile(`the (\d+) core kinds it reads`).FindStringSubmatch(header); len(m) == 2 {
			claimed = m[1]
		}
		t.Errorf("deploy/rbac.yaml claims %s core kinds; the collector always reads %d.\n"+
			"  The published ClusterRole's own prose must not understate what it grants.", claimed, always)
	}
}

// THE PUBLIC PAGE ABOUT WHAT THIS TOOL DOES TO A CLUSTER IS HELD TO THE COLLECTOR, NOT TO A COPYWRITER.
//
// site/read-only.html states the permission surface in prose: how many resources are asked for, that the
// verbs are get and list, that there is no watch, and that Secrets and ConfigMaps are never requested. That
// page is the strongest asset this product has and the buyer's first question about anything that touches a
// production cluster — and it is exactly the kind of copy that goes stale the first time a rule needs a new
// kind. `deploy/rbac.yaml` is already pinned to the collector by TestRBACContractMatchesCollector; this
// pins the sentence a stranger reads to the same source.
//
// The count is group/resource PAIRS, not names: `networkpolicies` is asked of both networking.k8s.io and
// projectcalico.org, so 47 pairs carry 46 distinct words. The page says both numbers, because a reader who
// counts the list and gets a different answer from the heading has been given a reason to check nothing
// else on it.
func TestReadOnlyPage_SaysWhatTheCollectorAsksFor(t *testing.T) {
	b, err := os.ReadFile("../../site/read-only.html")
	if err != nil {
		t.Skipf("site/read-only.html is absent (%v); nothing to hold to the collector", err)
	}
	page := string(b)

	res := CollectedResources()
	names := map[string]bool{}
	for _, r := range res {
		names[r.Resource] = true
	}
	pairs, distinct := len(res), len(names)
	if pairs < 20 {
		t.Fatalf("CollectedResources returned %d entries, too few for this comparison to mean anything", pairs)
	}

	for _, want := range []string{
		fmt.Sprintf("%d group/resource pairs", pairs),
		fmt.Sprintf("%d distinct names", distinct),
		fmt.Sprintf("It asks %d questions", pairs),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("site/read-only.html does not say %q: the page states a permission surface that is no "+
				"longer the one the collector asks for", want)
		}
	}

	// Every resource the collector reads is named on the page. A kind added for a new rule and left off
	// this page makes the page an understatement, which is the direction that costs trust when somebody
	// diffs it against their own audit log.
	for _, r := range res {
		if !strings.Contains(page, ">"+r.Resource) && !strings.Contains(page, ">"+r.Resource+" ") {
			t.Errorf("the collector reads %q and site/read-only.html does not list it", r.Resource)
		}
	}

	// And the verbs. If a step ever needs more than get+list, the page has to stop saying otherwise before
	// the code ships.
	for _, r := range res {
		for _, v := range r.Verbs {
			if v != "get" && v != "list" {
				t.Errorf("%s carries verb %q, and site/read-only.html tells the reader the verbs are get "+
					"and list with no watch", r.Resource, v)
			}
		}
	}
	// The two the page promises are never requested.
	for _, forbidden := range []string{"secrets", "configmaps"} {
		if names[forbidden] {
			t.Errorf("the collector reads %q, which site/read-only.html states is never requested — and "+
				"deploy/rbac.yaml's own security contract says the same", forbidden)
		}
	}
}
