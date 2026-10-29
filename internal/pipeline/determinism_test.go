package pipeline

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// determinism_test.go — the end-to-end guard the re-derivability claim rests on.
//
// WHY THIS FILE EXISTS. Determinism was asserted in six places before it, each narrow: one rule hashed twice,
// one topology built twice, one redaction run twice. No test evaluated the WHOLE producer set over one
// inventory and compared the result, so the collective reading of those six was broader than any of them —
// the same shape as two vacuity defects this build has already caught. Order was deterministic only
// transitively: rules.All() and analyzers.All() are fixed slices and ~37 independent per-producer sorts
// happened to line up. Nothing pinned any of it.
//
// THIS IS OPTION C OF THE SPEC, AND IT IS NOT THE CLAIM. It proves re-derivability WITHIN ONE PROCESS over an
// in-memory inventory, which is not what a customer with the file and the formula would do. It is here
// because it is cheap, because it catches every map-order regression, and because each fix in this epic
// needed a failing test first. No surface may state the re-derivation claim on the strength of this file.

// evaluateOnce runs every producer over one inventory exactly as Run does. It deliberately does not go
// through Run: Run re-enters Collect, which stamps a fresh Meta.StartedAt, so two Run calls differ by their
// reading clock and could not isolate the property under test.
//
// THE ANALYZER HALF IS analyzers.RunAll, NOT A COPY OF IT. This comment used to promise "the same two loops,
// the same GVR gate" and deliver that by duplicating both — a promise that held only until somebody edited
// the original. There were three copies of that loop (here, internal/pipeline.Run, and nowhere in the e2e
// test, which is the defect that produced the extraction: it walked rules.All() alone, so the analyzer path
// was never exercised against a real API server). One function now, and this file's claim is a fact.
func evaluateOnce(inv *collect.Inventory, ropts rules.Options) []types.Finding {
	var findings []types.Finding
	for _, r := range rules.All() {
		findings = append(findings, r.Evaluate(inv, ropts)...)
	}
	return append(findings, analyzers.RunAll(inv)...)
}

func idsOf(fs []types.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

// determinismInventory is one captured inventory with enough in it to exercise the map-keyed fields: several
// namespaces and workloads, and TWO custom-resource GVRs so StackObjects has more than one key. A single key
// cannot detect an unsorted range over the map, which is exactly defect 5.
func determinismInventory(t *testing.T) *collect.Inventory {
	inv := buildDeterminismInventory(t)
	if len(inv.StackObjects) < 2 {
		t.Fatalf("the fixture has %d StackObjects key(s); with fewer than two an unsorted range over the map "+
			"cannot be detected and this file proves nothing about defect 5", len(inv.StackObjects))
	}
	return inv
}

func buildDeterminismInventory(t *testing.T) *collect.Inventory {
	t.Helper()

	certGVR := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	// v1, NOT v1beta1: the analyzer's RequiredGVRs pin the version, PresentGVRs records the server-preferred
	// one, and hasAllAnalyzerGVRs matches exactly — so a fixture serving v1beta1 collects nothing here and the
	// non-vacuity guard below is what caught it.
	paGVR := schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}
	apGVR := schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}
	drGVR := schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"}
	crdGVR := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(certGVR.GroupVersion().WithKind("CertificateList"), &unstructured.UnstructuredList{})
	scheme.AddKnownTypeWithName(paGVR.GroupVersion().WithKind("PeerAuthenticationList"), &unstructured.UnstructuredList{})
	scheme.AddKnownTypeWithName(apGVR.GroupVersion().WithKind("AuthorizationPolicyList"), &unstructured.UnstructuredList{})
	scheme.AddKnownTypeWithName(drGVR.GroupVersion().WithKind("DestinationRuleList"), &unstructured.UnstructuredList{})

	cr := func(gvr schema.GroupVersionResource, kind, ns, name string, spec, status map[string]interface{}) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": gvr.GroupVersion().String(), "kind": kind,
			"metadata": map[string]interface{}{"namespace": ns, "name": name},
			"spec":     spec, "status": status,
		}}
		o.SetGroupVersionKind(gvr.GroupVersion().WithKind(kind))
		return o
	}
	// Several objects per GVR, so an unsorted range within one key is detectable too.
	objs := []runtime.Object{
		cr(certGVR, "Certificate", "prod", "api-tls", map[string]interface{}{"issuerRef": map[string]interface{}{"name": "le"}},
			map[string]interface{}{"notAfter": "2027-01-01T00:00:00Z"}),
		cr(certGVR, "Certificate", "prod", "web-tls", map[string]interface{}{"issuerRef": map[string]interface{}{"name": "le"}},
			map[string]interface{}{"notAfter": "2027-02-01T00:00:00Z"}),
		cr(paGVR, "PeerAuthentication", "prod", "default",
			map[string]interface{}{"mtls": map[string]interface{}{"mode": "PERMISSIVE"}}, map[string]interface{}{}),
		cr(paGVR, "PeerAuthentication", "shop", "default",
			map[string]interface{}{"mtls": map[string]interface{}{"mode": "PERMISSIVE"}}, map[string]interface{}{}),
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		certGVR: "CertificateList",
		paGVR:   "PeerAuthenticationList",
		apGVR:   "AuthorizationPolicyList",
		drGVR:   "DestinationRuleList",
		crdGVR:  "CustomResourceDefinitionList",
	}, objs...)

	cs := fakeClientsetWithWorkloads(t)
	for _, ns := range []string{"prod", "shop"} {
		_, _ = cs.CoreV1().Namespaces().Create(context.Background(),
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
	}
	disco := &fakePreferredDiscovery{
		FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}},
		preferred: []*metav1.APIResourceList{
			{GroupVersion: "cert-manager.io/v1", APIResources: []metav1.APIResource{
				{Name: "certificates", Namespaced: true, Kind: "Certificate"}}},
			{GroupVersion: "security.istio.io/v1", APIResources: []metav1.APIResource{
				{Name: "peerauthentications", Namespaced: true, Kind: "PeerAuthentication"},
				{Name: "authorizationpolicies", Namespaced: true, Kind: "AuthorizationPolicy"}}},
			{GroupVersion: "networking.istio.io/v1", APIResources: []metav1.APIResource{
				{Name: "destinationrules", Namespaced: true, Kind: "DestinationRule"}}},
		},
	}

	inv, err := collect.NewWithClients(cs, dyn, disco).Collect(context.Background(), analyzers.RequiredGVRsUnion())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return inv
}

// ONE INVENTORY, EVALUATED TWICE, IN THE SAME PROCESS. Same findings, same order.
func TestEvaluate_SameInventoryTwiceIsIdentical(t *testing.T) {
	inv := determinismInventory(t)
	ropts := rules.Options{}

	first := idsOf(evaluateOnce(inv, ropts))
	if len(first) < 5 {
		t.Fatalf("only %d finding(s) from the whole producer set; a harness that evaluates almost nothing "+
			"would pass every comparison below", len(first))
	}
	// Repeated, not doubled: a map's range order varies per iteration, so a single re-run can agree by luck.
	for i := 2; i <= 6; i++ {
		again := idsOf(evaluateOnce(inv, ropts))
		if len(again) != len(first) {
			t.Fatalf("evaluation %d produced %d findings against %d in the first", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("evaluation %d differs from the first at position %d: %s vs %s\n"+
					"the finding order over one inventory is not stable", i, j, again[j], first[j])
			}
		}
	}
	t.Logf("%d findings, identical in order over 6 evaluations of one inventory", len(first))

	// NON-VACUITY: a different cluster must produce a different set, or the comparison above is measuring a
	// constant. The control removes a workload rather than adding one, so it cannot pass by producing more.
	mutated := *inv
	if len(mutated.Deployments) == 0 {
		t.Fatal("the fixture carries no Deployment, so the control cannot change anything")
	}
	mutated.Deployments = mutated.Deployments[1:]
	if got := idsOf(evaluateOnce(&mutated, ropts)); strings.Join(got, ",") == strings.Join(first, ",") {
		t.Error("removing a Deployment changed no finding; this test would pass over an inventory it never read")
	}
}

// THE ID TESTS THAT USED TO LIVE HERE ARE GONE, AND THAT IS THE POINT.
//
// One carried an exception list of producers whose ids could not be recomputed from the finding; the other
// pinned the set of 21 rules that minted from a synthesized reference the finding never published, measured
// at 105 of the golden's 134 findings checkable and 29 not. Both were honest descriptions of a gap.
//
// `Finding.IDBasis` closed it: every mint site now publishes the three slots it hashed, so idbasis_test.go
// asserts the recipe over EVERY finding with no exception list at all — 134 of 134 on the golden. An
// exception list is an admission that a claim is smaller than it sounds, and deleting one is what the change
// that removed its reason to exist is for.
