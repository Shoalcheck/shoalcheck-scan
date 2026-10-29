package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// upgrade_preflight_test.go — §7 of the Upgrade Preflight spec, each test with what stops it being vacuous.
//
// THE FAMILY'S BOUNDARY IS THE THING UNDER TEST, not its arithmetic. Every one of these rules could be
// written to say something stronger and every stronger version would be false, so the assertions are mostly
// about what is NOT said.

var bannedUpgradePhrases = []string{
	"will break", "will fail", "breaks your", "outage", "downtime", "cannot upgrade",
	"the upgrade fails", "data loss", "guaranteed", "certainly",
}

func TestUpgrade_ClaimsWhatStopsBeingServedAndNothingMore(t *testing.T) {
	out := allUpgradeFindings(upgradeFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters,
		}, f.Evidence...), "\n"))
		for _, p := range bannedUpgradePhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — the cluster is visible and its clients are not:\n%s",
					f.ID, p, blob)
			}
		}
	}
}

func TestUpgrade_NeverCarriesDollars(t *testing.T) {
	for _, f := range allUpgradeFindings(upgradeFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

// §7.2 — AN UNPARSEABLE SERVER VERSION WITHHOLDS THE WHOLE RULE. Proven by planting a malformed version,
// and the assertion is the WITHHELD path rather than the empty one: rendering "no deprecated APIs served"
// off a version we could not read is the absence-as-fact defect.
func TestDeprecatedAPI_AnUnparseableServerVersionWithholdsTheRule(t *testing.T) {
	for _, v := range []string{"", "0.0.0-master+$Format:%H$", "not-a-version", "v"} {
		inv := upgradeFixture()
		inv.Meta.ServerVersion = v
		if got := (DeprecatedAPIServed{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
			t.Errorf("server version %q was compared against anyway: %s", v, got[0].Title)
		}
	}
}

// §7.1's shape — a denied discovery read is silence, not "nothing deprecated".
func TestDeprecatedAPI_ADeniedDiscoveryIsSilence(t *testing.T) {
	inv := upgradeFixture()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "server-resources")
	inv.Meta.Denied = append(inv.Meta.Denied, "server-resources: forbidden")
	assertSilent(t, (DeprecatedAPIServed{}).Evaluate(inv, Options{IncludeSystem: true}))
}

// A version already PAST is a statement about our table, not an upgrade warning. Conflating the two would
// report a healthy modern cluster as doomed by a removal that already happened.
func TestDeprecatedAPI_AVersionAlreadyPastIsNotAnUpgradeWarning(t *testing.T) {
	inv := upgradeFixture()
	inv.Meta.ServerVersion = "v1.31.2"
	// batch/v1beta1 was removed in 1.25; this cluster is 1.31 and still serves it.
	inv.ServedGroupVersions = []string{"v1", "apps/v1", "batch/v1beta1"}
	got := (DeprecatedAPIServed{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 0 {
		t.Fatalf("a removal that already happened was reported as an upgrade warning: %s", got[0].Title)
	}
}

// The disclosure half of the case above: when something else DOES fire, the already-past versions are
// named as excluded rather than silently dropped.
func TestDeprecatedAPI_AlreadyPastVersionsAreDisclosedWhenTheRuleFires(t *testing.T) {
	inv := upgradeFixture()
	inv.Meta.ServerVersion = "v1.28.5"
	inv.ServedGroupVersions = []string{
		"v1", "apps/v1",
		"batch/v1beta1",                        // removed 1.25 — already past
		"flowcontrol.apiserver.k8s.io/v1beta3", // removed 1.32 — ahead
	}
	got := (DeprecatedAPIServed{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if !strings.Contains(blob, "batch/v1beta1") {
		t.Errorf("an already-past served version was dropped silently:\n%s", blob)
	}
	if !strings.Contains(blob, "flowcontrol.apiserver.k8s.io/v1beta3") {
		t.Errorf("the future removal is not named:\n%s", blob)
	}
}

// §3 in test form, and it is the boundary the whole epic rests on.
func TestDeprecatedAPI_NamesNoWorkload(t *testing.T) {
	got := (DeprecatedAPIServed{}).Evaluate(upgradeFixture(), Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	for _, ref := range got[0].AffectedResources {
		switch ref.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Pod":
			t.Errorf("the finding names %s %s/%s — when a version is removed the OBJECTS survive and the "+
				"CLIENTS break, and the clients are not in a kubeconfig", ref.Kind, ref.Namespace, ref.Name)
		}
	}
}

// §7.4 — the conversion-webhook rule, both directions.
func TestConversionWebhook_FiresUnbackedAndStaysSilentWhenBacked(t *testing.T) {
	t.Run("no ready endpoints — fires", func(t *testing.T) {
		got := (CRDConversionWebhookUnbacked{}).Evaluate(upgradeFixture(), Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "widgets.acme.example") {
			t.Error("the CRD is not named")
		}
	})
	t.Run("a backed Service — silent", func(t *testing.T) {
		inv := upgradeFixture()
		inv.EndpointSlices = append(inv.EndpointSlices, discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: "acme-system", Name: "acme-webhook-abc",
				Labels: map[string]string{discoveryv1.LabelServiceName: "acme-webhook"}},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.0.0.9"}, Conditions: discoveryv1.EndpointConditions{Ready: ptrBoolUP(true)}}},
		})
		assertSilent(t, (CRDConversionWebhookUnbacked{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
	t.Run("strategy None — out of scope and silent", func(t *testing.T) {
		inv := upgradeFixture()
		for i := range inv.CRDs {
			inv.CRDs[i].ConversionStrategy = "None"
		}
		assertSilent(t, (CRDConversionWebhookUnbacked{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
}

// §7.5 — THE DENIAL GUARD, and the distinction it protects is `unknown` versus `unbacked`.
func TestConversionWebhook_AServiceThisReadingDidNotSeeIsUnknownNotUnbacked(t *testing.T) {
	inv := upgradeFixture()
	// The Service exists on the cluster; this reading's RBAC did not reach its namespace, so it is
	// absent from the list. Calling that "publishes no endpoints" would fabricate the finding.
	inv.Services = nil
	got := (CRDConversionWebhookUnbacked{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 0 {
		t.Errorf("a Service absent from the reading was reported as unbacked: %s",
			strings.Join(got[0].Evidence, " | "))
	}
	// And the whole rule falls silent when the CRD list itself was denied.
	inv2 := upgradeFixture()
	inv2.Meta.Collected = withoutKind(inv2.Meta.Collected, "customresourcedefinitions")
	inv2.Meta.Denied = append(inv2.Meta.Denied, "customresourcedefinitions: forbidden")
	assertSilent(t, (CRDConversionWebhookUnbacked{}).Evaluate(inv2, Options{IncludeSystem: true}))
}

// §7.6 — the node-pool rule cites the per-node findings by ID and does not restate their evidence.
//
// NOT VACUOUS: the fixture plants a pod whose nodeSelector names the node it is on, so losing that node
// leaves it a DECLARATION refusal on every survivor — which is the only shape NodeLossFeasibility reports at
// node granularity, capacity refusals being node_headroom's subject. The test asserts the per-node rule
// fires FIRST; if the shared model ever stopped producing it, this test would fail rather than skip, because
// a composition test that skips when its input dries up is a test that cannot fail.
func TestNodePoolCannotRoll_CitesPerNodeFindingsWithoutRestatingThem(t *testing.T) {
	inv := rollBlockedFixture()
	perNode := (NodeLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(perNode) == 0 {
		t.Fatal("the fixture produced no per-node finding, so this test would prove nothing about composition")
	}
	got := (NodePoolCannotRoll{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 composed finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	for _, f := range perNode {
		if !strings.Contains(blob, f.ID) {
			t.Errorf("the composed finding does not cite per-node finding %s", f.ID)
		}
	}
	// AND IT MUST NOT RESTATE. If the composed card repeated the per-node evidence, one problem would be
	// described twice — at cluster level and per-node level — which is the RolloutPassesThroughZero defect:
	// two cards for one configuration make the count wrong and verdict.Select cannot dedupe them.
	// The snapshot note is excluded because every finding in the product carries it; it is a preamble, not
	// evidence, and asserting on it would fail the test for a property it is not about.
	note := snapshotNote(inv)
	for _, f := range perNode {
		for _, e := range f.Evidence {
			if e == note || len(e) <= 40 {
				continue
			}
			if strings.Contains(blob, e) {
				t.Errorf("the composed finding repeats per-node evidence verbatim:\n  %s", e)
			}
		}
	}
}

// §7.6's other half — a cluster whose nodes can all be evacuated produces no composed finding, and the
// composed rule is silent for the same reason the per-node one is rather than by a rule of its own.
func TestNodePoolCannotRoll_SilentWhenEveryNodeCanBeEvacuated(t *testing.T) {
	inv := rollBlockedFixture()
	// Remove the pin: the pod now fits either survivor. And give it a controller: a pod nothing manages stops a
	// drain on its own (NodeDrainUnmanaged), so an evacuable cluster is one whose pods something recreates.
	for i := range inv.Pods {
		inv.Pods[i].Spec.NodeSelector = nil
		inv.Pods[i].OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "app-7f4b9c", Controller: ptrBoolUP(true)}}
	}
	if got := (NodeLossFeasibility{}).Evaluate(inv, Options{IncludeSystem: true}); len(got) != 0 {
		t.Fatalf("the unpinned fixture still produces a per-node finding: %s", got[0].Title)
	}
	assertSilent(t, (NodePoolCannotRoll{}).Evaluate(inv, Options{IncludeSystem: true}))
}

// A NODE ROLL MEETS EVERY NODE A DRAIN STOPS ON, NOT ONLY THE ONES WHOSE WORK HAS NOWHERE TO GO. The rule
// composed the node-loss model alone, so the sample opened on "5 nodes cannot be evacuated" — the drain's own
// stops — while its high, ticketable finding said a node roll meets 1 of 12; and on kind, `preflight upgrade`
// answered ✓ while `preflight drain` stopped on two of three nodes (D50 product review). An upgrade drains every
// node, so whatever stops a drain stops the roll at that node: a pod nothing recreates, a budget at zero, a
// volume pinned to it, work with nowhere to go.
func TestNodePoolCannotRoll_MeetsEveryNodeADrainStopsOn(t *testing.T) {
	inv := rollBlockedFixture()
	// node-a: the pinned pod — its work has nowhere to go (node-loss), and nothing recreates it (unmanaged).
	// node-b: a debugging pod someone ran by hand — it fits anywhere, but kubectl drain refuses it without --force.
	inv.Pods = append(inv.Pods, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "debug-shell"},
		Spec: corev1.PodSpec{NodeName: "node-b", Containers: []corev1.Container{{Name: "sh", Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})
	o := Options{IncludeSystem: true}
	stopped := map[string]bool{}
	for _, r := range DrainStops() {
		for _, f := range r.Evaluate(inv, o) {
			for _, ref := range f.AffectedResources {
				if ref.Kind == "Node" {
					stopped[ref.Name] = true
				}
			}
			if r.ID() == (NodeLossFeasibility{}).ID() {
				stopped["node-a"] = true // the node-loss finding names its node only through its id
			}
		}
	}
	if !stopped["node-b"] {
		t.Fatal("the fixture's hand-run pod stops no drain, so this test would prove nothing")
	}
	got := (NodePoolCannotRoll{}).Evaluate(inv, o)
	if len(got) != 1 {
		t.Fatalf("want one roll finding, got %d", len(got))
	}
	var nodes []string
	for _, ref := range got[0].AffectedResources {
		nodes = append(nodes, ref.Name)
	}
	if strings.Join(nodes, ",") != "node-a,node-b" || !strings.Contains(got[0].Title, "2 of 3") {
		t.Errorf("the roll meets %v (%q); a drain stops on node-a and node-b", nodes, got[0].Title)
	}
}

// rollBlockedFixture: three nodes, one pod pinned by nodeSelector to the node it runs on.
func rollBlockedFixture() *collect.Inventory {
	node := func(name string) corev1.Node {
		return corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				"kubernetes.io/hostname":      name,
				"topology.kubernetes.io/zone": "eu-central-1a",
			}},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			},
		}
	}
	return &collect.Inventory{
		Meta: collect.Meta{
			Collected: []string{"nodes", "pods", "persistentvolumeclaims", "persistentvolumes",
				"server-resources", "customresourcedefinitions", "services", "endpointslices"},
			ServerVersion: "v1.28.5",
			StartedAt:     fixedReading,
		},
		Nodes: []corev1.Node{node("node-a"), node("node-b"), node("node-c")},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "pinned-0"},
			Spec: corev1.PodSpec{
				NodeName:     "node-a",
				NodeSelector: map[string]string{"kubernetes.io/hostname": "node-a"},
				Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")}}}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}},
	}
}

func ptrBoolUP(b bool) *bool { return &b }

// upgradeFixture: a 1.28 cluster serving one doomed version, with one CRD whose conversion webhook has
// nothing behind it.
func upgradeFixture() *collect.Inventory {
	return &collect.Inventory{
		Meta: collect.Meta{
			Collected: []string{"server-resources", "customresourcedefinitions", "services",
				"endpointslices", "nodes", "pods", "persistentvolumes", "persistentvolumeclaims"},
			ServerVersion: "v1.28.5",
			StartedAt:     fixedReading,
		},
		ServedGroupVersions: []string{"v1", "apps/v1", "flowcontrol.apiserver.k8s.io/v1beta3"},
		CRDs: []collect.CRDInfo{{
			Name: "widgets.acme.example", Group: "acme.example",
			ConversionStrategy:      "Webhook",
			WebhookServiceNamespace: "acme-system",
			WebhookServiceName:      "acme-webhook",
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "acme-system", Name: "acme-webhook"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "acme-webhook"}},
		}},
	}
}

func allUpgradeFindings(inv *collect.Inventory) []types.Finding {
	o := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (DeprecatedAPIServed{}).Evaluate(inv, o)...)
	out = append(out, (CRDConversionWebhookUnbacked{}).Evaluate(inv, o)...)
	return out
}

// B-155 END TO END — the rule, not just the table.
//
// The fix is only worth anything if the RULE calls Applicable rather than For; a corrected table read
// through the old lookup changes nothing that reaches a report. This plants the exact cluster the §8 sweep
// found: a v1.28 server serving admissionregistration.k8s.io/v1beta1, which there carries
// ValidatingAdmissionPolicy and is entirely current.
func TestDeprecatedAPI_AReintroducedVersionIsNeitherWarnedNorDisclosedAsPast(t *testing.T) {
	inv := upgradeFixture()
	inv.Meta.ServerVersion = "v1.28.15"
	inv.ServedGroupVersions = []string{
		"v1", "apps/v1",
		"admissionregistration.k8s.io/v1",
		"admissionregistration.k8s.io/v1beta1", // ValidatingAdmissionPolicy at 1.28, not the webhook types
		"flowcontrol.apiserver.k8s.io/v1beta3", // genuinely removed in 1.32
	}
	got := (DeprecatedAPIServed{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	blob := strings.Join(got[0].Evidence, "\n")
	if strings.Contains(blob, "admissionregistration.k8s.io/v1beta1") {
		t.Errorf("a group/version reintroduced at this server's own version was still named — either as a "+
			"warning or in the already-past disclosure, and both tell the operator this reading's "+
			"schedule may be wrong about a version that is entirely current:\n%s", blob)
	}
	if !strings.Contains(blob, "flowcontrol.apiserver.k8s.io/v1beta3") {
		t.Error("the genuine future removal stopped being reported, so the narrowing is too wide")
	}
	// And below the reintroduction it IS the webhook types, and IS a warning.
	old := upgradeFixture()
	old.Meta.ServerVersion = "v1.21.14"
	old.ServedGroupVersions = []string{"v1", "admissionregistration.k8s.io/v1beta1"}
	got2 := (DeprecatedAPIServed{}).Evaluate(old, Options{IncludeSystem: true})
	if len(got2) != 1 || !strings.Contains(strings.Join(got2[0].Evidence, "\n"),
		"admissionregistration.k8s.io/v1beta1") {
		t.Error("a v1.21 server serving admissionregistration.k8s.io/v1beta1 was not warned; there it " +
			"really is MutatingWebhookConfiguration and the removal really is coming")
	}
}
