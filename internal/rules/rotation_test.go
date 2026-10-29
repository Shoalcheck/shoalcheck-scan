package rules

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// ---------------------------------------------------------------------------------------------
// GROUND TRUTH 1a — the guard for what these rules may not say.
//
// The whole epic rests on one distinction: an EndpointSlice entry means "a controller published
// this pod as a backend", never "a request reached it". Every phrase below converts a published
// count into an outcome the snapshot cannot support, so a finding containing one has stopped being
// a reading and become a guess.
//
// The list bans BARE "traffic": unlike the drain rules — where rule C legitimately says a node is
// unreachable and the mandatory caveat itself contains the word — nothing these three rules say
// needs it. Same for "serving" and "receiving": the honest verb is "published"/"registered".
//
// Durations are banned as words ("seconds", "minutes") and the two windows these rules DO have to
// print are written in the compact form ("60s", "5m0s"), because a window on the reading is not a
// claim about how long anything takes.
// ---------------------------------------------------------------------------------------------

var rotationBannedPhrases = []string{
	// Outcome vocabulary. A published entry is not a request; an absent entry is not an outage.
	"traffic", "rotation", "serving", "receiving", "receives", "serves",
	"in the serving path", "reachable from", "blackhole", "resolves to nothing",
	// User/impact claims. There is no request, revenue or SLA data in the snapshot.
	"users", "user-facing", "user-visible", "customer", "outage", "downtime",
	"is down", "goes down", "impact",
	// Verdicts. State the observation, never the judgment.
	"broken", "failing", "misconfigured", "single point of failure", "spof",
	// Durations and promises.
	// "guaranteed" is global — see TestEveryRuleOutput_ClearsTheGlobalCopyPolicy.
	"seconds", "minutes", "will take", "no impact", "will fail",
}

func rotationRuleSet() []Rule {
	return []Rule{ServiceNoReadyEndpoints{}, ServiceEndpointsOneNode{}, PodSelectedButUnpublished{}}
}

func TestRotationRules_EmitNoUnsupportableClaim(t *testing.T) {
	inv := rotationInventory()
	for _, r := range rotationRuleSet() {
		findings := r.Evaluate(inv, Options{})
		if len(findings) == 0 {
			t.Fatalf("%s produced no findings on the rotation fixture — the guard would be vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " "))
			for _, banned := range rotationBannedPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s emits the banned phrase %q — the snapshot cannot support it.\n  finding: %s",
						r.ID(), banned, f.Title)
				}
			}
		}
	}
}

// There is no request, revenue or SLA data in the snapshot, so a dollar on a rotation finding
// would be invented outright.
func TestRotationRules_NeverCarryDollars(t *testing.T) {
	inv := rotationInventory()
	for _, r := range rotationRuleSet() {
		for _, f := range r.Evaluate(inv, Options{}) {
			if f.DollarImpactMonthly != 0 {
				t.Errorf("%s put $%.2f on %q", r.ID(), f.DollarImpactMonthly, f.Title)
			}
		}
	}
}

// A Service shape we cannot judge must be excluded AND SAID SO. A silent skip makes the report's
// coverage look total, which is the same defect as a chart that dropped 18 of 24 findings and
// counted none of them.
func TestRotationRules_DiscloseEveryShapeTheyCannotJudge(t *testing.T) {
	inv := rotationInventory()
	findings := (ServiceNoReadyEndpoints{}).Evaluate(inv, Options{})
	if len(findings) == 0 {
		t.Fatal("no findings, so nothing carries a coverage line")
	}

	// None of the unjudgeable shapes may appear as a finding, in either direction.
	forbidden := []string{"ext", "selectorless", "headless", "foreign", "newborn"}
	for _, f := range findings {
		for _, ref := range f.AffectedResources {
			for _, bad := range forbidden {
				if ref.Name == bad {
					t.Errorf("%s judged Service shop/%s, which it cannot judge", f.RuleID, bad)
				}
			}
		}
	}

	// Every finding carries the coverage line, and it names each exclusion class it applied.
	for _, f := range findings {
		cov := ""
		for _, e := range f.Evidence {
			if strings.HasPrefix(e, "coverage:") {
				cov = e
			}
		}
		if cov == "" {
			t.Fatalf("finding %q carries no coverage line", f.Title)
		}
		for _, want := range []string{"ExternalName", "selectorless", "headless", "another controller", "5m0s"} {
			if !strings.Contains(cov, want) {
				t.Errorf("coverage line does not disclose %q:\n  %s", want, cov)
			}
		}
	}
}

// An absent EndpointSlice list is not an absence of endpoints. With the kind denied, all three
// rules must be silent — otherwise the rule reports the operator's RBAC as a cluster fact.
func TestRotationRules_DenialGuard(t *testing.T) {
	for _, denied := range []string{"endpointslices", "services"} {
		inv := rotationInventory()
		inv.Meta.Collected = withoutKind(inv.Meta.Collected, denied)
		inv.Meta.Denied = append(inv.Meta.Denied, denied+": forbidden")
		for _, r := range rotationRuleSet() {
			if fs := r.Evaluate(inv, Options{}); len(fs) != 0 {
				t.Errorf("%s emitted %d findings with %q denied", r.ID(), len(fs), denied)
			}
		}
	}
	// Rule 3 additionally rests on the pod list; rules 1 and 2 do not and must keep firing.
	inv := rotationInventory()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "pods")
	inv.Meta.Denied = append(inv.Meta.Denied, "pods: forbidden")
	if fs := (PodSelectedButUnpublished{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("pod-selected-but-unpublished emitted %d findings with pods denied", len(fs))
	}
	if fs := (ServiceNoReadyEndpoints{}).Evaluate(inv, Options{}); len(fs) == 0 {
		t.Error("service-no-ready-endpoints fell silent when only the pod list was denied — it never reads a Pod")
	}
}

// A dual-stack Service publishes an IPv4 and an IPv6 slice for the SAME pods. Counting both
// doubles every figure, which node_drain.go already learned; this epic must not re-derive it wrong.
func TestRotationRules_DualStackCountsEachBackendOnce(t *testing.T) {
	inv := rotationInventory()
	var dual []string
	for _, f := range (ServiceEndpointsOneNode{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Name == "dual" {
			dual = f.Evidence
		}
	}
	if dual == nil {
		t.Fatal("the dual-stack Service produced no one-node finding, so the dedup is untested")
	}
	blob := strings.Join(dual, " ")
	if !strings.Contains(blob, "2 ready") {
		t.Errorf("dual-stack Service should report 2 ready addresses, not 4:\n  %s", blob)
	}
	if strings.Contains(blob, "4 ready") {
		t.Errorf("dual-stack Service double-counted its backends:\n  %s", blob)
	}
	if !strings.Contains(blob, "IPv4") {
		t.Errorf("the counted address family must be named:\n  %s", blob)
	}
}

// nodeName on an EndpointSlice entry is the controller's batched copy of the pod's node. It has no
// referential integrity and is absent on manually written slices — so when it is missing the
// placement claim cannot be made at all, rather than made about the entries that happen to have it.
func TestServiceEndpointsOneNode_SilentWhenNodeNameIsAbsent(t *testing.T) {
	inv := rotationInventory()
	for i := range inv.EndpointSlices {
		s := &inv.EndpointSlices[i]
		if s.Labels[discoveryv1.LabelServiceName] != "onenode" {
			continue
		}
		s.Endpoints[0].NodeName = nil
	}
	for _, f := range (ServiceEndpointsOneNode{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Name == "onenode" {
			t.Errorf("placement claimed for a Service with an entry carrying no nodeName: %v", f.Evidence)
		}
	}
}

// The most likely false positive in the epic: any rollout produces pods that match a selector
// before the EndpointSlice controller catches up. A pod that became Ready moments before the
// reading is therefore not evidence of anything.
func TestPodSelectedButUnpublished_IgnoresPodsReadyTooRecently(t *testing.T) {
	inv := rotationInventory()
	if len((PodSelectedButUnpublished{}).Evaluate(inv, Options{})) == 0 {
		t.Fatal("fixture produces no finding, so the gate below is untested")
	}
	for i := range inv.Pods {
		if inv.Pods[i].Name == "unpub-missing" {
			setPodReadyAt(&inv.Pods[i], rotNow.Add(-10*time.Second))
		}
	}
	for _, f := range (PodSelectedButUnpublished{}).Evaluate(inv, Options{}) {
		if strings.Contains(strings.Join(f.Evidence, " "), "unpub-missing") {
			t.Errorf("a pod Ready for 10s was reported as unpublished: %v", f.Evidence)
		}
	}
}

// A pod with a deletionTimestamp is being removed from the slices on purpose. Reporting it as
// unpublished would flag the controller doing its job.
func TestPodSelectedButUnpublished_IgnoresTerminatingPods(t *testing.T) {
	inv := rotationInventory()
	for i := range inv.Pods {
		if inv.Pods[i].Name == "unpub-missing" {
			now := metav1.NewTime(rotNow.Add(-time.Minute))
			inv.Pods[i].DeletionTimestamp = &now
		}
	}
	for _, f := range (PodSelectedButUnpublished{}).Evaluate(inv, Options{}) {
		if strings.Contains(strings.Join(f.Evidence, " "), "unpub-missing") {
			t.Errorf("a terminating pod was reported as unpublished: %v", f.Evidence)
		}
	}
}

// The finding must print the window it applied, or the claim is unbounded.
func TestPodSelectedButUnpublished_NamesItsWindow(t *testing.T) {
	fs := (PodSelectedButUnpublished{}).Evaluate(rotationInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range fs {
		if !strings.Contains(strings.Join(f.Evidence, " ")+f.Description, "60s") {
			t.Errorf("finding %q never names the readiness window it required", f.Title)
		}
	}
}

// A healthy Service — ready addresses on two nodes, every matching pod published — must produce
// nothing from any of the three rules. Without this the fixture cannot tell a rule that judges
// from a rule that flags everything.
func TestRotationRules_LeaveAHealthyServiceAlone(t *testing.T) {
	inv := rotationInventory()
	for _, r := range rotationRuleSet() {
		for _, f := range r.Evaluate(inv, Options{}) {
			for _, ref := range f.AffectedResources {
				if ref.Name == "healthy" {
					t.Errorf("%s flagged the healthy Service: %v", r.ID(), f.Evidence)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------------------------

// rotNow is the reading time. Fixed so every window in these tests is arithmetic, not a race.
var rotNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func withoutKind(kinds []string, drop string) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if k != drop {
			out = append(out, k)
		}
	}
	return out
}

func boolp(b bool) *bool { return &b }

func strp(s string) *string { return &s }

func rotSvc(ns, name string, selector map[string]string, mutate func(*corev1.Service)) corev1.Service {
	s := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			CreationTimestamp: metav1.NewTime(rotNow.Add(-24 * time.Hour)),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.0.0.1",
			Selector:  selector,
		},
	}
	if mutate != nil {
		mutate(&s)
	}
	return s
}

type rotEntry struct {
	uid   string
	ready *bool
	node  string
	addr  string
}

func rotSlice(ns, svc, family string, entries []rotEntry, mutate func(*discoveryv1.EndpointSlice)) discoveryv1.EndpointSlice {
	s := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: svc + "-" + strings.ToLower(family), Namespace: ns,
			Labels: map[string]string{
				discoveryv1.LabelServiceName:             svc,
				"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
			},
		},
		AddressType: discoveryv1.AddressType(family),
	}
	for _, e := range entries {
		ep := discoveryv1.Endpoint{
			Addresses:  []string{e.addr},
			Conditions: discoveryv1.EndpointConditions{Ready: e.ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: ns, UID: apitypes.UID(e.uid)},
		}
		if e.node != "" {
			ep.NodeName = strp(e.node)
		}
		s.Endpoints = append(s.Endpoints, ep)
	}
	if mutate != nil {
		mutate(&s)
	}
	return s
}

func rotPod(ns, name, uid string, lbls map[string]string, readyAt time.Time) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbls, UID: apitypes.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	setPodReadyAt(&p, readyAt)
	return p
}

func setPodReadyAt(p *corev1.Pod, at time.Time) {
	p.Status.Conditions = []corev1.PodCondition{{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(at),
	}}
}

// rotationInventory is one cluster holding one instance of every case the three rules must handle:
// the three findings, the five shapes that must be excluded and disclosed, a dual-stack Service
// whose backends must be counted once, and one Service that is fine.
func rotationInventory() *collect.Inventory {
	long := rotNow.Add(-2 * time.Hour) // Ready well before the reading

	return &collect.Inventory{
		Services: []corev1.Service{
			// rule 1: two published addresses, neither ready.
			rotSvc("shop", "zero", map[string]string{"app": "zero"}, nil),
			// rule 2: three ready addresses, all on node-a.
			rotSvc("shop", "onenode", map[string]string{"app": "onenode"}, nil),
			// rule 3: one published pod, one Ready-and-matching pod in no slice.
			rotSvc("shop", "unpub", map[string]string{"app": "unpub"}, nil),
			// dual-stack: same two backends in two families.
			rotSvc("shop", "dual", map[string]string{"app": "dual"}, nil),
			// fine: two ready addresses on two nodes, every matching pod published.
			rotSvc("shop", "healthy", map[string]string{"app": "healthy"}, nil),

			// --- shapes that must be excluded and disclosed ---
			rotSvc("shop", "ext", nil, func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeExternalName
				s.Spec.ExternalName = "db.example.com"
				s.Spec.ClusterIP = ""
			}),
			rotSvc("shop", "selectorless", nil, nil),
			rotSvc("shop", "headless", map[string]string{"app": "hl"}, func(s *corev1.Service) {
				s.Spec.ClusterIP = corev1.ClusterIPNone
			}),
			rotSvc("shop", "foreign", map[string]string{"app": "foreign"}, nil),
			rotSvc("shop", "newborn", map[string]string{"app": "newborn"}, func(s *corev1.Service) {
				s.CreationTimestamp = metav1.NewTime(rotNow.Add(-30 * time.Second))
			}),
		},
		EndpointSlices: []discoveryv1.EndpointSlice{
			rotSlice("shop", "zero", "IPv4", []rotEntry{
				{uid: "u-zero-1", ready: boolp(false), node: "node-a", addr: "10.1.0.1"},
				{uid: "u-zero-2", ready: nil, node: "node-b", addr: "10.1.0.2"},
			}, nil),
			rotSlice("shop", "onenode", "IPv4", []rotEntry{
				{uid: "u-on-1", ready: boolp(true), node: "node-a", addr: "10.1.1.1"},
				{uid: "u-on-2", ready: boolp(true), node: "node-a", addr: "10.1.1.2"},
				{uid: "u-on-3", ready: boolp(true), node: "node-a", addr: "10.1.1.3"},
			}, nil),
			rotSlice("shop", "unpub", "IPv4", []rotEntry{
				{uid: "u-unpub-pub", ready: boolp(true), node: "node-a", addr: "10.1.2.1"},
			}, nil),
			// The same two UIDs in both families — 2 backends, not 4.
			rotSlice("shop", "dual", "IPv4", []rotEntry{
				{uid: "u-dual-1", ready: boolp(true), node: "node-a", addr: "10.1.3.1"},
				{uid: "u-dual-2", ready: boolp(true), node: "node-a", addr: "10.1.3.2"},
			}, nil),
			rotSlice("shop", "dual", "IPv6", []rotEntry{
				{uid: "u-dual-1", ready: boolp(true), node: "node-a", addr: "fd00::1"},
				{uid: "u-dual-2", ready: boolp(true), node: "node-a", addr: "fd00::2"},
			}, nil),
			rotSlice("shop", "healthy", "IPv4", []rotEntry{
				{uid: "u-ok-1", ready: boolp(true), node: "node-a", addr: "10.1.4.1"},
				{uid: "u-ok-2", ready: boolp(true), node: "node-b", addr: "10.1.4.2"},
			}, nil),
			// headless with zero ready: excluded from rule 1, eligible for rule 3.
			rotSlice("shop", "headless", "IPv4", []rotEntry{
				{uid: "u-hl-1", ready: boolp(false), node: "node-a", addr: "10.1.5.1"},
			}, nil),
			// published by something that is not the upstream controller.
			rotSlice("shop", "foreign", "IPv4", []rotEntry{
				{uid: "u-f-1", ready: boolp(false), node: "node-a", addr: "10.1.6.1"},
			}, func(s *discoveryv1.EndpointSlice) {
				s.Labels["endpointslice.kubernetes.io/managed-by"] = "some-mesh-controller.example.com"
			}),
		},
		Pods: []corev1.Pod{
			rotPod("shop", "unpub-published", "u-unpub-pub", map[string]string{"app": "unpub"}, long),
			rotPod("shop", "unpub-missing", "u-unpub-missing", map[string]string{"app": "unpub"}, long),
			rotPod("shop", "ok-1", "u-ok-1", map[string]string{"app": "healthy"}, long),
			rotPod("shop", "ok-2", "u-ok-2", map[string]string{"app": "healthy"}, long),
		},
		Meta: collect.Meta{
			Collected: []string{"services", "endpointslices", "pods", "nodes"},
			StartedAt: rotNow,
		},
	}
}
