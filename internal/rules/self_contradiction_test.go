package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ---------------------------------------------------------------------------------------------
// SELF-CONTRADICTION — the guard for what this family may not say.
//
// The family's claim is arithmetic over the operator's own declarations, which is why its
// Confidence is 1.0 by construction and why the WORDING is the whole risk: an exact reading
// invites an outcome sentence the reading does not support.
//
// Three bans carry most of the weight:
//
//	Scheduling verdicts. What the scheduler does with a node that lacks a constraint's
//	topologyKey differs between topology spread constraints and inter-pod affinity terms, and
//	NEITHER is modelled here. "will not schedule" and "cannot be scheduled" are already in
//	bannedDrainPhrases for the same reason and are banned here too.
//
//	Verdicts about intent. An unmatched PodDisruptionBudget may be pre-created for a workload
//	that is not deployed yet; a nodeSelector naming an absent label may be a node pool held at
//	zero on purpose; a quota may have been lowered deliberately during a freeze. "misconfigured",
//	"broken", "typo", "mistake", "wrong" all assert something nobody told us.
//
//	Drain and eviction vocabulary. k8s.config.pdb-selects-no-pods makes NO claim about what a
//	budget does — only that the disruption controller matched no pods with it. The drain family
//	owns budget claims and TestDrainRules_AlwaysNameTheBypass forces every one of them to name
//	the bypass in the same breath. Banning the vocabulary here means a future edit cannot make a
//	budget claim in this file without that caveat.
// ---------------------------------------------------------------------------------------------

var contradictionBannedPhrases = []string{
	// Scheduling verdicts.
	"will schedule", "will not schedule", "cannot be scheduled", "unschedulable",
	"never schedule", "nowhere to run", "will stay pending", "pending forever",
	"no pods will",
	// Verdicts about intent.
	"misconfigured", "broken", "typo", "mistake", "wrong", "orphan", "abandoned",
	// Outcomes and user impact. There is no traffic, revenue or SLA data in the snapshot.
	"downtime", "outage", "user-facing", "customer impact", "users",
	// Admission outcomes for the quota rule: a quota is a ceiling applied when an object is
	// admitted, and whether the API server has that admission plugin enabled is not readable
	// from a read-only client. So the rule states the arithmetic and never completes it.
	"will be rejected", "cannot create", "rejects",
	// Drain / eviction vocabulary — see the header.
	"drain", "eviction", "evict",
	// "guaranteed" lives in lexicon.Banned() and reaches every rule through
	// TestRuleOutput_ClearsTheGlobalCopyPolicy. Not restated here.
}

func contradictionRuleSet() []Rule {
	return []Rule{
		PDBSelectsNoPods{}, TopologyKeyNoNodeCarries{}, NodeSelectorNoNodeCarries{},
		QuotaBelowCommitted{}, NetPolPeerSelectsNoNamespace{},
	}
}

func TestSelfContradiction_EmitNoUnsupportableClaim(t *testing.T) {
	inv := contradictionInventory()
	for _, r := range contradictionRuleSet() {
		findings := r.Evaluate(inv, Options{})
		// NON-VACUITY GUARD. A phrase scan over an empty finding set passes trivially, which is
		// how three vacuous gates got into this tree in two days.
		if len(findings) == 0 {
			t.Fatalf("%s produced no findings on the contradiction fixture — the guard would be vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " "))
			for _, banned := range contradictionBannedPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s emits the banned phrase %q — the snapshot cannot support it.\n  finding: %s",
						r.ID(), banned, f.Title)
				}
			}
		}
	}
}

// TestSelfContradiction_NeverCarryDollars — a contradiction between two declarations has no price.
// There is no traffic, revenue or SLA data in the snapshot to derive one from.
func TestSelfContradiction_NeverCarryDollars(t *testing.T) {
	inv := contradictionInventory()
	any := 0
	for _, r := range contradictionRuleSet() {
		fs := r.Evaluate(inv, Options{})
		any += len(fs)
		for _, f := range fs {
			if f.DollarImpactMonthly != 0 {
				t.Errorf("%s put $%.2f on %q", r.ID(), f.DollarImpactMonthly, f.Title)
			}
			if f.PriceBasis != types.PriceNotCost {
				t.Errorf("%s set priceBasis=%q on %q — these findings have no cost dimension at all",
					r.ID(), f.PriceBasis, f.Title)
			}
		}
	}
	if any == 0 {
		t.Fatal("no findings at all — the dollar guard would be vacuous")
	}
}

// contradictionSilencingKinds names, per rule, the kinds whose refusal must silence it outright —
// the lists its ABSENCE claims are made over.
//
// IT IS NOT THE SAME AS RequiredKinds() AND MUST NOT BE. deps.go:26-31 is explicit that the
// declaration gates the COMPARISON and not the run: "Gating the run would mean a rule that walks
// Deployments, StatefulSets and DaemonSets loses its real Deployment findings when only DaemonSets
// was denied". A test that demanded silence for every declared kind would be demanding exactly the
// design deps.go rejects. So the silencing set is written down separately, and the test below
// asserts it is a SUBSET of RequiredKinds — a kind that silences a rule but is not declared would
// make a comparison read that silence as the cluster changing.
var contradictionSilencingKinds = map[string][]string{
	"k8s.config.pdb-selects-no-pods":              {"poddisruptionbudgets"},
	"k8s.config.topology-key-no-node-carries":     {"nodes"},
	"k8s.config.node-selector-no-node-carries":    {"nodes"},
	"k8s.config.quota-below-committed":            {"resourcequotas"},
	"k8s.config.netpol-peer-selects-no-namespace": {"namespaces", "networkpolicies"},
}

// TestSelfContradiction_SkipWhenTheInputWasDenied — every one of these five reasons about an ABSENCE
// (no node carries this key, no namespace matches this selector, the controller matched no pods),
// and each would fabricate a finding per object off one refused list. The positive assertion comes
// first: without it the test passes on a rule that never fires.
func TestSelfContradiction_SkipWhenTheInputWasDenied(t *testing.T) {
	for _, r := range contradictionRuleSet() {
		if len(r.Evaluate(contradictionInventory(), Options{})) == 0 {
			t.Fatalf("%s fires on nothing in the fixture — the denial guard test would be vacuous", r.ID())
		}
		silencing, ok := contradictionSilencingKinds[r.ID()]
		if !ok || len(silencing) == 0 {
			t.Fatalf("%s has no entry in contradictionSilencingKinds — every rule reasoning about absence needs one", r.ID())
		}
		declared := map[string]bool{}
		for _, k := range r.RequiredKinds() {
			declared[k] = true
		}
		for _, kind := range silencing {
			if !declared[kind] {
				t.Errorf("%s is silenced by a refused %q but does not declare it in RequiredKinds — a comparison "+
					"would read that silence as the cluster changing", r.ID(), kind)
			}
			inv := contradictionInventory()
			inv.Meta.Collected = withoutKind(inv.Meta.Collected, kind)
			inv.Meta.Denied = append(inv.Meta.Denied, kind+": forbidden")
			if got := r.Evaluate(inv, Options{}); len(got) != 0 {
				t.Errorf("%s emitted %d finding(s) with %q denied — an absent list is not an observed absence",
					r.ID(), len(got), kind)
			}
		}
	}
}

// TestNodeSelector_RefusedPodListDegradesRatherThanSilences — `pods` is declared in RequiredKinds
// but is NOT in the silencing set, and this test is why that is honest rather than sloppy. With the
// pod list refused the rule still states the label arithmetic (which needs no pods) and drops to the
// weaker reading, saying the list was not read. Both halves are asserted, so it fails whether the
// rule over-suppresses or silently claims nothing is bound.
func TestNodeSelector_RefusedPodListDegradesRatherThanSilences(t *testing.T) {
	inv := contradictionInventory()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "pods")
	inv.Meta.Denied = append(inv.Meta.Denied, "pods: forbidden")

	fs := (NodeSelectorNoNodeCarries{}).Evaluate(inv, Options{})
	if len(fs) == 0 {
		t.Fatal("a refused pod list silenced the rule — the label arithmetic does not depend on pods")
	}
	for _, f := range fs {
		if f.Severity != types.SeverityLow {
			t.Errorf("%q is severity %q with the pod list refused; the unknown case is the weaker claim",
				f.Title, f.Severity)
		}
		blob := strings.ToLower(strings.Join(f.Evidence, " ") + " " + f.Description)
		if !strings.Contains(blob, "not read") && !strings.Contains(blob, "not known") {
			t.Errorf("%q never says the pod list was not read — silence about a refused input is the defect", f.Title)
		}
		if strings.Contains(blob, "no pod of this workload is bound") {
			t.Errorf("%q asserts nothing is bound from a refused list", f.Title)
		}
	}
}

// withoutKind lives in rotation_test.go — one copy, same package.

// TestTopologyKey_DistinguishesEnforcementMode — a hard constraint and an advisory one are two
// different statements about the same missing label, and one sentence for both would be false for
// one of them. Same shape as the nil-versus-old lastSuccessfulTime split in silent_failures.go,
// where two branches that read alike WERE the defect.
func TestTopologyKey_DistinguishesEnforcementMode(t *testing.T) {
	byName := map[string]types.Finding{}
	for _, f := range (TopologyKeyNoNodeCarries{}).Evaluate(contradictionInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "Deployment" {
				byName[ref.Name] = f
			}
		}
	}
	hard, ok := byName["spread-required"]
	if !ok {
		t.Fatal("no finding for spread-required (topologyKey with DoNotSchedule) — nothing to compare")
	}
	soft, ok := byName["spread-preferred"]
	if !ok {
		t.Fatal("no finding for spread-preferred (topologyKey with ScheduleAnyway) — nothing to compare")
	}
	if hard.Description == soft.Description {
		t.Error("the hard-mode and advisory-mode descriptions are identical — one of them is false")
	}
	if hard.Severity == soft.Severity {
		t.Errorf("both modes carry severity %q — severity must follow the operator's declared enforcement mode",
			hard.Severity)
	}
	if _, fired := byName["spread-ok"]; fired {
		t.Error("spread-ok declares topology.kubernetes.io/zone, which both nodes carry — it must be silent")
	}
}

// TestNodeAffinity_AllTermsMustBeUnsatisfiable — nodeSelectorTerms are OR'd. One dead term beside a
// live one is the ordinary way to write "pool A or pool B" with B held at zero, and flagging it
// would report a correct declaration. Both halves are asserted, so the test fails whether the rule
// over-claims or falls silent everywhere.
func TestNodeAffinity_AllTermsMustBeUnsatisfiable(t *testing.T) {
	names := firedDeploymentNames((NodeSelectorNoNodeCarries{}).Evaluate(contradictionInventory(), Options{}))
	if names["aff-one-dead-one-live"] {
		t.Error("aff-one-dead-one-live has a satisfiable second nodeSelectorTerm — the OR makes the affinity satisfiable")
	}
	if !names["aff-both-dead"] {
		t.Error("aff-both-dead has no satisfiable term — it must fire, or this test proves nothing")
	}
}

// TestNodeAffinity_NegatedOperatorsAreNotFlagged — NotIn and DoesNotExist are SATISFIED by a missing
// label, so treating them like In/Exists inverts the claim. Asserted alongside a sibling that does
// fire, so the test cannot pass by the rule being globally silent.
func TestNodeAffinity_NegatedOperatorsAreNotFlagged(t *testing.T) {
	names := firedDeploymentNames((NodeSelectorNoNodeCarries{}).Evaluate(contradictionInventory(), Options{}))
	if names["aff-negated"] {
		t.Error("aff-negated requires DoesNotExist on an absent key — a missing label SATISFIES that")
	}
	if !names["pinned-dead"] {
		t.Error("pinned-dead must fire, or the negated-operator assertion above is vacuous")
	}
}

// TestNodeSelector_ParkedWorkloadIsNotReported — replicas 0 asks the scheduler for nothing, and a
// workload pinned to a cold pool is the ordinary way to park one.
func TestNodeSelector_ParkedWorkloadIsNotReported(t *testing.T) {
	names := firedDeploymentNames((NodeSelectorNoNodeCarries{}).Evaluate(contradictionInventory(), Options{}))
	if names["parked"] {
		t.Error("parked declares replicas 0 — nothing is being asked of the scheduler")
	}
	if names["pinned-ok"] {
		t.Error("pinned-ok selects kubernetes.io/os=linux, which both nodes carry")
	}
	if !names["pinned-dead"] {
		t.Fatal("pinned-dead must fire, or every assertion here is vacuous")
	}
}

// TestNodeSelector_BoundPodsChangeTheReading — nodeSelector and nodeAffinity are
// IgnoredDuringExecution, so a pod already bound stays bound when the labels change. "nothing has
// been placed against this declaration" and "these pods were placed before the labels diverged" are
// two different clusters and must not read alike.
func TestNodeSelector_BoundPodsChangeTheReading(t *testing.T) {
	var unbound, bound *types.Finding
	for _, f := range (NodeSelectorNoNodeCarries{}).Evaluate(contradictionInventory(), Options{}) {
		f := f
		for _, ref := range f.AffectedResources {
			switch ref.Name {
			case "pinned-dead":
				unbound = &f
			case "pinned-bound":
				bound = &f
			}
		}
	}
	if unbound == nil || bound == nil {
		t.Fatalf("need both readings: unbound=%v bound=%v", unbound != nil, bound != nil)
	}
	if unbound.Description == bound.Description {
		t.Error("the bound and unbound readings are identical — one of them is false")
	}
	if bound.Severity != types.SeverityLow {
		t.Errorf("a workload whose pods are already bound is severity %q, want low", bound.Severity)
	}
	if unbound.Severity == bound.Severity {
		t.Error("the two readings carry the same severity — the bound case is the weaker claim")
	}
}

// TestNetpolPeer_ResolvesSelectorsTheWayTheAPIDoes — namespaceSelector:{} selects ALL namespaces and
// a nil selector means the policy's own namespace. Getting either wrong turns a correct policy into a
// finding, so the silent cases are asserted beside firing ones.
//
// WHAT THIS TEST DOES AND DOES NOT MEASURE, because a probe showed the difference. Deleting the
// rule's explicit `{}` exemption does NOT make this test fail: metav1.LabelSelectorAsSelector turns
// an empty LabelSelector into labels.Everything(), which matches the first namespace and returns.
// The exemption is therefore defence-in-depth and documentation, not the load-bearing guard — the
// load-bearing part is that the rule compiles the selector through the API's own helper instead of
// hand-rolling a matchLabels loop. What this test CAN catch, and does, is the discrimination:
// inverting the match, or reporting a peer whose selector resolves, fails it. Written down rather
// than left implied, after "a test whose name claimed more than it measured".
func TestNetpolPeer_ResolvesSelectorsTheWayTheAPIDoes(t *testing.T) {
	fired := map[string]bool{}
	for _, f := range (NetPolPeerSelectsNoNamespace{}).Evaluate(contradictionInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "NetworkPolicy" {
				fired[ref.Name] = true
			}
		}
	}
	if fired["all-ns"] {
		t.Error("all-ns uses namespaceSelector:{} — that is every namespace, never zero")
	}
	if fired["live-peer"] {
		t.Error("live-peer selects name=other, which namespace \"other\" carries")
	}
	if !fired["dead-ingress"] {
		t.Error("dead-ingress selects a label no namespace carries — it must fire")
	}
	if !fired["dead-egress"] {
		t.Error("the egress path must be walked too, not only ingress")
	}
}

// TestQuotaBelowCommitted_EmptyStatusIsNotZero — a ResourceQuota carries no observedGeneration, so
// the presence of the key in status.used is the only freshness signal there is. An unanswered status
// read as zero would invent the finding out of a missing reading, which is the absence-versus-denial
// trap one level down: the object was collected, the answer was not.
func TestQuotaBelowCommitted_EmptyStatusIsNotZero(t *testing.T) {
	fired := map[string]bool{}
	for _, f := range (QuotaBelowCommitted{}).Evaluate(contradictionInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "ResourceQuota" {
				fired[ref.Name] = true
			}
		}
	}
	// spec.hard with no published status. THIS ASSERTION IS FALSIFIABLE AND THE FIXTURE MAKES IT SO:
	// the namespace's two bound pods request 1 CPU each against this quota's spec.hard of 1, so an
	// implementation that summed pod requests itself — which is how the backlog phrased this check —
	// would fire here. Ours reads the controller's own numbers and stays silent.
	if fired["nostatus"] {
		t.Error("nostatus has spec.hard and no published status — the controller has not answered, " +
			"and summing requests ourselves is not the same reading")
	}
	// status.used published, status.hard missing that key. An implementation iterating status.used and
	// defaulting a missing hard to zero fabricates a finding out of a partial status; this is the
	// dangerous direction, because unlike the case above it produces used > hard for any nonzero used.
	if fired["halfstatus"] {
		t.Error("halfstatus publishes used with no hard for that resource — a missing ceiling is not a ceiling of 0")
	}
	if fired["under"] {
		t.Error("under has used below hard — that is a quota doing its job")
	}
	if !fired["over"] {
		t.Error("over publishes used above hard — it must fire, or this test proves nothing")
	}
}

// TestPDBSelectsNoPods_StaleStatusIsNotZero — a budget created seconds before the reading has an
// empty status, and an empty status is not "matched no pods": it is "the disruption controller has
// not answered yet". Reuses pdbStatusIsFresh, the guard pdb_blocks_drains.go added for exactly this.
func TestPDBSelectsNoPods_StaleStatusIsNotZero(t *testing.T) {
	fired := map[string]bool{}
	for _, f := range (PDBSelectsNoPods{}).Evaluate(contradictionInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "PodDisruptionBudget" {
				fired[ref.Name] = true
			}
		}
	}
	if fired["stale-pdb"] {
		t.Error("stale-pdb has observedGeneration behind generation — its status describes another spec")
	}
	if fired["real-pdb"] {
		t.Error("real-pdb reports expectedPods=3 — the controller matched pods with it")
	}
	if !fired["unmatched-pdb"] {
		t.Error("unmatched-pdb reports expectedPods=0 with a caught-up status — it must fire")
	}
}

// TestPDBSelectsNoPods_DoesNotMatchSelectorsItself — the rule reads the disruption controller's own
// expectedPods rather than matching the selector against workloads(). That is not a style choice:
// workloads() knows Deployments, StatefulSets and DaemonSets only, so a budget over CloudNativePG
// Cluster or Strimzi StrimziPodSet pods would look unmatched. Eviction does not care who owns a pod.
// The fixture's unmatched-pdb selector matches a pod owned by NOTHING the workload index knows, and
// its status says the controller found it — so a selector-matching implementation fails here.
func TestPDBSelectsNoPods_DoesNotMatchSelectorsItself(t *testing.T) {
	inv := contradictionInventory()
	for _, f := range (PDBSelectsNoPods{}).Evaluate(inv, Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "PodDisruptionBudget" && ref.Name == "operator-pdb" {
				t.Errorf("operator-pdb guards an operator-owned pod the workload index cannot see, "+
					"and its status.expectedPods=%d says the controller matched it",
					inv.PDBs[operatorPDBIndex(inv)].Status.ExpectedPods)
			}
		}
	}
}

func operatorPDBIndex(inv *collect.Inventory) int {
	for i := range inv.PDBs {
		if inv.PDBs[i].Name == "operator-pdb" {
			return i
		}
	}
	return 0
}

func firedDeploymentNames(fs []types.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "Deployment" || ref.Kind == "StatefulSet" || ref.Kind == "DaemonSet" {
				out[ref.Name] = true
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// The fixture. Two nodes carrying hostname / zone / os labels and NOT carrying
// topology.kubernetes.io/rack or pool, which is what every unsatisfiable declaration below names.
// ---------------------------------------------------------------------------------------------

func contradictionInventory() *collect.Inventory {
	return &collect.Inventory{
		Nodes: []corev1.Node{
			contradictionNode("node-a", "eu-central-1a"),
			contradictionNode("node-b", "eu-central-1b"),
		},
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"name": "app"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"name": "other"}}},
		},
		Pods: []corev1.Pod{
			// Bound to node-a even though its workload's nodeSelector names an absent label: these
			// fields are IgnoredDuringExecution, so a label change after binding leaves the pod put.
			contradictionPod("pinned-bound-0", "node-a", map[string]string{"app": "pinned-bound"}),
			// Owned by nothing workloads() knows — the CloudNativePG / StrimziPodSet shape.
			contradictionPod("pg-cluster-1", "node-b", map[string]string{"cnpg.io/cluster": "pg"}),
		},
		Deployments: []appsv1.Deployment{
			contradictionDeploy("spread-required", 3, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
					MaxSkew:           1,
					TopologyKey:       "topology.kubernetes.io/rack",
					WhenUnsatisfiable: corev1.DoNotSchedule,
				}}
			}),
			contradictionDeploy("spread-preferred", 3, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
					MaxSkew:           1,
					TopologyKey:       "topology.kubernetes.io/rack",
					WhenUnsatisfiable: corev1.ScheduleAnyway,
				}}
			}),
			contradictionDeploy("spread-ok", 3, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
					MaxSkew:           1,
					TopologyKey:       "topology.kubernetes.io/zone",
					WhenUnsatisfiable: corev1.DoNotSchedule,
				}}
			}),
			contradictionDeploy("affinity-required", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Affinity = &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
							TopologyKey:   "topology.kubernetes.io/rack",
							LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "affinity-required"}},
						}},
					},
				}
			}),
			contradictionDeploy("pinned-dead", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.NodeSelector = map[string]string{"pool": "gpu"}
			}),
			contradictionDeploy("pinned-bound", 1, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.NodeSelector = map[string]string{"pool": "gpu"}
			}),
			contradictionDeploy("pinned-ok", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.NodeSelector = map[string]string{"kubernetes.io/os": "linux"}
			}),
			contradictionDeploy("parked", 0, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.NodeSelector = map[string]string{"pool": "gpu"}
			}),
			contradictionDeploy("aff-one-dead-one-live", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Affinity = requiredNodeAffinity(
					nodeTerm("pool", corev1.NodeSelectorOpIn, "gpu"),
					nodeTerm("kubernetes.io/os", corev1.NodeSelectorOpIn, "linux"),
				)
			}),
			contradictionDeploy("aff-both-dead", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Affinity = requiredNodeAffinity(
					nodeTerm("pool", corev1.NodeSelectorOpIn, "gpu"),
					nodeTerm("rack", corev1.NodeSelectorOpExists),
				)
			}),
			contradictionDeploy("aff-negated", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Affinity = requiredNodeAffinity(
					nodeTerm("pool", corev1.NodeSelectorOpDoesNotExist),
				)
			}),
		},
		PDBs: []policyv1.PodDisruptionBudget{
			contradictionPDB("unmatched-pdb", 0, 1, 1),
			contradictionPDB("real-pdb", 3, 1, 1),
			contradictionPDB("stale-pdb", 0, 2, 1),
			// The controller matched an operator-owned pod with this one. A rule matching selectors
			// against workloads() would report it as matching nothing.
			contradictionPDB("operator-pdb", 1, 1, 1),
		},
		ResourceQuotas: []corev1.ResourceQuota{
			contradictionQuota("over", "4", "6"),
			contradictionQuota("under", "8", "2"),
			// spec.hard=1 against 2 CPU of pod requests in this namespace, so an implementation that
			// summed requests itself would fire on it. See TestQuotaBelowCommitted_EmptyStatusIsNotZero.
			specOnlyQuota("nostatus", "1"),
			halfStatusQuota("halfstatus", "6"),
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{
			netpolWithIngressPeer("dead-ingress", &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "ghost"}}),
			netpolWithIngressPeer("all-ns", &metav1.LabelSelector{}),
			netpolWithIngressPeer("live-peer", &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "other"}}),
			netpolWithEgressPeer("dead-egress", &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "vanished"}}),
		},
		Meta: collect.Meta{
			Collected: []string{
				"daemonsets", "deployments", "namespaces", "networkpolicies", "nodes", "pods",
				"poddisruptionbudgets", "resourcequotas", "statefulsets",
			},
			StartedAt: rotNow,
		},
	}
}

func contradictionNode(name, zone string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			"kubernetes.io/hostname":        name,
			"kubernetes.io/os":              "linux",
			"topology.kubernetes.io/zone":   zone,
			"topology.kubernetes.io/region": "eu-central-1",
		},
	}}
}

func contradictionPod(name, node string, labels map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app", Labels: labels},
		Spec: corev1.PodSpec{
			NodeName: node,
			// 1 CPU each. Load-bearing for TestQuotaBelowCommitted_EmptyStatusIsNotZero: the two of
			// them exceed the "nostatus" quota's spec.hard, so a rule that summed requests itself
			// would fire on a quota whose controller has published nothing.
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "app:1",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func contradictionDeploy(name string, replicas int32, mut func(*appsv1.Deployment)) appsv1.Deployment {
	r := replicas
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &r,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "app:1"}},
				},
			},
		},
	}
	if mut != nil {
		mut(&d)
	}
	return d
}

func requiredNodeAffinity(terms ...corev1.NodeSelectorTerm) *corev1.Affinity {
	return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: terms,
		},
	}}
}

func nodeTerm(key string, op corev1.NodeSelectorOperator, values ...string) corev1.NodeSelectorTerm {
	return corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{
		Key: key, Operator: op, Values: values,
	}}}
}

func contradictionPDB(name string, expected int32, generation, observed int64) policyv1.PodDisruptionBudget {
	one := intstr.FromInt32(1)
	return policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app", Generation: generation},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &one,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"pdb": name}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: observed,
			ExpectedPods:       expected,
			CurrentHealthy:     expected,
			DesiredHealthy:     1,
			DisruptionsAllowed: 0,
		},
	}
}

func contradictionQuota(name, hard, used string) corev1.ResourceQuota {
	q := corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"}}
	q.Spec.Hard = corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(hard)}
	q.Status.Hard = corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(hard)}
	q.Status.Used = corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(used)}
	return q
}

// specOnlyQuota is a quota the controller has not answered for: spec.hard is set and status is empty.
func specOnlyQuota(name, hard string) corev1.ResourceQuota {
	return corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
		Spec:       corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(hard)}},
	}
}

// halfStatusQuota publishes status.used with NO status.hard for that resource — a partially computed
// status, which is not a ceiling of zero.
func halfStatusQuota(name, used string) corev1.ResourceQuota {
	q := corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"}}
	q.Spec.Hard = corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse("4")}
	q.Status.Used = corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse(used)}
	return q
}

func netpolWithIngressPeer(name string, ns *metav1.LabelSelector) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: ns}},
			}},
		},
	}
}

func netpolWithEgressPeer(name string, ns *metav1.LabelSelector) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: ns}},
			}},
		},
	}
}
