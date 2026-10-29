package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// ---------------------------------------------------------------------------------------------
// ROLLOUT PREFLIGHT — the guard for what these rules may not say.
//
// Two of these bans are the whole reason this epic exists.
//
// "blocked" / "blocks" / "will block" are banned even in the rule that NAMES a PodDisruptionBudget,
// because a PDB cannot block a rolling update and that is the entire finding. PDBs are enforced by
// the Eviction API; a rollout scales the old ReplicaSet down and the ReplicaSet controller DELETEs
// pods, which never consults the budget. Proven on the kind testbed: the same pod under the same
// zero-budget PDB returned 429 to an eviction and was replaced by a rollout minutes later.
//
// Scheduling verdicts are banned because requests-versus-usage reasoning is wrong in both
// directions and has already cost this project a founder-caught $1,121 "saving" that would have
// caused an OOM. The surge rule compares requests to ALLOCATABLE and says "capacity", never
// "will schedule".
// ---------------------------------------------------------------------------------------------

var rolloutBannedPhrases = []string{
	// Durations. No reading of image pull time, probe timing or controller throughput exists.
	"minutes", "seconds", "will take", "slow", "how long", "quickly",
	// Outcomes and user impact.
	"downtime", "outage", "will fail", "cannot begin", "users", "user-facing", "customer",
	"traffic", "impact", "is down", "service",
	// Scheduling verdicts.
	// "guaranteed" is global — see TestEveryRuleOutput_ClearsTheGlobalCopyPolicy.
	"will schedule", "will not schedule", "cannot be scheduled", "unschedulable",
	// §9: the PDB does not sit on this path, so nothing here may say it stops anything.
	"blocked", "blocks", "will block", "prevents the rollout",
}

// rolloutPDBSilentPhrases apply to the rules that must not reference a PDB AT ALL. The
// contradiction rule is deliberately exempt: naming the declared minimum is its whole content.
var rolloutPDBSilentPhrases = []string{
	"disruption budget", "poddisruptionbudget", "pdb", "minavailable", "desiredhealthy", "eviction",
}

func rolloutRuleSet() []Rule {
	return []Rule{
		RolloutDoesNotSelfRoll{}, RolloutNeedsSurgeCapacity{},
		RolloutContradictsDeclaredMinimum{}, StatefulSetPartitionLeftBehind{},
	}
}

func TestRolloutRules_EmitNoUnsupportableClaim(t *testing.T) {
	inv := rolloutInventory()
	for _, r := range rolloutRuleSet() {
		findings := r.Evaluate(inv, Options{})
		if len(findings) == 0 {
			t.Fatalf("%s produced no findings on the rollout fixture — the guard would be vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " "))
			for _, banned := range rolloutBannedPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s emits the banned phrase %q — the snapshot cannot support it.\n  finding: %s",
						r.ID(), banned, f.Title)
				}
			}
		}
	}
}

func TestRolloutRules_NeverCarryDollars(t *testing.T) {
	inv := rolloutInventory()
	for _, r := range rolloutRuleSet() {
		for _, f := range r.Evaluate(inv, Options{}) {
			if f.DollarImpactMonthly != 0 {
				t.Errorf("%s put $%.2f on %q", r.ID(), f.DollarImpactMonthly, f.Title)
			}
		}
	}
}

// THE REGRESSION GUARD FOR THE WHOLE EPIC. The fixture holds a zero-budget PDB matching the
// workloads, so a future edit that "improves" these rules by reading it will fail here. Only the
// contradiction rule may name a declared minimum, and even it may not say the budget stops anything.
func TestRolloutRules_NeverMentionAPDBExceptTheContradictionRule(t *testing.T) {
	inv := rolloutInventory()
	silent := []Rule{RolloutDoesNotSelfRoll{}, RolloutNeedsSurgeCapacity{}, StatefulSetPartitionLeftBehind{}}
	for _, r := range silent {
		findings := r.Evaluate(inv, Options{})
		if len(findings) == 0 {
			t.Fatalf("%s produced nothing, so this guard is vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters, strings.Join(f.Evidence, " "),
			}, " "))
			for _, banned := range rolloutPDBSilentPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s references %q. A PodDisruptionBudget does not gate a rolling update; "+
						"reading one here would report a false blocker.\n  finding: %s", r.ID(), banned, f.Title)
				}
			}
		}
		// And the rules must not declare a dependency on a kind they do not read.
		for _, k := range r.RequiredKinds() {
			if k == "poddisruptionbudgets" {
				t.Errorf("%s declares poddisruptionbudgets, which it must not read", r.ID())
			}
		}
	}
}

// The Recreate branch was removed because it duplicated k8s.workload.risky-rollout-strategy, which
// has fired on Deployment Recreate since f37abf2 and carries the remediation and the ReadWriteOnce
// caveat this rule never had. Two findings on one object double-count one configuration, and
// verdict.Select collapses per RuleID so it cannot dedupe them.
//
// This test is the guard: it fails if either rule stops owning its half, in either direction.
func TestRolloutDoesNotSelfRoll_OwnsOnDeleteOnlyAndRecreateBelongsToTheOlderRule(t *testing.T) {
	inv := rolloutInventory()

	for _, f := range (RolloutDoesNotSelfRoll{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Kind == "Deployment" {
			t.Errorf("this rule fired on a Deployment (%s) — Recreate belongs to risky-rollout-strategy, "+
				"and two findings on one object double-count it", f.AffectedResources[0].Name)
		}
		if !strings.Contains(strings.ToLower(f.Title+f.Description), "ondelete") {
			t.Errorf("a finding that is not about OnDelete: %q", f.Title)
		}
		// The rule is no longer named for passing through zero, and must not claim it: an OnDelete
		// StatefulSet's replica count is untouched — nothing rolls at all.
		if strings.Contains(strings.ToLower(f.Title+f.Description+strings.Join(f.Evidence, " ")), "reaches 0") {
			t.Errorf("OnDelete does not pass through zero, but the finding says it does: %q", f.Title)
		}
	}

	var covered bool
	for _, f := range (RiskyRolloutStrategy{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Kind == "Deployment" && f.AffectedResources[0].Name == "recreate" {
			covered = true
		}
	}
	if !covered {
		t.Error("risky-rollout-strategy no longer covers Deployment Recreate — removing it here left a gap")
	}
}

func TestRolloutNeedsSurgeCapacity_FiresOnlyWhenTheSurgeDoesNotFit(t *testing.T) {
	fs := (RolloutNeedsSurgeCapacity{}).Evaluate(rolloutInventory(), Options{})
	names := map[string]string{}
	for _, f := range fs {
		names[f.AffectedResources[0].Name] = strings.Join(f.Evidence, " ")
	}
	if _, ok := names["surge-short"]; !ok {
		t.Fatalf("the Deployment whose surge does not fit produced no finding; got %v", keysOf(names))
	}
	if _, ok := names["surge-fits"]; ok {
		t.Errorf("a Deployment whose surge fits in aggregate was reported: %s", names["surge-fits"])
	}
	if _, ok := names["no-requests"]; ok {
		t.Errorf("a Deployment whose template declares no requests was reported; the arithmetic cannot "+
			"bound a surge it has no numbers for: %s", names["no-requests"])
	}
	blob := names["surge-short"]
	for _, want := range []string{"allocatable", "maxSurge", "capacity"} {
		if !strings.Contains(blob, want) {
			t.Errorf("evidence does not cite %q:\n  %s", want, blob)
		}
	}
	if !strings.Contains(blob, "fragment") {
		t.Errorf("the per-node fragmentation caveat is missing, so the aggregate reading is presented as "+
			"more than it is:\n  %s", blob)
	}
}

// A surge that fits in aggregate but on no single node must produce NOTHING. We have not read
// taints, affinity, topology spread or the scheduler, so the honest answer is silence — not a
// prediction in either direction.
func TestRolloutNeedsSurgeCapacity_SaysNothingAboutFragmentation(t *testing.T) {
	inv := rolloutInventory()
	// Replace the node set with many small nodes: 8 CPU free in aggregate, 1 CPU free per node.
	inv.Nodes = nil
	inv.Pods = nil
	for i := 0; i < 8; i++ {
		n := "small-" + string(rune('a'+i))
		inv.Nodes = append(inv.Nodes, rolloutNode(n, "4", "8Gi"))
		inv.Pods = append(inv.Pods, rolloutBoundPod("filler-"+n, n, "3", "6Gi"))
	}
	for _, f := range (RolloutNeedsSurgeCapacity{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Name == "surge-short" {
			t.Errorf("a surge that fits in aggregate was reported as short of capacity, which is a "+
				"per-node claim this rule does not make: %v", f.Evidence)
		}
	}
}

// The claim is a contradiction between two declarations the operator wrote, and it must say in the
// same finding that the budget mechanism does not sit on this path.
func TestRolloutContradictsDeclaredMinimum_ComparesTwoDeclarations(t *testing.T) {
	fs := (RolloutContradictsDeclaredMinimum{}).Evaluate(rolloutInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.AffectedResources[0].Name] = f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " ")
	}
	blob, ok := got["contradiction"]
	if !ok {
		t.Fatalf("the contradicting Deployment produced no finding; got %v", keysOf(got))
	}
	for _, want := range []string{"desiredHealthy", "maxUnavailable", "expectedPods"} {
		if !strings.Contains(blob, want) {
			t.Errorf("evidence does not cite %q:\n  %s", want, blob)
		}
	}
	if !strings.Contains(strings.ToLower(blob), "not consulted") && !strings.Contains(strings.ToLower(blob), "does not constrain") {
		t.Errorf("the finding never says the budget mechanism is not on this path, which is the whole "+
			"content of the claim:\n  %s", blob)
	}
	if _, bad := got["agrees"]; bad {
		t.Errorf("a Deployment whose strategy stays above the declared minimum was reported: %s", got["agrees"])
	}
}

// A PDB whose status has not been computed is not a declared minimum of zero — it is a controller
// that has not answered yet. This is B-098's lesson one level down.
func TestRolloutContradictsDeclaredMinimum_IgnoresAnUncomputedPDBStatus(t *testing.T) {
	inv := rolloutInventory()
	for i := range inv.PDBs {
		if inv.PDBs[i].Name == "contradiction-pdb" {
			inv.PDBs[i].Status = policyv1.PodDisruptionBudgetStatus{} // never computed
			inv.PDBs[i].Generation = 2
		}
	}
	for _, f := range (RolloutContradictsDeclaredMinimum{}).Evaluate(inv, Options{}) {
		if f.AffectedResources[0].Name == "contradiction" {
			t.Errorf("a PDB with no computed status was read as a declared minimum: %v", f.Evidence)
		}
	}
}

// A partition left on a StatefulSet holds the low ordinals on the old revision permanently, and
// nothing in the cluster reports it. The finding must name which ordinals.
func TestStatefulSetPartitionLeftBehind_NamesTheOrdinalsItHoldsBack(t *testing.T) {
	fs := (StatefulSetPartitionLeftBehind{}).Evaluate(rolloutInventory(), Options{})
	got := map[string]string{}
	for _, f := range fs {
		got[f.AffectedResources[0].Name] = f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " ")
	}
	blob, ok := got["partitioned"]
	if !ok {
		t.Fatalf("the partitioned StatefulSet produced no finding; got %v", keysOf(got))
	}
	for _, want := range []string{"partition=3", "5 replica", "ordinal"} {
		if !strings.Contains(blob, want) {
			t.Errorf("evidence does not cite %q:\n  %s", want, blob)
		}
	}
	if !strings.Contains(blob, "currentRevision") {
		t.Errorf("the finding does not cite the revision fields, which are what make the claim a reading "+
			"rather than a hypothetical:\n  %s", blob)
	}
	if _, bad := got["ondelete"]; bad {
		t.Error("an OnDelete StatefulSet was reported by the partition rule; partition has no meaning there")
	}
	if _, bad := got["plain-sts"]; bad {
		t.Errorf("a StatefulSet with no partition was reported: %s", got["plain-sts"])
	}
}

// NO ROUND ARITHMETIC FOR STATEFULSETS, and therefore no reading of a field behind a feature gate.
// spec.updateStrategy.rollingUpdate.maxUnavailable sits behind MaxUnavailableStatefulSet, which is
// not readable from a read-only client on EKS/AKS/GKE — so a rule that counted rounds would be
// wrong on some clusters and could not know which.
func TestRolloutRules_NeverCountStatefulSetRounds(t *testing.T) {
	inv := rolloutInventory()
	for _, r := range rolloutRuleSet() {
		for _, f := range r.Evaluate(inv, Options{}) {
			blob := strings.ToLower(f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " "))
			for _, banned := range []string{"one pod at a time", "rounds", "maxunavailablestatefulset"} {
				if strings.Contains(blob, banned) {
					t.Errorf("%s says %q about a StatefulSet update; the feature gate that decides it is "+
						"unreadable:\n  %s", r.ID(), banned, f.Title)
				}
			}
		}
	}
}

// The capacity rule is the only one that reads Nodes, and it reasons about insufficiency, which is
// an absence claim.
func TestRolloutRules_DenialGuard(t *testing.T) {
	for _, denied := range []string{"nodes", "pods"} {
		inv := rolloutInventory()
		inv.Meta.Collected = withoutKind(inv.Meta.Collected, denied)
		inv.Meta.Denied = append(inv.Meta.Denied, denied+": forbidden")
		if fs := (RolloutNeedsSurgeCapacity{}).Evaluate(inv, Options{}); len(fs) != 0 {
			t.Errorf("the capacity rule emitted %d findings with %q denied", len(fs), denied)
		}
		// The strategy rules never read either kind and must keep firing.
		if fs := (RolloutDoesNotSelfRoll{}).Evaluate(inv, Options{}); len(fs) == 0 {
			t.Errorf("rollout-does-not-self-roll fell silent when only %q was denied, but it reads neither", denied)
		}
	}
	// The strategy fields ARE the claim, so whichever workload kind a rule reads must be declared —
	// otherwise a comparison would read a denied workload list as a fixed cluster.
	declares := func(r Rule, kind string) bool {
		for _, k := range r.RequiredKinds() {
			if k == kind {
				return true
			}
		}
		return false
	}
	// statefulsets ONLY: deployments went with the Recreate branch, and a kind the rule no longer
	// reads must not be declared — a comparison would then report it unevaluated on a full run.
	if !declares(RolloutDoesNotSelfRoll{}, "statefulsets") {
		t.Errorf("rollout-does-not-self-roll does not declare statefulsets: %v",
			(RolloutDoesNotSelfRoll{}).RequiredKinds())
	}
	if declares(RolloutDoesNotSelfRoll{}, "deployments") {
		t.Errorf("rollout-does-not-self-roll still declares deployments, which it no longer reads: %v",
			(RolloutDoesNotSelfRoll{}).RequiredKinds())
	}
	if !declares(StatefulSetPartitionLeftBehind{}, "statefulsets") {
		t.Errorf("the partition rule does not declare statefulsets: %v",
			(StatefulSetPartitionLeftBehind{}).RequiredKinds())
	}
	// The capacity rule's headroom side sums BOUND POD REQUESTS, so the pod list is load-bearing:
	// without it the requested side reads as ~0 and abundant headroom is fabricated out of a
	// collection gap. The design spec omitted `pods` here; that was wrong and this pins it.
	if !declares(RolloutNeedsSurgeCapacity{}, "pods") || !declares(RolloutNeedsSurgeCapacity{}, "nodes") {
		t.Errorf("the capacity rule must declare nodes AND pods; it declares %v",
			(RolloutNeedsSurgeCapacity{}).RequiredKinds())
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------------------------

func rolloutNode(name, cpu, mem string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
			},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
}

func rolloutBoundPod(name, node, cpu, mem string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{{Name: "main", Image: "img", Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse(cpu),
					corev1.ResourceMemory: resource.MustParse(mem),
				},
			}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func rolloutDeploy(name string, replicas int32, cpu, mem string, mutate func(*appsv1.Deployment)) appsv1.Deployment {
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "main", Image: "img",
				}}},
			},
		},
	}
	if cpu != "" || mem != "" {
		req := corev1.ResourceList{}
		if cpu != "" {
			req[corev1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem != "" {
			req[corev1.ResourceMemory] = resource.MustParse(mem)
		}
		d.Spec.Template.Spec.Containers[0].Resources.Requests = req
	}
	if mutate != nil {
		mutate(&d)
	}
	return d
}

func rollingUpdate(maxUnavailable, maxSurge intstr.IntOrString) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		mu, ms := maxUnavailable, maxSurge
		d.Spec.Strategy = appsv1.DeploymentStrategy{
			Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{
				MaxUnavailable: &mu,
				MaxSurge:       &ms,
			},
		}
	}
}

func rolloutSts(name string, replicas int32, mutate func(*appsv1.StatefulSet)) appsv1.StatefulSet {
	s := appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
			},
		},
		Status: appsv1.StatefulSetStatus{
			Replicas: replicas, CurrentRevision: name + "-abc123", UpdateRevision: name + "-abc123",
		},
	}
	if mutate != nil {
		mutate(&s)
	}
	return s
}

// rolloutPDB publishes a computed status, because a PDB on a real cluster always has one and a
// fixture without one is not a smaller cluster — it is an impossible one (B-098).
func rolloutPDB(name, app string, expected, desired int32) policyv1.PodDisruptionBudget {
	min := intstr.FromInt32(desired)
	return policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", Generation: 1},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &min,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1,
			ExpectedPods:       expected,
			CurrentHealthy:     expected,
			DesiredHealthy:     desired,
			DisruptionsAllowed: expected - desired,
		},
	}
}

func rolloutInventory() *collect.Inventory {
	one := intstr.FromInt32(1)
	zero := intstr.FromInt32(0)
	half := intstr.FromString("50%")

	return &collect.Inventory{
		// 2 nodes, 8 CPU / 16Gi allocatable in total; 6 CPU / 8Gi already requested by bound pods,
		// leaving 2 CPU / 8Gi of requested headroom.
		Nodes: []corev1.Node{
			rolloutNode("node-a", "4", "8Gi"),
			rolloutNode("node-b", "4", "8Gi"),
		},
		Pods: []corev1.Pod{
			rolloutBoundPod("filler-a", "node-a", "3", "4Gi"),
			rolloutBoundPod("filler-b", "node-b", "3", "4Gi"),
		},
		Deployments: []appsv1.Deployment{
			// Recreate: the replica count reaches 0 on every update.
			rolloutDeploy("recreate", 3, "100m", "128Mi", func(d *appsv1.Deployment) {
				d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
			}),
			// maxUnavailable=0, maxSurge=50% of 4 = 2 pods needing 4 CPU: does not fit in 2 CPU.
			rolloutDeploy("surge-short", 4, "2", "1Gi", rollingUpdate(zero, half)),
			// maxUnavailable=0, maxSurge=1 pod needing 100m: fits.
			rolloutDeploy("surge-fits", 2, "100m", "128Mi", rollingUpdate(zero, one)),
			// maxUnavailable=0 with no requests at all: the arithmetic has no numbers to bound.
			rolloutDeploy("no-requests", 2, "", "", rollingUpdate(zero, one)),
			// replicas 3 - maxUnavailable 1 = 2 available, against a declared desiredHealthy of 3.
			rolloutDeploy("contradiction", 3, "100m", "128Mi", rollingUpdate(one, one)),
			// replicas 4 - maxUnavailable 1 = 3 available, against a declared desiredHealthy of 3.
			rolloutDeploy("agrees", 4, "100m", "128Mi", rollingUpdate(one, one)),
		},
		StatefulSets: []appsv1.StatefulSet{
			rolloutSts("ondelete", 3, func(s *appsv1.StatefulSet) {
				s.Spec.UpdateStrategy = appsv1.StatefulSetUpdateStrategy{
					Type: appsv1.OnDeleteStatefulSetStrategyType,
				}
			}),
			rolloutSts("partitioned", 5, func(s *appsv1.StatefulSet) {
				p := int32(3)
				s.Spec.UpdateStrategy = appsv1.StatefulSetUpdateStrategy{
					Type:          appsv1.RollingUpdateStatefulSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateStatefulSetStrategy{Partition: &p},
				}
				s.Status.CurrentRevision = "partitioned-old"
				s.Status.UpdateRevision = "partitioned-new"
				s.Status.UpdatedReplicas = 2
			}),
			rolloutSts("plain-sts", 3, nil),
		},
		// A zero-budget PDB matching a workload, so any rule that reads one for a rollout claim
		// fails TestRolloutRules_NeverMentionAPDBExceptTheContradictionRule.
		PDBs: []policyv1.PodDisruptionBudget{
			rolloutPDB("contradiction-pdb", "contradiction", 3, 3),
			rolloutPDB("agrees-pdb", "agrees", 4, 3),
			rolloutPDB("recreate-pdb", "recreate", 3, 3),
		},
		Meta: collect.Meta{
			Collected: []string{"deployments", "statefulsets", "nodes", "pods", "poddisruptionbudgets"},
			StartedAt: rotNow,
		},
	}
}
