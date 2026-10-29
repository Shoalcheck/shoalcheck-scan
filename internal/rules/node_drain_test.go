package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types2 "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ---------------------------------------------------------------------------------------------
// THE HONESTY GUARD
//
// Drain Preflight makes the most dangerous claims in this product: statements about what will
// happen to a cluster. An adversarial review established exactly which of those statements a
// read-only snapshot can and cannot support, and this test is what keeps the line where the review
// put it.
//
// The refusals are not stylistic. Each one corresponds to something the snapshot genuinely cannot
// know:
//
//   durations       — a probe-derived floor inverts precisely where it is most dangerous, since a
//                     workload with no readinessProbe would score as the FASTEST recovery while
//                     being the most likely to serve errors. And pod-recovery time is not
//                     service-downtime time.
//   user impact     — a selector match is not a published endpoint, and a published endpoint is not a request
//                     membership; type=LoadBalancer is not proof of internet exposure (internal LBs
//                     are annotation-only) and a ClusterIP can be exposed through a mesh gateway;
//                     cross-cluster and DNS failover sit entirely outside the kubeconfig.
//   "SPOF"          — an outcome claim resting on at least four systematic blind spots. The provable
//                     statement is placement arithmetic.
//   survival scores — a single unknown falsifies a universal claim. The snapshot supports existential
//                     statements about mechanism, never "your cluster survives any one node".
//   scheduling      — requests-versus-usage is wrong in both directions; this project already has a
//                     founder-caught false positive of exactly that shape ($1,121 of "headroom" that
//                     was really an OOM). Reading affinity fields is not simulating the scheduler.
//   control-plane
//   timing          — node-monitor-grace-period and DefaultTolerationSeconds are provider-set flags,
//                     unreadable on EKS/AKS/GKE, and taint-eviction can be disabled outright.
//
// If a future contributor deletes this test to make a finding read better, the feature silently
// reverts to the version that was rejected on review. It plays the same structural role for claims
// that TestSafety_IgnoresConfidence plays for remediation safety.
// ---------------------------------------------------------------------------------------------

// bannedDrainPhrases must never appear in anything the three drain rules emit.
var bannedDrainPhrases = []string{
	"downtime", "user-visible", "user-facing", "customer impact", "outage",
	"spof", "single point of failure",
	"seconds", "minutes", "will be down", "goes down",
	"survives", "resilience score",
	// Endpoint vocabulary: a published entry is not traffic. Present-tense membership is
	// arithmetic; every one of these implies an outcome the snapshot cannot support.
	// Phrases, not bare words: rule C legitimately says a NODE is unreachable, and the mandatory
	// not-traffic caveat itself contains the word "traffic". Banning either bare word would force
	// the honest sentences out.
	"rotation", "traffic path", "receives traffic", "serves traffic", "serving traffic",
	"reachable from", "blackhole", "resolves to nothing", "only backend", "last backend",
	"will schedule", "will not schedule", "cannot be scheduled",
	// "guaranteed" lives in lexicon.Banned() — the GLOBAL copy policy — and is applied to every
	// rule by TestEveryRuleOutput_ClearsTheGlobalCopyPolicy. Restating it here is the drift the
	// lexicon package exists to end. This list keeps only the drain family's own vocabulary.
	"no impact",
}

func TestDrainRules_EmitNoUnsupportableClaim(t *testing.T) {
	inv := drainInventory()
	for _, r := range []Rule{NodeDrainBudget{}, NodePlacementConcentration{}, NodePinnedVolume{}} {
		findings := r.Evaluate(inv, Options{IncludeSystem: true})
		if len(findings) == 0 {
			t.Fatalf("%s produced no findings on the drain fixture — the guard would be vacuous", r.ID())
		}
		for _, f := range findings {
			blob := strings.ToLower(strings.Join([]string{
				f.Title, f.Description, f.WhyItMatters,
				strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
			}, " "))
			for _, banned := range bannedDrainPhrases {
				if strings.Contains(blob, banned) {
					t.Errorf("%s emits the banned phrase %q — the snapshot cannot support it.\n  finding: %s",
						r.ID(), banned, f.Title)
				}
			}
		}
	}
}

// TestDrainRules_NeverCarryDollars — there is no traffic, revenue or SLA data in the snapshot, so a
// dollar figure on a drain finding would be invented outright.
func TestDrainRules_NeverCarryDollars(t *testing.T) {
	inv := drainInventory()
	for _, r := range []Rule{NodeDrainBudget{}, NodePlacementConcentration{}, NodePinnedVolume{}} {
		for _, f := range r.Evaluate(inv, Options{IncludeSystem: true}) {
			if f.DollarImpactMonthly != 0 {
				t.Errorf("%s put $%.2f on %q", r.ID(), f.DollarImpactMonthly, f.Title)
			}
		}
	}
}

// TestDrainRules_AlwaysNameTheBypass — every budget claim must say, in the same breath, that a
// PodDisruptionBudget constrains only voluntary eviction. A reader who takes "the PDB blocks this"
// as protection against the node dying has been misled by omission.
func TestDrainRules_AlwaysNameTheBypass(t *testing.T) {
	for _, f := range (NodeDrainBudget{}).Evaluate(drainInventory(), Options{IncludeSystem: true}) {
		blob := strings.ToLower(strings.Join(f.Evidence, " ") + " " + f.WhyItMatters)
		for _, want := range []string{"voluntary", "force"} {
			if !strings.Contains(blob, want) {
				t.Errorf("budget finding %q never mentions %q — the bypass must be named with the claim",
					f.Title, want)
			}
		}
	}
}

// TestDrainRules_SkipWhenTheInputWasDenied — an empty pod or node list read as observed absence
// fabricates findings. Mirrors the denial guard every other rule in this package carries.
func TestDrainRules_SkipWhenTheInputWasDenied(t *testing.T) {
	for _, denied := range []string{"nodes", "pods", "poddisruptionbudgets"} {
		inv := drainInventory()
		// Move the step from Collected to Denied.
		var kept []string
		for _, c := range inv.Meta.Collected {
			if c != denied {
				kept = append(kept, c)
			}
		}
		inv.Meta.Collected = kept
		inv.Meta.Denied = append(inv.Meta.Denied, denied+": forbidden")

		got := 0
		for _, r := range []Rule{NodeDrainBudget{}, NodePlacementConcentration{}, NodePinnedVolume{}} {
			got += len(r.Evaluate(inv, Options{IncludeSystem: true}))
		}
		switch denied {
		case "nodes", "pods":
			if got != 0 {
				t.Errorf("denied %q still produced %d findings — absence was read as observation", denied, got)
			}
		case "poddisruptionbudgets":
			// Only the budget rule depends on PDBs; the others may still speak.
			if n := len((NodeDrainBudget{}).Evaluate(inv, Options{IncludeSystem: true})); n != 0 {
				t.Errorf("denied poddisruptionbudgets still produced %d budget findings", n)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// fixture: one node holding a budget-blocked workload, a fully-concentrated workload, and a pod
// whose volume is pinned to it.
// ---------------------------------------------------------------------------------------------

func drainInventory() *collect.Inventory {
	return &collect.Inventory{
		Nodes: []corev1.Node{
			drainNode("node-a", "eu-central-1a"),
			drainNode("node-b", "eu-central-1b"),
		},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}},
		Deployments: []appsv1.Deployment{
			drainDeploy("shop", "checkout", 3),
			drainDeploy("shop", "search", 2),
		},
		StatefulSets: []appsv1.StatefulSet{drainSts("shop", "pg", 1)},
		Pods: []corev1.Pod{
			// checkout: 3 of 3 on node-a, covered by a zero-budget PDB
			drainPod("shop", "checkout-1", "node-a", "checkout", "Deployment", "checkout"),
			drainPod("shop", "checkout-2", "node-a", "checkout", "Deployment", "checkout"),
			drainPod("shop", "checkout-3", "node-a", "checkout", "Deployment", "checkout"),
			// search: 2 of 2 on node-a, no PDB — concentration only
			withUID(drainPod("shop", "search-1", "node-a", "search", "Deployment", "search"), "uid-search-1"),
			withUID(drainPod("shop", "search-2", "node-a", "search", "Deployment", "search"), "uid-search-2"),
			// pg-0 on node-a with a node-pinned PV
			withPVC(drainPod("shop", "pg-0", "node-a", "pg", "StatefulSet", "pg"), "data-pg-0"),
		},
		PDBs: []policyv1.PodDisruptionBudget{drainPDBZero("shop", "checkout-pdb", "checkout", 3)},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "search", Namespace: "shop"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "search"}},
		}},
		EndpointSlices: []discoveryv1.EndpointSlice{drainSlice("shop", "search", "IPv4",
			[]epEntry{{uid: "uid-search-1", ready: boolPtr(true)}, {uid: "uid-search-2", ready: nil}})},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Name: "data-pg-0", Namespace: "shop"},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-pg-0"},
		}},
		PVs: []corev1.PersistentVolume{pinnedPV("pv-pg-0", "node-a")},
		Meta: collect.Meta{
			Collected: []string{"nodes", "pods", "deployments", "statefulsets", "poddisruptionbudgets",
				"persistentvolumes", "persistentvolumeclaims", "endpointslices", "services"},
			ServerVersion: "v1.30.2",
		},
	}
}

func drainNode(name, zone string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
		"topology.kubernetes.io/zone":      zone,
		"kubernetes.io/hostname":           name,
		"node.kubernetes.io/instance-type": "m6i.large",
	}}}
}

func drainDeploy(ns, name string, replicas int32) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
		},
	}
}

func drainSts(ns, name string, replicas int32) appsv1.StatefulSet {
	return appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
		},
	}
}

func drainPod(ns, name, node, app, ownerKind, ownerName string) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Labels: map[string]string{"app": app},
			OwnerReferences: []metav1.OwnerReference{{
				Kind: ownerKind, Name: ownerName, Controller: boolPtr(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if ownerKind == "Deployment" {
		// Real clusters own Deployment pods through a ReplicaSet; ownerChain strips the
		// pod-template-hash. Mirror that shape so the fixture exercises the real path.
		p.OwnerReferences = []metav1.OwnerReference{{
			Kind: "ReplicaSet", Name: ownerName + "-7d9f8b6c5d", Controller: boolPtr(true),
		}}
	}
	return p
}

func withPVC(p corev1.Pod, claim string) corev1.Pod {
	p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
		},
	})
	return p
}

// drainPDBZero builds a PDB whose STATUS reports a zero budget, matching what the controller
// publishes for maxUnavailable=0. Status is what the rule reads — the spec alone cannot tell you
// what the eviction API will do.
func drainPDBZero(ns, name, app string, expected int32) policyv1.PodDisruptionBudget {
	zero := intstr.FromInt32(0)
	return policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &zero,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1,
			DisruptionsAllowed: 0,
			CurrentHealthy:     expected,
			DesiredHealthy:     expected,
			ExpectedPods:       expected,
		},
	}
}

func pinnedPV(name, node string) corev1.PersistentVolume {
	return corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:    corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      "kubernetes.io/hostname",
						Operator: corev1.NodeSelectorOpIn,
						Values:   []string{node},
					}},
				}}},
			},
		},
	}
}

func boolPtr(b bool) *bool { return &b }

func withUID(p corev1.Pod, uid string) corev1.Pod { p.UID = types2.UID(uid); return p }

// ---------------------------------------------------------------------------------------------
// behaviour
// ---------------------------------------------------------------------------------------------

// TestNodeDrainBudget_ReportsTheRejectionArithmetic — the strongest claim the snapshot supports:
// this many evictions, this budget, therefore rejected.
func TestNodeDrainBudget_ReportsTheRejectionArithmetic(t *testing.T) {
	findings := (NodeDrainBudget{}).Evaluate(drainInventory(), Options{IncludeSystem: true})
	var f *types.Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "node-a") {
			f = &findings[i]
		}
	}
	if f == nil {
		t.Fatalf("no budget finding for node-a; got %d findings", len(findings))
	}
	blob := strings.Join(f.Evidence, " ")
	for _, want := range []string{"disruptionsAllowed=0", "maxUnavailable", "3"} {
		if !strings.Contains(blob, want) {
			t.Errorf("evidence omits %q:\n%s", want, blob)
		}
	}
	if f.Confidence != 1 {
		t.Errorf("Confidence = %v, want 1 — this is arithmetic over published status", f.Confidence)
	}
	// The already-shipped PDBBlocksDrains rule owns the PDB remediation; offering it twice would
	// put the same fix on one page from two cards.
	if f.RemediationCommand != "" || f.RemediationYAML != "" {
		t.Error("budget finding carries a remediation — that belongs to PDBBlocksDrains alone")
	}
	// node-b holds nothing, so it must not appear at all.
	for _, g := range findings {
		if strings.Contains(g.Title, "node-b") {
			t.Errorf("node-b has no matching pods yet produced %q", g.Title)
		}
	}
}

// TestNodePlacementConcentration_IsPlacementArithmeticOnly — fires for search (2 of 2 on one node)
// and must NOT fire for the single-replica pg, which SingleReplicaNoPDB already owns.
func TestNodePlacementConcentration_IsPlacementArithmeticOnly(t *testing.T) {
	findings := (NodePlacementConcentration{}).Evaluate(drainInventory(), Options{IncludeSystem: true})

	byWorkload := map[string]types.Finding{}
	for _, f := range findings {
		for _, r := range f.AffectedResources {
			if r.Kind == "Deployment" || r.Kind == "StatefulSet" {
				byWorkload[r.Name] = f
			}
		}
	}
	if _, ok := byWorkload["search"]; !ok {
		t.Error("search has 2 of 2 pods on node-a and was not reported")
	}
	if _, ok := byWorkload["pg"]; ok {
		t.Error("pg has one replica — that is SingleReplicaNoPDB's finding, not a concentration one")
	}
	f := byWorkload["search"]
	if !strings.Contains(strings.Join(f.Evidence, " "), "2 of 2") {
		t.Errorf("evidence should state the placement arithmetic verbatim:\n%s", strings.Join(f.Evidence, " "))
	}
	// The EndpointSlice blind spot must be disclosed, because without it we cannot know which of
	// those pods were serving.
	// The old disclaimer ("rotation membership is unknown") is now a real count, so the guard is
	// that the mandatory not-traffic caveat travels with it.
	if !strings.Contains(strings.Join(f.Evidence, " "), "not an observation that any request reached") {
		t.Errorf("endpoint evidence is missing the mandatory not-traffic caveat:\n%s",
			strings.Join(f.Evidence, " "))
	}
}

// TestNodePinnedVolume_OnlyWhenThePVItselfPins — the claim is about a hard scheduling constraint
// written on the PV, not an inference from the pod's placement.
func TestNodePinnedVolume_OnlyWhenThePVItselfPins(t *testing.T) {
	findings := (NodePinnedVolume{}).Evaluate(drainInventory(), Options{IncludeSystem: true})
	if len(findings) != 1 {
		t.Fatalf("want exactly one pinned-volume finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Confidence != 1 {
		t.Errorf("Confidence = %v, want 1 — the pin is read verbatim from the PV", f.Confidence)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "pv-pg-0") {
		t.Error("evidence does not name the PV that carries the pin")
	}

	// An unpinned PV must produce nothing at all rather than a hedged guess.
	inv := drainInventory()
	inv.PVs = []corev1.PersistentVolume{{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-pg-0"},
		Spec:       corev1.PersistentVolumeSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}},
	}}
	if n := len((NodePinnedVolume{}).Evaluate(inv, Options{IncludeSystem: true})); n != 0 {
		t.Errorf("an unpinned PV produced %d findings", n)
	}
}

// TestDrainPlacement_ExcludesPodsThatAreNotLive — this is the first code in the tree to read
// Status.Phase and DeletionTimestamp, and getting the predicate wrong silently corrupts every count
// in every one of these findings.
func TestDrainPlacement_ExcludesPodsThatAreNotLive(t *testing.T) {
	inv := drainInventory()
	// Add a Succeeded pod and a Terminating pod for search on node-a. Neither is live capacity, so
	// search must still read as 2 of 2 rather than 4 of 4.
	done := drainPod("shop", "search-old", "node-a", "search", "Deployment", "search")
	done.Status.Phase = corev1.PodSucceeded
	term := drainPod("shop", "search-going", "node-a", "search", "Deployment", "search")
	now := metav1.Now()
	term.DeletionTimestamp = &now
	inv.Pods = append(inv.Pods, done, term)

	for _, f := range (NodePlacementConcentration{}).Evaluate(inv, Options{IncludeSystem: true}) {
		blob := strings.Join(f.Evidence, " ")
		if strings.Contains(blob, "4 of") || strings.Contains(blob, "of 4") {
			t.Errorf("terminating/completed pods were counted as live capacity:\n%s", blob)
		}
	}
}

// TestNodeDrainBudget_CoversOperatorManagedPods is a real-cluster regression.
//
// On the AKS dev cluster an independent recount found five reportable (node, PDB) pairs — four
// PostgreSQL primaries with disruptionsAllowed=0 and one Kafka broker set that serializes into two
// rounds — and this rule emitted nothing. The cause was a design error, not a slip: Rule A looked for
// covered pods inside the placement index's byOwner map, which only holds pods owned by a Deployment
// or StatefulSet. CloudNativePG pods are owned by a Cluster CR and Strimzi's by a StrimziPodSet, so
// the workloads most likely to block a drain — operator-managed databases — were silently discarded.
//
// The conceptual fix is that eviction does not care who owns a pod. A budget covers pods; ownership
// only matters for the redundancy arithmetic in Rule B. Coupling the two through one structure bought
// convenience and a false negative on the case that matters most.
func TestNodeDrainBudget_CoversOperatorManagedPods(t *testing.T) {
	inv := drainInventory()

	// A CloudNativePG-shaped pod: owned by a Cluster CR, covered by a zero-budget PDB.
	pg := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pgsql-main-1", Namespace: "data",
			Labels: map[string]string{"cnpg.io/cluster": "pgsql-main"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "postgresql.cnpg.io/v1", Kind: "Cluster",
				Name: "pgsql-main", Controller: boolPtr(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	inv.Pods = append(inv.Pods, pg)
	inv.Namespaces = append(inv.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "data"}})

	zero := intstr.FromInt32(0)
	inv.PDBs = append(inv.PDBs, policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "pgsql-main-primary", Namespace: "data", Generation: 1},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &zero,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"cnpg.io/cluster": "pgsql-main"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1, DisruptionsAllowed: 0,
			CurrentHealthy: 1, DesiredHealthy: 1, ExpectedPods: 1,
		},
	})

	var found *types.Finding
	for _, f := range (NodeDrainBudget{}).Evaluate(inv, Options{IncludeSystem: true}) {
		for _, r := range f.AffectedResources {
			if r.Kind == "PodDisruptionBudget" && r.Name == "pgsql-main-primary" {
				g := f
				found = &g
			}
		}
	}
	if found == nil {
		t.Fatal("a zero-budget PDB covering an operator-managed pod produced no finding — " +
			"eviction arithmetic must not depend on who owns the pod")
	}
	if !strings.Contains(strings.Join(found.Evidence, " "), "data/pgsql-main-1") {
		t.Errorf("the covered pod is not named in the evidence:\n%s", strings.Join(found.Evidence, " "))
	}
}

// TestNodeDrainBudget_CountsDaemonSetPodsItCovers — a DaemonSet pod is not redundancy, but it is
// still a pod the eviction API has to permit, so a budget covering one must be reported.
func TestNodeDrainBudget_CountsDaemonSetPodsItCovers(t *testing.T) {
	inv := drainInventory()
	ds := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "agent-xyz", Namespace: "shop",
			Labels: map[string]string{"app": "agent"},
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "DaemonSet", Name: "agent", Controller: boolPtr(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	inv.Pods = append(inv.Pods, ds)
	zero := intstr.FromInt32(0)
	inv.PDBs = append(inv.PDBs, policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "agent-pdb", Namespace: "shop", Generation: 1},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &zero,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1, DisruptionsAllowed: 0,
			CurrentHealthy: 1, DesiredHealthy: 1, ExpectedPods: 1,
		},
	})

	hit := false
	for _, f := range (NodeDrainBudget{}).Evaluate(inv, Options{IncludeSystem: true}) {
		for _, r := range f.AffectedResources {
			if r.Name == "agent-pdb" {
				hit = true
			}
		}
	}
	if !hit {
		t.Error("a budget covering a DaemonSet pod was ignored — that pod still has to be evicted")
	}
}

// epEntry is a compact endpoint fixture: the pod UID it points at and its readiness condition,
// where a nil ready deliberately means UNSET rather than false.
type epEntry struct {
	uid   string
	ready *bool
}

func drainSlice(ns, svc, family string, entries []epEntry) discoveryv1.EndpointSlice {
	s := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: svc + "-xyz", Namespace: ns,
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
		AddressType: discoveryv1.AddressType(family),
	}
	for _, e := range entries {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{
			Conditions: discoveryv1.EndpointConditions{Ready: e.ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: ns, UID: types2.UID(e.uid)},
		})
	}
	return s
}

// TestEndpointReady_NilIsNotReady pins a deliberate divergence from internal/prom/portforward.go.
//
// That code treats conditions.ready == nil as READY, which is right when it just needs some pod to
// port-forward to. The API defines an unset value as UNKNOWN, so as the basis of a figure the product
// prints, merging unset into ready would overstate readiness — the exact shape of the four
// safety-classification bugs this project already fixed. Both behaviours are correct for their own
// caller and must stay apart; this test exists so nobody "harmonises" them.
func TestEndpointReady_NilIsNotReady(t *testing.T) {
	inv := drainInventory()
	pods := []corev1.Pod{
		withUID(drainPod("shop", "a", "node-a", "x", "Deployment", "x"), "u1"),
		withUID(drainPod("shop", "b", "node-a", "x", "Deployment", "x"), "u2"),
	}
	inv.EndpointSlices = []discoveryv1.EndpointSlice{
		drainSlice("shop", "x", "IPv4", []epEntry{{uid: "u1", ready: boolPtr(true)}, {uid: "u2", ready: nil}}),
	}
	blob := strings.Join(endpointEvidence(inv, pods), " ")
	if !strings.Contains(blob, "1 recorded conditions.ready=true") {
		t.Errorf("ready count wrong:\n%s", blob)
	}
	if !strings.Contains(blob, "1 left ready unset") {
		t.Errorf("unset entry was not counted apart:\n%s", blob)
	}
}

// TestEndpointCount_DedupsDualStack — a dual-stack Service publishes an IPv4 and an IPv6 slice for
// the SAME backends. Counting both would double every figure the product prints.
func TestEndpointCount_DedupsDualStack(t *testing.T) {
	inv := drainInventory()
	pods := []corev1.Pod{
		withUID(drainPod("shop", "a", "node-a", "x", "Deployment", "x"), "u1"),
		withUID(drainPod("shop", "b", "node-a", "x", "Deployment", "x"), "u2"),
		withUID(drainPod("shop", "c", "node-a", "x", "Deployment", "x"), "u3"),
	}
	entries := []epEntry{{uid: "u1", ready: boolPtr(true)}, {uid: "u2", ready: boolPtr(true)}, {uid: "u3", ready: boolPtr(true)}}
	inv.EndpointSlices = []discoveryv1.EndpointSlice{
		drainSlice("shop", "x", "IPv4", entries),
		drainSlice("shop", "x", "IPv6", entries),
	}
	blob := strings.Join(endpointEvidence(inv, pods), " ")
	if !strings.Contains(blob, "3 of these 3 pods") {
		t.Errorf("dual-stack slices were double-counted:\n%s", blob)
	}
	if !strings.Contains(blob, "addressType IPv4 only") {
		t.Errorf("the counted address family is not named:\n%s", blob)
	}
}

// TestEndpointCount_SuppressedOnPublishNotReadyAddresses — for such a Service an entry's readiness
// says nothing, so the figures are omitted rather than footnoted.
func TestEndpointCount_SuppressedOnPublishNotReadyAddresses(t *testing.T) {
	inv := drainInventory()
	inv.Services = append(inv.Services, corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "hs", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{PublishNotReadyAddresses: true},
	})
	pods := []corev1.Pod{withUID(drainPod("shop", "a", "node-a", "x", "Deployment", "x"), "u1")}
	inv.EndpointSlices = []discoveryv1.EndpointSlice{
		drainSlice("shop", "hs", "IPv4", []epEntry{{uid: "u1", ready: boolPtr(true)}}),
	}
	blob := strings.Join(endpointEvidence(inv, pods), " ")
	if strings.Contains(blob, "conditions.ready=true") {
		t.Errorf("readiness figures survived publishNotReadyAddresses:\n%s", blob)
	}
	if !strings.Contains(blob, "publishNotReadyAddresses") {
		t.Errorf("the reason for omitting them is not stated:\n%s", blob)
	}
}

// TestEndpointGate_RequiresPositiveCollected — asserting membership is only honest if the slices were
// actually read, so this must rest on observed(), which refuses an inventory that never said what it read; the
// empty-Meta escape hatch that used to sit in this guard would have licensed
// the assertion on a fixture that read nothing.
func TestEndpointGate_RequiresPositiveCollected(t *testing.T) {
	inv := drainInventory()
	inv.Meta.Collected = []string{"nodes", "pods"} // everything except endpointslices
	pods := []corev1.Pod{withUID(drainPod("shop", "a", "node-a", "x", "Deployment", "x"), "u1")}
	inv.EndpointSlices = []discoveryv1.EndpointSlice{
		drainSlice("shop", "x", "IPv4", []epEntry{{uid: "u1", ready: boolPtr(true)}}),
	}
	blob := strings.Join(endpointEvidence(inv, pods), " ")
	if !strings.Contains(blob, "were not read in this audit") {
		t.Errorf("counted endpoints without having collected them:\n%s", blob)
	}
}

// --- claim 3: the placement universal ---------------------------------------------------------
//
// "Every endpoint entry published for this Service that this audit could place on a node records
// THIS node." A universal is falsified by a single exception, so it is emitted only when every
// deduped entry resolved — otherwise the split is stated and no universal is made. Suppress rather
// than hedge.

func epPlacementInv(t *testing.T) *collect.Inventory {
	t.Helper()
	inv := drainInventory()
	inv.Services = append(inv.Services, corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.9", Selector: map[string]string{"app": "api"}},
	})
	return inv
}

func TestEndpointPlacement_UniversalOnlyWhenEveryEntryIsOnThisNode(t *testing.T) {
	inv := epPlacementInv(t)
	pods := []corev1.Pod{
		withUID(drainPod("shop", "api-1", "node-a", "api", "Deployment", "api"), "u1"),
		withUID(drainPod("shop", "api-2", "node-a", "api", "Deployment", "api"), "u2"),
	}
	inv.Pods = append(inv.Pods, pods...)
	inv.EndpointSlices = append(inv.EndpointSlices, drainSlice("shop", "api", "IPv4",
		[]epEntry{{uid: "u1", ready: boolPtr(true)}, {uid: "u2", ready: boolPtr(true)}}))

	blob := strings.Join(endpointPlacementEvidence(inv, pods, "node-a"), " ")
	if !strings.Contains(blob, "Every endpoint entry") {
		t.Errorf("the universal was not emitted although every entry is on this node:\n%s", blob)
	}
}

func TestEndpointPlacement_NoUniversalWhenAnEntryIsElsewhere(t *testing.T) {
	inv := epPlacementInv(t)
	here := withUID(drainPod("shop", "api-1", "node-a", "api", "Deployment", "api"), "u1")
	there := withUID(drainPod("shop", "api-2", "node-b", "api", "Deployment", "api"), "u2")
	inv.Pods = append(inv.Pods, here, there)
	inv.EndpointSlices = append(inv.EndpointSlices, drainSlice("shop", "api", "IPv4",
		[]epEntry{{uid: "u1", ready: boolPtr(true)}, {uid: "u2", ready: boolPtr(true)}}))

	blob := strings.Join(endpointPlacementEvidence(inv, []corev1.Pod{here}, "node-a"), " ")
	if strings.Contains(blob, "Every endpoint entry") {
		t.Errorf("a universal was claimed although one entry is on another node:\n%s", blob)
	}
	if !strings.Contains(blob, "1 of the 2") {
		t.Errorf("the split was not stated:\n%s", blob)
	}
}

func TestEndpointPlacement_SuppressedWhenAnyEntryIsUnplaceable(t *testing.T) {
	inv := epPlacementInv(t)
	here := withUID(drainPod("shop", "api-1", "node-a", "api", "Deployment", "api"), "u1")
	inv.Pods = append(inv.Pods, here)
	// The second entry points at a pod this audit never saw — unplaceable, so no universal.
	inv.EndpointSlices = append(inv.EndpointSlices, drainSlice("shop", "api", "IPv4",
		[]epEntry{{uid: "u1", ready: boolPtr(true)}, {uid: "ghost", ready: boolPtr(true)}}))

	blob := strings.Join(endpointPlacementEvidence(inv, []corev1.Pod{here}, "node-a"), " ")
	if strings.Contains(blob, "Every endpoint entry") {
		t.Errorf("a universal was claimed with an unplaceable entry present:\n%s", blob)
	}
	if !strings.Contains(blob, "could not be placed") {
		t.Errorf("the unplaceable entry was not disclosed:\n%s", blob)
	}
}

// TestEndpointPlacement_SkipsHeadlessServices — a headless Service has no proxy in front of it, so
// "published for" invites a routing reading the data cannot support.
func TestEndpointPlacement_SkipsHeadlessServices(t *testing.T) {
	inv := drainInventory()
	inv.Services = append(inv.Services, corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "hl", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone},
	})
	p := withUID(drainPod("shop", "hl-0", "node-a", "hl", "StatefulSet", "hl"), "u1")
	inv.Pods = append(inv.Pods, p)
	inv.EndpointSlices = append(inv.EndpointSlices, drainSlice("shop", "hl", "IPv4",
		[]epEntry{{uid: "u1", ready: boolPtr(true)}}))

	if got := endpointPlacementEvidence(inv, []corev1.Pod{p}, "node-a"); len(got) != 0 {
		t.Errorf("a headless Service produced placement evidence: %v", got)
	}
}

// ONE POD IS ONE POD. The landing's hero quoted this rule word for word, and it read "requires evicting 1 pod(s)"
// and "would reject each of those 1 evictions" — the engine's grammar printed on the first screen a stranger sees.
func TestNodeDrainBudget_CountsInWords(t *testing.T) {
	inv := drainInventory()
	inv.Pods = inv.Pods[2:] // checkout-3 alone is covered on node-a
	inv.PDBs = []policyv1.PodDisruptionBudget{drainPDBZero("shop", "checkout-pdb", "checkout", 1)}
	var f *types.Finding
	for _, g := range (NodeDrainBudget{}).Evaluate(inv, Options{IncludeSystem: true}) {
		if strings.Contains(g.Title, "node-a") {
			g := g
			f = &g
		}
	}
	if f == nil {
		t.Fatal("no budget finding for node-a with one covered pod")
	}
	text := f.Description + " " + strings.Join(f.Evidence, " ")
	for _, bad := range []string{"(s)", "each of those 1 ", "1 pods", "1 evictions"} {
		if strings.Contains(text, bad) {
			t.Errorf("the finding says %q:\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "1 pod covered") || !strings.Contains(text, "that eviction") {
		t.Errorf("one covered pod is not said as one:\n%s", text)
	}
}

// KUBECTL DRAIN STOPS ON A POD NO CONTROLLER MANAGES. Its own pre-check refuses to evict such a pod unless it is
// given --force, and with --force the pod is deleted and nothing recreates it. The drain model answered "nothing
// this model checks stops the drain" for a node carrying one — the sample's ip-10-0-1-a, with a debug shell left
// on it — while the command it models would have stopped there.
func TestNodeDrainUnmanaged_TheDrainStopsOnAPodNoControllerManages(t *testing.T) {
	inv := drainInventory()
	bare := drainPod("shop", "debug-shell", "node-b", "debug", "", "")
	bare.OwnerReferences = nil
	mirror := drainPod("kube-system", "etcd-node-b", "node-b", "etcd", "", "")
	mirror.OwnerReferences = nil
	mirror.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "x"}
	done := drainPod("shop", "migrate-once", "node-b", "migrate", "", "")
	done.OwnerReferences = nil
	done.Status.Phase = corev1.PodSucceeded
	inv.Pods = append(inv.Pods, bare, mirror, done)

	findings := (NodeDrainUnmanaged{}).Evaluate(inv, Options{})
	if len(findings) != 1 {
		t.Fatalf("%d findings; one node carries one pod no controller manages", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Title, "node-b") || !strings.Contains(f.Title, "1 pod") {
		t.Errorf("title %q does not name the node and the count", f.Title)
	}
	blob := strings.Join(f.Evidence, " ") + " " + f.Description
	for _, want := range []string{"shop/debug-shell", "--force", "nothing recreates"} {
		if !strings.Contains(blob, want) {
			t.Errorf("the finding omits %q:\n%s", want, blob)
		}
	}
	for _, never := range []string{"etcd-node-b", "migrate-once"} {
		if strings.Contains(blob, never) {
			t.Errorf("the finding names %s — a static pod and a finished pod are not what stops a drain", never)
		}
	}
	nodeRef := false
	for _, r := range f.AffectedResources {
		if r.Kind == "Node" && r.Name == "node-b" {
			nodeRef = true
		}
	}
	if !nodeRef {
		t.Error("the finding does not name its node, so preflight cannot attribute it to the drain asked about")
	}
}
