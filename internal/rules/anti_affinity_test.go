package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// nodesCollected returns Meta with "nodes" marked collected so the rule trusts
// the (possibly empty) inv.Nodes list as observed rather than denied.
func nodesCollected() collect.Meta {
	return collect.Meta{Collected: []string{"nodes"}}
}

// twoNodesTwoZones builds a node list the rule reads as "2 schedulable nodes
// across 2 zones" — enough to keep Severity at Medium.
func twoNodesTwoZones() []corev1.Node {
	return []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{
			"kubernetes.io/hostname":      "n1",
			"topology.kubernetes.io/zone": "z-a",
		}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n2", Labels: map[string]string{
			"kubernetes.io/hostname":      "n2",
			"topology.kubernetes.io/zone": "z-b",
		}}},
	}
}

// twoNodesOneZone builds a node list the rule reads as single-AZ -> Low.
func twoNodesOneZone() []corev1.Node {
	return []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{
			"kubernetes.io/hostname":      "n1",
			"topology.kubernetes.io/zone": "z-a",
		}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n2", Labels: map[string]string{
			"kubernetes.io/hostname":      "n2",
			"topology.kubernetes.io/zone": "z-a",
		}}},
	}
}

func withPodAntiAffinityTerm(d *appsv1.Deployment) {
	d.Spec.Template.Spec.Affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
			TopologyKey:   "kubernetes.io/hostname",
			LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "spread"}},
		}},
	}}
}

func withEmptyPodAntiAffinity(d *appsv1.Deployment) {
	// Empty struct, no required and no preferred terms — carries no spread intent.
	d.Spec.Template.Spec.Affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{}}
}

func withTopologySpread(d *appsv1.Deployment) {
	d.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
		MaxSkew:           1,
		TopologyKey:       "kubernetes.io/hostname",
		WhenUnsatisfiable: corev1.ScheduleAnyway,
	}}
}

func TestNoAntiAffinity_Flagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 3, nil)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.RuleID != "k8s.workload.no-anti-affinity" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	joined := strings.Join(f.Evidence, " ")
	if !strings.Contains(joined, "Deployment app/packed") ||
		!strings.Contains(joined, "3 replicas") ||
		!strings.Contains(joined, "no podAntiAffinity/topologySpreadConstraints") {
		t.Errorf("evidence must state replicas and the missing spread config: %v", f.Evidence)
	}
	for _, want := range []string{
		"topologySpreadConstraints",
		"maxSkew: 1",
		"topologyKey: kubernetes.io/hostname",
		"whenUnsatisfiable: ScheduleAnyway",
		"app: packed", // labelSelector interpolated from PodLabels
		"name: packed",
		"namespace: app",
		"Validate against your workload before applying", // safe-remediation caveat
	} {
		if !strings.Contains(f.RemediationYAML, want) {
			t.Errorf("remediation YAML missing %q:\n%s", want, f.RemediationYAML)
		}
	}
	if f.Severity != types.SeverityMedium {
		t.Errorf("2 nodes / 2 zones must stay Medium, got %v", f.Severity)
	}
	if f.Confidence != 0.6 {
		t.Errorf("confidence = %v, want 0.6", f.Confidence)
	}
	if !strings.Contains(f.Description, "2 schedulable nodes across 2 zones") {
		t.Errorf("description must report observed topology: %q", f.Description)
	}
}

func TestNoAntiAffinity_SingleNodeClusterSuppressed(t *testing.T) {
	// One schedulable node: spreading is impossible and buys zero availability.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 3, nil)},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "only", Labels: map[string]string{
				"kubernetes.io/hostname": "only",
			}}},
		},
		Meta: nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("single-node cluster cannot spread — must suppress, got %+v", fs)
	}
}

func TestNoAntiAffinity_CordonedNodesNotCounted(t *testing.T) {
	// Two nodes but one is cordoned (unschedulable) -> only one placement target.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 3, nil)},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"kubernetes.io/hostname": "n1"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "n2", Labels: map[string]string{"kubernetes.io/hostname": "n2"}},
				Spec: corev1.NodeSpec{Unschedulable: true}},
		},
		Meta: nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("one schedulable node (other cordoned) -> suppress, got %+v", fs)
	}
}

func TestNoAntiAffinity_NodesNotCollectedStillFlagsWithCaveat(t *testing.T) {
	// Denial guard: nodes never collected -> do NOT read empty list as
	// single-node; keep the finding but caveat feasibility as unverified.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 3, nil)},
		Meta:        collect.Meta{Denied: []string{"nodes: forbidden"}},
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("nodes denied must not suppress the finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Description, "Node topology was not collected") {
		t.Errorf("must caveat unverified feasibility when nodes not collected: %q", fs[0].Description)
	}
	if fs[0].Severity != types.SeverityMedium {
		t.Errorf("unknown topology keeps Medium, got %v", fs[0].Severity)
	}
}

func TestNoAntiAffinity_SingleZoneLowSeverity(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 2, nil)},
		Nodes:       twoNodesOneZone(),
		Meta:        nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityLow {
		t.Errorf("single-AZ must lower severity to Low, got %v", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Description, "single availability zone") {
		t.Errorf("must note single-AZ limit: %q", fs[0].Description)
	}
}

func TestNoAntiAffinity_ReplicasExceedNodesNoted(t *testing.T) {
	// 3 replicas but only 2 nodes across 2 zones: spread bounded by node count.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "packed", 3, nil)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Description, "bounded by node count") {
		t.Errorf("must note spread is bounded when replicas > nodes: %q", fs[0].Description)
	}
}

func TestNoAntiAffinity_SingleReplicaNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "solo", 1, nil)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("replicas=1 must not flag (spreading one pod is meaningless): %+v", fs)
	}
}

func TestNoAntiAffinity_PodAntiAffinityTermNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "spread", 3, withPodAntiAffinityTerm)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("podAntiAffinity with a real term present, must not flag: %+v", fs)
	}
}

func TestNoAntiAffinity_EmptyPodAntiAffinityStillFlagged(t *testing.T) {
	// Empty &PodAntiAffinity{} carries no spread intent -> treated as absent.
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "cosmetic", 3, withEmptyPodAntiAffinity)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 1 {
		t.Fatalf("empty podAntiAffinity struct must still flag (no real spread intent), got %d", len(fs))
	}
}

func TestNoAntiAffinity_TopologySpreadNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "spread", 3, withTopologySpread)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("topologySpreadConstraints present, must not flag: %+v", fs)
	}
}

func TestNoAntiAffinity_NodeAffinityOnlyStillFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "pinned", 2, func(d *appsv1.Deployment) {
				d.Spec.Template.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{}}
			}),
		},
		Nodes: twoNodesTwoZones(),
		Meta:  nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 1 {
		t.Fatalf("nodeAffinity alone does not spread replicas — want 1 finding, got %d", len(fs))
	}
}

func TestNoAntiAffinity_PDBBoundsDrainWording(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "covered", 3, nil)},
		Nodes:       twoNodesTwoZones(),
		PDBs: []policyv1.PodDisruptionBudget{{
			ObjectMeta: metav1.ObjectMeta{Name: "covered-pdb", Namespace: "app"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "covered"}},
			},
		}},
		Meta: nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	d := fs[0].Description
	if !strings.Contains(d, "PodDisruptionBudget already bounds") {
		t.Errorf("a covering PDB must reframe drain blast radius: %q", d)
	}
	if !strings.Contains(d, "involuntary") {
		t.Errorf("with a PDB the finding must center involuntary node failure: %q", d)
	}
}

func TestNoAntiAffinity_NoPDBKeepsDrainWording(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "uncovered", 3, nil)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Description, "one node failure or drain could take several down together") {
		t.Errorf("without a PDB the original drain wording stands: %q", fs[0].Description)
	}
}

func TestNoAntiAffinity_StatefulSetFlagged(t *testing.T) {
	replicas := int32(2)
	inv := &collect.Inventory{
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "app"},
			Spec: appsv1.StatefulSetSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "redis"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
				},
			},
		}},
		Nodes: twoNodesTwoZones(),
		Meta:  nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for StatefulSet, got %d", len(fs))
	}
	if fs[0].AffectedResources[0].Kind != "StatefulSet" {
		t.Errorf("affected kind = %q, want StatefulSet", fs[0].AffectedResources[0].Kind)
	}
	if !strings.Contains(fs[0].WhyItMatters, "does not replace adequate replica count") {
		t.Errorf("StatefulSet finding must carry the quorum/HA caveat: %q", fs[0].WhyItMatters)
	}
}

func TestNoAntiAffinity_DeploymentNoStatefulCaveat(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "web", 3, nil)},
		Nodes:       twoNodesTwoZones(),
		Meta:        nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if strings.Contains(fs[0].WhyItMatters, "quorum") {
		t.Errorf("stateless Deployment must not carry the StatefulSet quorum caveat: %q", fs[0].WhyItMatters)
	}
}

func TestNoAntiAffinity_DaemonSetNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		DaemonSets: []appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "app"},
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "agent"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img"}}},
				},
			},
		}},
		Nodes: twoNodesTwoZones(),
		Meta:  nodesCollected(),
	}
	if fs := (NoAntiAffinity{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("DaemonSets are node-bound by design, must not flag: %+v", fs)
	}
}

func TestNoAntiAffinity_SystemNamespaceSkipped(t *testing.T) {
	mk := func() *collect.Inventory {
		return &collect.Inventory{
			Deployments: []appsv1.Deployment{deploy("kube-system", "coredns", 2, nil)},
			Nodes:       twoNodesTwoZones(),
			Meta:        nodesCollected(),
		}
	}
	if fs := (NoAntiAffinity{}).Evaluate(mk(), Options{}); len(fs) != 0 {
		t.Fatalf("system namespace must be skipped by default: %+v", fs)
	}
	if fs := (NoAntiAffinity{}).Evaluate(mk(), Options{IncludeSystem: true}); len(fs) != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", len(fs))
	}
}

func TestNoAntiAffinity_DistinctIDs(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "one", 2, nil),
			deploy("app", "two", 2, nil),
		},
		Nodes: twoNodesTwoZones(),
		Meta:  nodesCollected(),
	}
	fs := NoAntiAffinity{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	if fs[0].ID == fs[1].ID || !strings.HasPrefix(fs[0].ID, "f-") {
		t.Fatalf("finding IDs must be distinct f-prefixed hashes: %q vs %q", fs[0].ID, fs[1].ID)
	}
}
