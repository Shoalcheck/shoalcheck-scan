package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// poolNode builds a node with an instance-type label, region label, and
// allocatable CPU/mem so the headroom math has real numbers to work with.
func poolNode(name, region, itype, cpu, mem string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"topology.kubernetes.io/region":    region,
				"node.kubernetes.io/instance-type": itype,
			},
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
			},
		},
	}
}

// requestPod is a scheduled pod (NodeName set) requesting cpu/mem on one container.
func requestPod(ns, name, nodeName, cpu, mem string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{{
				Name: "main",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse(cpu),
						corev1.ResourceMemory: resource.MustParse(mem),
					},
				},
			}},
		},
	}
}

// daemonPod is a DaemonSet-owned scheduled pod — its requests must be EXCLUDED
// from the consolidation math because the footprint scales 1:1 with node count.
func daemonPod(ns, name, nodeName, cpu, mem string) corev1.Pod {
	p := requestPod(ns, name, nodeName, cpu, mem)
	p.OwnerReferences = []metav1.OwnerReference{{Kind: "DaemonSet", Name: "agent"}}
	return p
}

// invWithPods builds an inventory and marks pods+nodes as actually collected, so
// the rule's denial guard (skip when "pods" weren't collected) is satisfied.
func invWithPods(nodes []corev1.Node, pods []corev1.Pod) *collect.Inventory {
	inv := &collect.Inventory{Nodes: nodes, Pods: pods}
	inv.Meta.Collected = []string{"nodes", "pods"}
	return inv
}

// TestNodeHeadroom_RequestSlackIsNotBankable is the core honesty contract (after
// the founder caught a memory-bound false positive): a pool with large
// request-slack surfaces as a VERIFY-FIRST candidate — $0, low confidence, with
// an OOM warning — NEVER a confident saving. Requests-only cannot tell a
// genuinely-idle pool from one whose pods simply under-request vs real usage, so
// it must not bill either (acting on the latter OOMs the cluster).
func TestNodeHeadroom_RequestSlackIsNotBankable(t *testing.T) {
	// 4x m6i.large, requests fill a sliver → ~3 nodes of request-slack.
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n3", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n4", "eu-central-1", "m6i.large", "1800m", "7Gi"),
	}
	pods := []corev1.Pod{
		requestPod("app", "a", "n1", "600m", "2Gi"),
		requestPod("app", "b", "n2", "600m", "2Gi"),
	}
	inv := invWithPods(nodes, pods)

	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (one pool), got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.cost.node-headroom" || f.Category != "cost" {
		t.Errorf("ruleID/category = %q/%q", f.RuleID, f.Category)
	}
	// NOT bankable: dollar must be 0 so it can never top the savings headline
	// with a number that would OOM if acted on.
	if f.DollarImpactMonthly != 0 {
		t.Errorf("requests-only headroom must NOT be billed; want $0, got %v", f.DollarImpactMonthly)
	}
	// Verify-first posture: low severity + low confidence.
	if f.Severity != "low" {
		t.Errorf("severity = %q, want low", f.Severity)
	}
	if f.Confidence > 0.5 {
		t.Errorf("confidence = %v, want low (<=0.5)", f.Confidence)
	}
	ev := strings.Join(f.Evidence, " ")
	// 4-node pool with ~3 nodes of raw slack, but the HA floor caps the
	// suggestion at nodeCount-2 = 2 (never drain below 2 nodes).
	if !strings.Contains(ev, "m6i.large") || !strings.Contains(ev, "2 node") {
		t.Errorf("evidence must cite pool + HA-floored slack count: %v", f.Evidence)
	}
	low := strings.ToLower(ev)
	// Aggregate-ceiling caveat: must name the schedulability constraints it does
	// not model.
	if !strings.Contains(low, "aggregate") || !strings.Contains(low, "poddisruptionbudget") {
		t.Errorf("evidence must caveat the aggregate ceiling + unmodeled constraints: %v", f.Evidence)
	}
	// Provider-neutral HA floor caveat on every pool.
	if !strings.Contains(low, "ha floor") || !strings.Contains(low, "dns") {
		t.Errorf("every pool must carry the provider-neutral HA-floor caveat: %v", f.Evidence)
	}
	low = strings.ToLower(ev + " " + f.Title + " " + f.Description + " " + f.WhyItMatters)
	if !strings.Contains(low, "request") || !strings.Contains(low, "prometheus") {
		t.Errorf("finding must be labeled requests-based + point at Prometheus: %q", f.Description)
	}
	if !strings.Contains(low, "oom") {
		t.Errorf("finding must warn consolidating request-slack risks OOM: %v", f.Evidence)
	}
	if !strings.Contains(ev, "UNVERIFIED") {
		t.Errorf("the would-be dollar must be shown as UNVERIFIED, not billed: %v", f.Evidence)
	}
	if !strings.Contains(strings.ToLower(f.Title), "verify") {
		t.Errorf("title must signal verify-first, got %q", f.Title)
	}
}

func TestNodeHeadroom_TightPoolNoFinding(t *testing.T) {
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
	}
	pods := []corev1.Pod{
		requestPod("app", "a", "n1", "1700m", "6Gi"),
		requestPod("app", "b", "n2", "1700m", "6Gi"),
	}
	inv := invWithPods(nodes, pods)
	if got := len(NodeHeadroom{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("tight pool must produce no finding, got %d", got)
	}
}

func TestNodeHeadroom_SingleNodePoolSkipped(t *testing.T) {
	nodes := []corev1.Node{poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi")}
	inv := invWithPods(nodes, nil)
	if got := len(NodeHeadroom{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("single-node pool must be skipped, got %d", got)
	}
}

// TestNodeHeadroom_TwoNodePoolNoSuggestion locks the HA floor: a 2-node pool can
// never be reclaimed below 2 nodes, so even with huge request-slack it yields no
// finding (removable capped at nodeCount-2 = 0).
func TestNodeHeadroom_TwoNodePoolNoSuggestion(t *testing.T) {
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
	}
	pods := []corev1.Pod{requestPod("app", "a", "n1", "50m", "256Mi")}
	inv := invWithPods(nodes, pods)
	if got := len(NodeHeadroom{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("2-node pool must yield no suggestion (HA floor leaves >=2), got %d", got)
	}
}

// TestNodeHeadroom_PodsNotCollectedSkips locks the denial guard: when pods were
// RBAC-denied / never collected, summed requests read as ~0 and would fabricate
// phantom headroom — the rule must stay silent instead.
func TestNodeHeadroom_PodsNotCollectedSkips(t *testing.T) {
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n3", "eu-central-1", "m6i.large", "1800m", "7Gi"),
	}
	inv := &collect.Inventory{Nodes: nodes} // Meta.Collected omits "pods"
	inv.Meta.Collected = []string{"nodes"}
	inv.Meta.Denied = []string{"pods: forbidden"}
	if got := len(NodeHeadroom{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("pods-not-collected must skip (no phantom headroom), got %d", got)
	}
}

// TestNodeHeadroom_DaemonSetExcluded locks that DaemonSet pod requests do not
// count as reclaimable slack: a pool whose only "load" is a per-node DaemonSet
// must not be over-credited as nearly-empty by the DaemonSet footprint, and the
// finding (if any) must carry the DaemonSet caveat.
func TestNodeHeadroom_DaemonSetExcluded(t *testing.T) {
	// 4-node pool. Big DaemonSet requests (1500m/5Gi per node) PLUS one small app
	// pod. If DaemonSet requests were (wrongly) summed, the pool would look full;
	// excluding them, ~all capacity is "slack" but the caveat must be present.
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n3", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("n4", "eu-central-1", "m6i.large", "1800m", "7Gi"),
	}
	pods := []corev1.Pod{
		daemonPod("kube-system", "cni-1", "n1", "1500m", "5Gi"),
		daemonPod("kube-system", "cni-2", "n2", "1500m", "5Gi"),
		daemonPod("kube-system", "cni-3", "n3", "1500m", "5Gi"),
		daemonPod("kube-system", "cni-4", "n4", "1500m", "5Gi"),
		requestPod("app", "a", "n1", "200m", "1Gi"),
	}
	inv := invWithPods(nodes, pods)
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	low := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	// DaemonSet requests excluded → only the 200m/1Gi app pod counts; the summed
	// REQUESTS evidence must reflect the small figure, not the DaemonSet bulk.
	if !strings.Contains(low, "daemonset pods excluded") {
		t.Errorf("evidence must state DaemonSet pods are excluded: %v", fs[0].Evidence)
	}
	if !strings.Contains(low, "1:1 with node count") {
		t.Errorf("evidence must explain DaemonSet footprint scales per node: %v", fs[0].Evidence)
	}
	// Sanity: summed requests should be the small app pod (0.2 CPU), proving the
	// 6.0 CPU of DaemonSet requests were not counted.
	if !strings.Contains(low, "0.2 cpu") {
		t.Errorf("summed requests must exclude DaemonSet bulk (expect ~0.2 CPU): %v", fs[0].Evidence)
	}
}

func TestNodeHeadroom_UnknownPriceNote(t *testing.T) {
	// Unknown instance type → still a finding (dollar already 0 for everything),
	// with an explicit "not in price table" note instead of an UNVERIFIED figure.
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "made-up.xl", "1800m", "7Gi"),
		poolNode("n2", "eu-central-1", "made-up.xl", "1800m", "7Gi"),
		poolNode("n3", "eu-central-1", "made-up.xl", "1800m", "7Gi"),
	}
	pods := []corev1.Pod{requestPod("app", "a", "n1", "200m", "1Gi")}
	inv := invWithPods(nodes, pods)
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("dollar impact must be 0, got %v", fs[0].DollarImpactMonthly)
	}
	if !strings.Contains(strings.ToLower(strings.Join(fs[0].Evidence, " ")), "not in price table") {
		t.Errorf("evidence must note the price is unavailable: %v", fs[0].Evidence)
	}
}

func TestNodeHeadroom_PricedPoolStillNotBilled(t *testing.T) {
	// AKS Standard_D4lds_v5 with a KNOWN price: the would-be figure appears only
	// as an UNVERIFIED upper bound; DollarImpactMonthly stays 0.
	nodes := []corev1.Node{
		poolNode("n1", "westus3", "Standard_D4lds_v5", "3800m", "15Gi"),
		poolNode("n2", "westus3", "Standard_D4lds_v5", "3800m", "15Gi"),
		poolNode("n3", "westus3", "Standard_D4lds_v5", "3800m", "15Gi"),
	}
	pods := []corev1.Pod{requestPod("app", "a", "n1", "400m", "2Gi")}
	inv := invWithPods(nodes, pods)
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("priced pool: requests-only must not be billed; want $0, got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(ev, "UNVERIFIED") || !strings.Contains(ev, "$") {
		t.Errorf("priced pool must show the potential dollar as UNVERIFIED: %v", fs[0].Evidence)
	}
}

func TestNodeHeadroom_SystemPoolHACaveat(t *testing.T) {
	// AKS system pool (kubernetes.azure.com/mode=system) with slack must carry the
	// HA-floor caveat so a reader never drains control-plane addons below 2 nodes.
	mk := func(name string) corev1.Node {
		n := poolNode(name, "westus3", "Standard_D4lds_v5", "3800m", "15Gi")
		n.Labels["kubernetes.azure.com/mode"] = "system"
		return n
	}
	nodes := []corev1.Node{mk("s1"), mk("s2"), mk("s3")}
	pods := []corev1.Pod{requestPod("kube-system", "coredns", "s1", "200m", "1Gi")}
	inv := invWithPods(nodes, pods)
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	low := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	if !strings.Contains(low, "system") || !strings.Contains(low, "ha") {
		t.Errorf("system pool finding must carry the HA-floor caveat: %v", fs[0].Evidence)
	}
}

func TestNodeHeadroom_TwoPoolsTwoFindings(t *testing.T) {
	nodes := []corev1.Node{
		poolNode("a1", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("a2", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("a3", "eu-central-1", "m6i.large", "1800m", "7Gi"),
		poolNode("b1", "eu-central-1", "r6i.large", "1800m", "15Gi"),
		poolNode("b2", "eu-central-1", "r6i.large", "1800m", "15Gi"),
		poolNode("b3", "eu-central-1", "r6i.large", "1800m", "15Gi"),
	}
	pods := []corev1.Pod{
		requestPod("app", "x", "a1", "200m", "1Gi"),
		requestPod("app", "y", "b1", "200m", "1Gi"),
	}
	inv := invWithPods(nodes, pods)
	fs := NodeHeadroom{}.Evaluate(inv, Options{})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings (two pools), got %d", len(fs))
	}
	if fs[0].ID == fs[1].ID {
		t.Errorf("distinct pools must have distinct IDs: %q", fs[0].ID)
	}
	for _, f := range fs {
		if !strings.HasPrefix(f.ID, "f-") {
			t.Errorf("ID must be f-prefixed: %q", f.ID)
		}
	}
}

// B-102 — a native sidecar's request is reserved for the pod's whole life, and this rule skipped it.
//
// KEP-753 sidecars are initContainers with restartPolicy: Always. They start before the app
// containers and keep running, so the scheduler reserves their requests for as long as the pod
// exists — exactly like a regular container. podRequests counted only Spec.Containers, on a comment
// that was true before native sidecars existed: "init containers run before app containers, so
// their requests are not additive".
//
// The error direction is the unfavourable one. Undercounting what is bound OVERSTATES how much of a
// pool is idle, and this rule's whole output is "this pool looks drainable". On the mesh testbed it
// was 100m across ten istio-proxy sidecars; on a real injected cluster it is every pod.
func TestPodRequests_CountsNativeSidecars(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{
			{ // a native sidecar — runs for the pod's whole life
				Name: "istio-proxy", RestartPolicy: &always,
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("10m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				}},
			},
			{ // a classic init container — runs to completion, then releases
				Name: "migrate",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("1Gi"),
				}},
			},
		},
		Containers: []corev1.Container{{
			Name: "app",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			}},
		}},
	}}

	cpu, mem := podRequests(pod)
	if got, want := cpu.MilliValue(), int64(110); got != want {
		t.Errorf("cpu = %dm, want %dm (100m app + 10m native sidecar; the 500m classic init must NOT count)", got, want)
	}
	if got, want := mem.Value(), int64(192*1024*1024); got != want {
		t.Errorf("mem = %d, want %d (128Mi app + 64Mi native sidecar)", got, want)
	}
}

// A pool's finding id must not depend on the order the API server returned its nodes.
//
// The id hashes the pool's REGION, and the region was "the first region label seen while walking inv.Nodes".
// A pool whose nodes carry two different region labels — rare, but a cluster stretched across regions, or a
// node mislabelled during a migration — therefore got a different id depending on which node the list
// happened to lead with. The id is what the comparison layer, the history timeline and the re-derivation
// claim all key on, so "usually the same" is not a property any of them can rest on.
func TestNodeHeadroom_FindingIDDoesNotDependOnNodeListOrder(t *testing.T) {
	// ONE POOL (same instance type), FOUR NODES, TWO REGION LABELS — the shape the rule fires on, with the
	// ambiguity the id slot cannot resolve. Requests fill a sliver, so there is slack to report.
	a := poolNode("node-a", "eu-central-1", "m6i.large", "1800m", "7Gi")
	b := poolNode("node-b", "ap-south-1", "m6i.large", "1800m", "7Gi")
	c := poolNode("node-c", "eu-central-1", "m6i.large", "1800m", "7Gi")
	d := poolNode("node-d", "ap-south-1", "m6i.large", "1800m", "7Gi")
	pods := []corev1.Pod{
		requestPod("app", "p1", "node-a", "600m", "2Gi"),
		requestPod("app", "p2", "node-b", "600m", "2Gi"),
	}

	idsFor := func(nodes []corev1.Node) []string {
		var out []string
		for _, f := range (NodeHeadroom{}).Evaluate(invWithPods(nodes, pods), Options{}) {
			out = append(out, f.ID)
		}
		return out
	}

	fwd := idsFor([]corev1.Node{a, b, c, d})
	rev := idsFor([]corev1.Node{b, a, d, c})
	if len(fwd) == 0 {
		t.Fatal("the rule produced no finding for an idle two-node pool, so this test asserts nothing")
	}
	if len(fwd) != len(rev) {
		t.Fatalf("%d finding(s) one way, %d the other", len(fwd), len(rev))
	}
	for i := range fwd {
		if fwd[i] != rev[i] {
			t.Errorf("finding %d changes id with the node list order: %s vs %s\n"+
				"the id hashes the pool's region, and the region was whichever node came first", i, fwd[i], rev[i])
		}
	}
}

// A FINISHED POD RESERVES NOTHING. A Job's pod that has Succeeded stays bound to its node until it is
// garbage-collected, with its requests still in its spec; the scheduler and the kubelet stop counting them the
// moment it terminates. Counting them as reserved made a pool look fuller than it is — here a finished three-core
// batch run hid the pool's whole spare node. The same defect the feasibility model had (holdsRoom); measured on the
// engine bench.
func TestNodeHeadroom_AFinishedPodReservesNothing(t *testing.T) {
	nodes := []corev1.Node{
		poolNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi"),
		poolNode("n2", "eu-central-1", "m6i.xlarge", "4", "16Gi"),
		poolNode("n3", "eu-central-1", "m6i.xlarge", "4", "16Gi"),
	}
	done := requestPod("batch", "report-28123-x7k2p", "n1", "3", "12Gi")
	done.Status.Phase = corev1.PodSucceeded
	failed := requestPod("batch", "import-28123-q9w4z", "n2", "3", "12Gi")
	failed.Status.Phase = corev1.PodFailed
	pods := []corev1.Pod{
		requestPod("app", "a", "n1", "2", "8Gi"),
		requestPod("app", "b", "n2", "2", "8Gi"),
		requestPod("app", "c", "n3", "2", "8Gi"),
		done, failed,
	}
	if got := len(NodeHeadroom{}.Evaluate(invWithPods(nodes, pods), Options{})); got != 1 {
		t.Fatalf("six cores and 24 GiB of the pool are reserved by nothing running — a node's worth — "+
			"and the rule reported %d finding(s), want 1", got)
	}
}
