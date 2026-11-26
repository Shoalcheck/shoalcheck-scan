package rules

import (
	"math"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// node builds a Node with allocatable CPU/mem and the region + instance-type
// labels the rule prices against.
func rsNode(name, region, itype, cpu, mem string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"topology.kubernetes.io/region": region,
				labelInstanceType:               itype,
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

// rsPod builds a pod owned by deployment `owner` (via a ReplicaSet whose name
// strips back to the deployment), with one container `cname` requesting `cpu`.
func rsPod(ns, podName, owner, cname, cpu, mem string, labels map[string]string) corev1.Pod {
	ctrl := true
	reqs := corev1.ResourceList{}
	if cpu != "" {
		reqs[corev1.ResourceCPU] = resource.MustParse(cpu)
	}
	if mem != "" {
		reqs[corev1.ResourceMemory] = resource.MustParse(mem)
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: owner + "-7d4f8b9c5d", Controller: &ctrl},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "n1", // every fixture here has one node, n1; the dollar prices each replica on its own node
			Containers: []corev1.Container{
				{Name: cname, Image: "img", Resources: corev1.ResourceRequirements{Requests: reqs}},
			},
		},
	}
}

// week is the usage record of a Prometheus that holds the week its queries span: the one basis that banks a dollar.
var week = &types.UsageMethodology{Source: "prometheus", Window: "7d", Confidence: types.UsageConfidenceHigh}

// rsDeploy builds a Deployment with one container requesting cpu/mem.
func rsDeploy(ns, name string, replicas int32, cname, cpu, mem string) appsv1.Deployment {
	reqs := corev1.ResourceList{}
	if cpu != "" {
		reqs[corev1.ResourceCPU] = resource.MustParse(cpu)
	}
	if mem != "" {
		reqs[corev1.ResourceMemory] = resource.MustParse(mem)
	}
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					{Name: cname, Image: "img", Resources: corev1.ResourceRequirements{Requests: reqs}},
				}},
			},
		},
	}
}

func usageKey(ns, pod, c string) string { return ns + "/" + pod + "/" + c }

// TestRightsizing_OverprovisionedFlaggedWithDollar is the headline assertion:
// container "api" requests 1000m, 7d p95 = 180m, 3 replicas, on m6i.xlarge in
// eu-central-1. The exact recommended value and $/mo are pinned.
//
// Formula (documented in rightsizing.go):
//
//	recommended CPU = ceil(p95 * 1.3) rounded up to 10m = ceil(180*1.3=234) -> 240m
//	reclaim per replica = 1000 - 240 = 760m ; * 3 replicas = 2280m = 2.28 cores
//	m6i.xlarge eu-central-1 = $0.23/h * 730 = $167.90/mo ; allocatable 4 cores
//	CPU $ = (2.28 / 4) * 167.90 = 0.57 * 167.90 = $95.703/mo
//
// (memory is well-sized here, so CPU is the binding dimension.)
func TestRightsizing_OverprovisionedFlaggedWithDollar(t *testing.T) {
	const (
		nodePriceMo  = 0.23 * 730 // m6i.xlarge eu-central-1 = $167.90/mo (pinned to pricing table)
		wantRecommMC = 240        // recommended CPU millicores
		wantDollar   = (2.28 / 4.0) * nodePriceMo
	)

	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "api-aaa", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-bbb", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-ccc", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		// p95 CPU 180m on the highest replica; mem p95 ~400Mi (well within 512Mi*1.3).
		usageKey("shop", "api-aaa", "api"): {Namespace: "shop", Pod: "api-aaa", Container: "api", CPUCoresP95: 0.18, MemBytesP95: 400 * 1024 * 1024},
		usageKey("shop", "api-bbb", "api"): {Namespace: "shop", Pod: "api-bbb", Container: "api", CPUCoresP95: 0.12, MemBytesP95: 380 * 1024 * 1024},
		usageKey("shop", "api-ccc", "api"): {Namespace: "shop", Pod: "api-ccc", Container: "api", CPUCoresP95: 0.15, MemBytesP95: 390 * 1024 * 1024},
	}

	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.cost.overprovisioned-resources" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if f.Category != "cost" {
		t.Errorf("category = %q, want cost", f.Category)
	}
	if f.Severity != "medium" {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	// Confidence is now data-quality-derived, not hardcoded: a healthy 3-replica
	// series with no high-burstiness signal sits at the 0.85 baseline.
	if f.Confidence != 0.85 {
		t.Errorf("confidence = %v, want 0.85 (baseline: 3 series, no burstiness)", f.Confidence)
	}
	if math.Abs(f.DollarImpactMonthly-wantDollar) > 0.01 {
		t.Errorf("dollar = %.4f, want %.4f", f.DollarImpactMonthly, wantDollar)
	}
	// Recommended value must appear in the remediation YAML (240m).
	if !strings.Contains(f.RemediationYAML, "240m") {
		t.Errorf("remediation YAML must contain recommended 240m:\n%s", f.RemediationYAML)
	}
	if !strings.Contains(f.RemediationYAML, "name: api") {
		t.Errorf("remediation YAML must be container-specific:\n%s", f.RemediationYAML)
	}
	// Evidence must show the math: requests, p95, headroom, recommend, reclaim, replicas.
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{"1000m", "180m", "1.3", "240m", "760m", "3 replica"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence missing %q:\n%s", want, ev)
		}
	}
}

// TestRightsizing_WellSizedNotFlagged: request close to p95 -> no finding.
func TestRightsizing_WellSizedNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "web", 2, "web", "250m", "256Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "web-aaa", "web", "web", "250m", "256Mi", map[string]string{"app": "web"}),
			rsPod("shop", "web-bbb", "web", "web", "250m", "256Mi", map[string]string{"app": "web"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		// p95 200m -> *1.3 = 260m > request 250m: not overprovisioned.
		usageKey("shop", "web-aaa", "web"): {CPUCoresP95: 0.20, MemBytesP95: 230 * 1024 * 1024},
		usageKey("shop", "web-bbb", "web"): {CPUCoresP95: 0.19, MemBytesP95: 220 * 1024 * 1024},
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage, UsageBasis: week}); len(fs) != 0 {
		t.Fatalf("well-sized workload must not be flagged, got %d: %+v", len(fs), fs)
	}
}

// TestRightsizing_TrivialGapNotFlagged: request 120m, p95 100m -> gap below the
// 100m materiality floor (and headroom): no finding.
func TestRightsizing_TrivialGapNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "tiny", 1, "tiny", "120m", "128Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "tiny-aaa", "tiny", "tiny", "120m", "128Mi", map[string]string{"app": "tiny"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "tiny-aaa", "tiny"): {CPUCoresP95: 0.10, MemBytesP95: 100 * 1024 * 1024},
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage, UsageBasis: week}); len(fs) != 0 {
		t.Fatalf("trivial gap must not be flagged, got %d: %+v", len(fs), fs)
	}
}

// TestRightsizing_NoUsageNoFindings: Usage==nil -> rule is a no-op (honest:
// without Prometheus there is no usage signal to right-size against).
func TestRightsizing_NoUsageNoFindings(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "api-aaa", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
		},
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("Usage==nil must yield no findings, got %d", len(fs))
	}
}

// TestRightsizing_UnknownRegionZeroDollar: overprovisioned container in a region
// not in the price table -> finding still emitted, but $0 + an honest note.
func TestRightsizing_UnknownRegionZeroDollar(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "mars-west-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "api-aaa", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "api-aaa", "api"): {CPUCoresP95: 0.18, MemBytesP95: 400 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding even with unknown region, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("unknown region must yield $0, got %v", fs[0].DollarImpactMonthly)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, "\n"), "price unknown") {
		t.Errorf("evidence must note price unknown:\n%v", fs[0].Evidence)
	}
}

// TestRightsizing_MemoryFlooredAtObserved7dMax is the CRITICAL OOM guard:
// a JVM-like container requests 1000Mi, 7d p95 working set is 300Mi but the 7d
// MAX is 820Mi (GC runs to the heap ceiling). p95×1.3 = 390Mi would OOMKill the
// container the next time it touches its real working set. The recommendation
// MUST floor at ceil(820Mi×1.05) = 861Mi → rounded up to 16Mi = 864Mi, NEVER
// 390Mi. CPU is well-sized here so memory is the only dimension.
func TestRightsizing_MemoryFlooredAtObserved7dMax(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "jvm", 2, "jvm", "200m", "1000Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "jvm-aaa", "jvm", "jvm", "200m", "1000Mi", map[string]string{"app": "jvm"}),
			rsPod("shop", "jvm-bbb", "jvm", "jvm", "200m", "1000Mi", map[string]string{"app": "jvm"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		// p95 300Mi but MAX 820Mi: p95×1.3=390Mi is unsafe; floor must lift to 864Mi.
		usageKey("shop", "jvm-aaa", "jvm"): {CPUCoresP95: 0.10, CPUCoresMax: 0.15, MemBytesP95: 300 * 1024 * 1024, MemBytesMax: 820 * 1024 * 1024},
		usageKey("shop", "jvm-bbb", "jvm"): {CPUCoresP95: 0.09, CPUCoresMax: 0.14, MemBytesP95: 280 * 1024 * 1024, MemBytesMax: 800 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	// The recommended memory must be the max-floor (864Mi), never the p95 value.
	if !strings.Contains(f.RemediationYAML, "864Mi") {
		t.Errorf("memory recommendation must floor at 7d max (864Mi), got YAML:\n%s", f.RemediationYAML)
	}
	if strings.Contains(f.RemediationYAML, "390Mi") || strings.Contains(f.RemediationYAML, "memory: 3") {
		t.Errorf("memory must NOT be sized from p95 alone (would OOM):\n%s", f.RemediationYAML)
	}
	// The patch's comment names the figure the value was derived from. 864Mi is the 7d MAX ×1.05, so a
	// comment reading "p95 ×1.3" describes a different number (D70: an agent quoted it back as the method).
	if !strings.Contains(f.RemediationYAML, "memory: 864Mi  # 7d max ×1.05, right-sized") {
		t.Errorf("the memory line's comment must name the max floor it came from:\n%s", f.RemediationYAML)
	}
	ev := strings.Join(f.Evidence, "\n")
	// This test describes a run that HAD the seven days, and says so explicitly since M-127: the sentence
	// names the window the usage covered, so a fixture that wants the 7d wording has to provide it.
	if !strings.Contains(ev, "7d max") || !strings.Contains(ev, "floored at 7d max") {
		t.Errorf("evidence must show the max floor was applied:\n%s", ev)
	}
	// MAX >> p95 is high burstiness → confidence below the 0.85 baseline.
	if f.Confidence >= 0.85 {
		t.Errorf("high-burstiness memory must lower confidence below baseline, got %v", f.Confidence)
	}
}

// TestRightsizing_MemoryNotFlaggedWhenMaxMeetsRequest: 7d MAX already at/above
// the current request means there is no safe room to reclaim — cutting it OOMs.
// Memory must NOT be flagged even though p95 is far below the request.
func TestRightsizing_MemoryNotFlaggedWhenMaxMeetsRequest(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "cache", 1, "cache", "200m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "cache-aaa", "cache", "cache", "200m", "512Mi", map[string]string{"app": "cache"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		// p95 150Mi (looks reclaimable) but MAX 520Mi > request 512Mi: do NOT flag mem.
		// CPU is also well-sized so the whole finding should disappear.
		usageKey("shop", "cache-aaa", "cache"): {CPUCoresP95: 0.10, MemBytesP95: 150 * 1024 * 1024, MemBytesMax: 520 * 1024 * 1024},
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage, UsageBasis: week}); len(fs) != 0 {
		t.Fatalf("memory whose 7d max meets the request must not be flagged, got %d: %+v", len(fs), fs)
	}
}

// TestRightsizing_SingleReplicaLowersConfidence: a one-pod series is thin
// evidence (p95 over a possibly-unrepresentative range). Confidence must drop
// and the evidence must say so.
func TestRightsizing_SingleReplicaLowersConfidence(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "solo", 1, "solo", "1000m", "256Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "solo-aaa", "solo", "solo", "1000m", "256Mi", map[string]string{"app": "solo"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "solo-aaa", "solo"): {CPUCoresP95: 0.18, MemBytesP95: 120 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Confidence >= 0.85 {
		t.Errorf("single-series finding must drop below baseline confidence, got %v", fs[0].Confidence)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, "\n"), "one pod series") {
		t.Errorf("evidence must flag the single-series limitation:\n%v", fs[0].Evidence)
	}
}

// TestRightsizing_OwnerAttributionPreventsDoubleCount: a co-located sibling pod
// whose labels are a SUPERSET of this workload's pod-template labels must NOT be
// attributed here — owner refs partition pods so usage isn't double-counted.
// Deployment "api" has template labels {app:api}; a sibling pod owned by a
// DIFFERENT deployment "api-v2" carries {app:api,track:stable}. A label-superset
// match would pull the sibling in; owner attribution must exclude it.
func TestRightsizing_OwnerAttributionPreventsDoubleCount(t *testing.T) {
	inv := &collect.Inventory{
		Nodes: []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{
			rsDeploy("shop", "api", 1, "api", "1000m", "256Mi"),
			rsDeploy("shop", "api-v2", 1, "api", "1000m", "256Mi"),
		},
		Pods: []corev1.Pod{
			// api's own pod — owned by ReplicaSet api-<hash>.
			rsPod("shop", "api-aaa", "api", "api", "1000m", "256Mi", map[string]string{"app": "api"}),
			// sibling owned by api-v2 — labels are a superset of {app:api}.
			rsPod("shop", "api-v2-bbb", "api-v2", "api", "1000m", "256Mi", map[string]string{"app": "api", "track": "stable"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "api-aaa", "api"):    {CPUCoresP95: 0.18, MemBytesP95: 100 * 1024 * 1024},
		usageKey("shop", "api-v2-bbb", "api"): {CPUCoresP95: 0.18, MemBytesP95: 100 * 1024 * 1024},
	}
	// Attribution check: api must see only its own 1 pod, not the v2 sibling.
	got := podsForWorkload(inv, workload{Kind: "Deployment", Namespace: "shop", Name: "api", PodLabels: map[string]string{"app": "api"}})
	if len(got) != 1 || got[0].Name != "api-aaa" {
		names := make([]string, len(got))
		for i, p := range got {
			names[i] = p.Name
		}
		t.Fatalf("api must own exactly [api-aaa], got %v", names)
	}
	// And $ for api scales by its declared 1 replica, not 2 (no double-count).
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	for _, f := range fs {
		if f.AffectedResources[0].Name == "api" {
			if !strings.Contains(strings.Join(f.Evidence, "\n"), "1 replica") {
				t.Errorf("api $ must scale by its own 1 replica:\n%v", f.Evidence)
			}
		}
	}
}

// TestRightsizing_DaemonSetScalesByNodeCount: a DaemonSet (Replicas=-1) must scale $ by the controller's own
// count, status.desiredNumberScheduled (2 here), not the transient matched-pod count (ENG-10).
func TestRightsizing_DaemonSetScalesByNodeCount(t *testing.T) {
	nodeWith := func(name string, ssd bool) corev1.Node {
		n := rsNode(name, "eu-central-1", "m6i.xlarge", "4", "16Gi")
		if ssd {
			n.Labels["disktype"] = "ssd"
		}
		return n
	}
	ctrl := true
	dsPod := func(podName string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: podName, Namespace: "obs", Labels: map[string]string{"app": "agent"},
				OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: "agent", Controller: &ctrl}},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "img",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1000m")}}}}},
		}
	}
	inv := &collect.Inventory{
		Nodes: []corev1.Node{nodeWith("n1", true), nodeWith("n2", true), nodeWith("n3", false)},
		DaemonSets: []appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "obs"},
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "agent"}},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"disktype": "ssd"},
					Containers: []corev1.Container{{Name: "agent", Image: "img",
						Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1000m")}}}},
				},
			}},
			// The controller's own count: two ssd nodes, one of them tainted against the agent elsewhere would make
			// it fewer, which only the controller knows (ENG-10).
			Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2},
		}},
		// Only one pod currently scraped (the other is mid-rollout / scrape gap).
		Pods: []corev1.Pod{dsPod("agent-aaa")},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("obs", "agent-aaa", "agent"): {CPUCoresP95: 0.10, MemBytesP95: 50 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	// 2 matching ssd nodes → "2 replica", scaled by node count not the 1 scraped pod.
	if !strings.Contains(ev, "2 replica") {
		t.Errorf("DaemonSet $ must scale by 2 matching nodes, not the 1 scraped pod:\n%s", ev)
	}
	if !strings.Contains(ev, "status.desiredNumberScheduled") {
		t.Errorf("evidence must state the replica basis is node count:\n%s", ev)
	}
}

// TestRightsizing_DollarIsUpperBoundWithCaveat: the dollar is labelled an upper
// bound and the realisation precondition is stated in evidence.
func TestRightsizing_DollarIsUpperBoundWithCaveat(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "api-aaa", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-bbb", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-ccc", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "api-aaa", "api"): {CPUCoresP95: 0.18, MemBytesP95: 400 * 1024 * 1024},
		usageKey("shop", "api-bbb", "api"): {CPUCoresP95: 0.12, MemBytesP95: 380 * 1024 * 1024},
		usageKey("shop", "api-ccc", "api"): {CPUCoresP95: 0.15, MemBytesP95: 390 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	if !strings.Contains(ev, "UPPER BOUND") || !strings.Contains(ev, "if consolidated") {
		t.Errorf("dollar note must label the figure an upper bound:\n%s", ev)
	}
	if !strings.Contains(ev, "realisation caveat") || !strings.Contains(ev, "node-count-bound") {
		t.Errorf("evidence must state the realisation precondition:\n%s", ev)
	}
	// Description must drop the absolute no-starvation clause and carry the
	// throttle/OOM caveat.
	if strings.Contains(fs[0].Description, "without starving the workload") {
		t.Errorf("description must not claim no-starvation:\n%s", fs[0].Description)
	}
	if !strings.Contains(fs[0].Description, "OOMKilled") {
		t.Errorf("description must carry the OOM/throttle caveat:\n%s", fs[0].Description)
	}
}

// A FINDING THAT SAYS 7d ON ONE HOUR OF DATA.
//
// Measured on the mesh testbed with its own Prometheus, which had been running for an hour:
//
//	methodology → window "1h", confidence "low", caveat "Prometheus holds 1h of history, not the 7d the
//	              queries span — the p95 is computed over that shorter period."
//	finding     → "requests 900m CPU, 7d p95 usage 0m (×1.3 headroom = 0m) -> recommend 0m,
//	               reclaim 900m × 3 replicas; requests 768Mi mem, 7d p95 usage 0Mi / 7d max 0Mi"
//
// Twelve sentences across one finding named a seven-day window over sixty minutes of data. The methodology
// block was honest and the finding — the part that travels into a ticket, an export, a model's answer —
// was not. This is B-001's shape, fixed once in the methodology and still live in the rule's own text.
//
// THE RULE COULD NOT KNOW. Options carried the usage map and not the window it was measured over, so "7d"
// was the span the QUERIES ask for, printed as though it were the span the data covers. prom's provider
// already computes the real one — it is what the methodology block prints — so the pipeline passes it and
// the rule states what it had.
//
// An unknown window says "observed", never a number: a rule that cannot tell how far back it looked must not
// pick a figure.
func TestRightsizing_NamesTheWindowItActuallyHad(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
		Pods: []corev1.Pod{
			rsPod("shop", "api-aaa", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-bbb", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
			rsPod("shop", "api-ccc", "api", "api", "1000m", "512Mi", map[string]string{"app": "api"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("shop", "api-aaa", "api"): {Namespace: "shop", Pod: "api-aaa", Container: "api", CPUCoresP95: 0.18, MemBytesP95: 400 * 1024 * 1024},
		usageKey("shop", "api-bbb", "api"): {Namespace: "shop", Pod: "api-bbb", Container: "api", CPUCoresP95: 0.12, MemBytesP95: 380 * 1024 * 1024},
		usageKey("shop", "api-ccc", "api"): {Namespace: "shop", Pod: "api-ccc", Container: "api", CPUCoresP95: 0.15, MemBytesP95: 390 * 1024 * 1024},
	}
	textOf := func(f types.Finding) string {
		return strings.Join(append([]string{f.Title, f.Description, f.WhyItMatters, f.RemediationYAML}, f.Evidence...), "\n")
	}

	short := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "1h"})
	if len(short) != 1 {
		t.Fatalf("want 1 finding over the short window, got %d", len(short))
	}
	if txt := textOf(short[0]); strings.Contains(txt, "7d") || strings.Contains(txt, "7-day") {
		i := strings.Index(txt, "7d")
		if i < 0 {
			i = strings.Index(txt, "7-day")
		}
		t.Errorf("a finding computed over 1h of history says seven days:\n  …%s…", txt[max(0, i-90):i+60])
	} else if !strings.Contains(txt, "1h") {
		t.Errorf("the finding names no window at all, so a reader cannot weigh the figure:\n%s", txt)
	}

	// THE OVER-REACH: a run that really had the seven days still says so.
	long := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week})
	if len(long) != 1 {
		t.Fatalf("want 1 finding over the full window, got %d", len(long))
	}
	if txt := textOf(long[0]); !strings.Contains(txt, "7d") {
		t.Errorf("a run with seven days of history lost its window:\n%s", txt)
	}

	// AND THE UNKNOWN WINDOW: no number, because the rule cannot tell how far back it looked.
	none := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(none) != 1 {
		t.Fatalf("want 1 finding with no window, got %d", len(none))
	}
	if txt := textOf(none[0]); strings.Contains(txt, "7d") || strings.Contains(txt, "7-day") {
		t.Errorf("a run that does not know its window still claims seven days:\n%s", txt)
	}
}

// A RECOMMENDATION IS NEVER ZERO.
//
// Measured on the mesh testbed: an idle container (p95 CPU 0, 6h memory max 3Mi) got the patch
// `cpu: 0m # 6h p95 ×1.3, right-sized`, and the same text went verbatim into a ticket. Applied, a 0m request is
// no request — the container gets the minimum CPU shares and is the first starved under contention — and the
// dollar figure counted the whole request as reclaimable. ceil(0 × 1.3) rounds up to 0, so the rounding the
// header promises ("rounded UP to 10m") never produced a floor. The floor is the rounding step itself: 10m of
// CPU and 16Mi of memory, the smallest values this rule ever recommends.
func TestRightsizing_ARecommendationIsNeverZero(t *testing.T) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("waste", "idle-hog", 3, "sleeper", "900m", "768Mi")},
		Pods: []corev1.Pod{
			rsPod("waste", "idle-a", "idle-hog", "sleeper", "900m", "768Mi", map[string]string{"app": "idle-hog"}),
			rsPod("waste", "idle-b", "idle-hog", "sleeper", "900m", "768Mi", map[string]string{"app": "idle-hog"}),
		},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("waste", "idle-a", "sleeper"): {Namespace: "waste", Pod: "idle-a", Container: "sleeper"},
		usageKey("waste", "idle-b", "sleeper"): {Namespace: "waste", Pod: "idle-b", Container: "sleeper"},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	y := fs[0].RemediationYAML
	if strings.Contains(y, "cpu: 0m") || strings.Contains(y, "memory: 0Mi") {
		t.Errorf("the patch recommends a zero request:\n%s", y)
	}
	if !strings.Contains(y, "cpu: 10m") || !strings.Contains(y, "memory: 16Mi") {
		t.Errorf("the patch does not carry the floor (10m cpu, 16Mi memory):\n%s", y)
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	if !strings.Contains(ev, "recommend 10m") || !strings.Contains(ev, "reclaim 890m") {
		t.Errorf("the evidence does not reconcile with the floored recommendation:\n%s", ev)
	}
}

// overProvisioned is the shop/api fixture of the headline test with its usage: 3 replicas requesting 1000m CPU
// and 512Mi, the busiest at 500m CPU — at a 50% autoscaler target — and memory well sized.
func overProvisioned(nodes ...string) (*collect.Inventory, map[string]prom.ContainerUsage) {
	inv := &collect.Inventory{
		Nodes:       []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Deployments: []appsv1.Deployment{rsDeploy("shop", "api", 3, "api", "1000m", "512Mi")},
	}
	usage := map[string]prom.ContainerUsage{}
	for i, name := range []string{"api-aaa", "api-bbb", "api-ccc"} {
		p := rsPod("shop", name, "api", "api", "1000m", "512Mi", map[string]string{"app": "api"})
		if i < len(nodes) {
			p.Spec.NodeName = nodes[i]
		}
		inv.Pods = append(inv.Pods, p)
		usage[usageKey("shop", name, "api")] = prom.ContainerUsage{CPUCoresP95: 0.5, CPUCoresMax: 0.6, MemBytesP95: 400 << 20, MemBytesMax: 410 << 20}
	}
	return inv, usage
}

func hpa(target string, metrics ...autoscalingv2.MetricSpec) autoscalingv2.HorizontalPodAutoscaler {
	return autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: target, Namespace: "shop"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: target, APIVersion: "apps/v1"},
			Metrics:        metrics}}
}

func utilization(res corev1.ResourceName, pct int32) autoscalingv2.MetricSpec {
	return autoscalingv2.MetricSpec{Type: autoscalingv2.ResourceMetricSourceType, Resource: &autoscalingv2.ResourceMetricSource{
		Name: res, Target: autoscalingv2.MetricTarget{Type: autoscalingv2.UtilizationMetricType, AverageUtilization: &pct}}}
}

// AN AUTOSCALER ON CPU UTILIZATION GOVERNS THE CPU REQUEST (ENG-01). A workload an HPA holds at 50% CPU looks half
// idle; lowering its request makes the HPA add replicas until it is back at 50%, and saves $0. The same fixture
// without the HPA is flagged with a dollar — the guard, switched off.
func TestRightsizing_AnAutoscalerOnUtilizationGovernsTheRequest(t *testing.T) {
	inv, usage := overProvisioned()
	opts := Options{Usage: usage, UsageBasis: week}
	if fs := (Rightsizing{}).Evaluate(inv, opts); len(fs) != 1 || fs[0].DollarImpactMonthly <= 0 {
		t.Fatalf("without an autoscaler the fixture must be flagged with a dollar; got %+v", fs)
	}
	inv.HPAs = []autoscalingv2.HorizontalPodAutoscaler{hpa("api", utilization(corev1.ResourceCPU, 50))}
	if fs := (Rightsizing{}).Evaluate(inv, opts); len(fs) != 0 {
		t.Fatalf("an HPA at 50%% CPU holds this workload at 50%%: no CPU saving exists, yet %d finding(s): %v", len(fs), fs[0].Evidence)
	}
	if got := RightsizingWithheld(inv, opts); len(got) != 1 || got[0] != "Deployment shop/api (CPU)" {
		t.Fatalf("withheld = %v, want the workload counted with its dimension", got)
	}

	// An autoscaler with no metrics scales on CPU at 80%: the API's default governs too.
	inv.HPAs = []autoscalingv2.HorizontalPodAutoscaler{hpa("api")}
	if fs := (Rightsizing{}).Evaluate(inv, opts); len(fs) != 0 {
		t.Fatalf("an HPA with no metrics scales on CPU at 80%%; the request is governed, yet %d finding(s)", len(fs))
	}

	// A target in absolute units does not move with the request: nothing is governed.
	v := resource.MustParse("400m")
	inv.HPAs = []autoscalingv2.HorizontalPodAutoscaler{hpa("api", autoscalingv2.MetricSpec{Type: autoscalingv2.ResourceMetricSourceType,
		Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU, Target: autoscalingv2.MetricTarget{
			Type: autoscalingv2.AverageValueMetricType, AverageValue: &v}}})}
	if fs := (Rightsizing{}).Evaluate(inv, opts); len(fs) != 1 {
		t.Fatalf("an HPA on an absolute CPU value does not hold utilization; the request is not governed, got %d findings", len(fs))
	}
}

// One dimension governed, the other over-provisioned: the finding offers the other, with no dollar or patch line
// for the governed one and the reason stated.
func TestRightsizing_AGovernedDimensionIsWithheldAndTheOtherOffered(t *testing.T) {
	inv, usage := overProvisioned()
	for k, u := range usage {
		u.MemBytesP95, u.MemBytesMax = 100<<20, 110<<20 // 512Mi request, 110Mi max: memory over-provisioned too
		usage[k] = u
	}
	inv.HPAs = []autoscalingv2.HorizontalPodAutoscaler{hpa("api", utilization(corev1.ResourceCPU, 50))}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("memory is over-provisioned and not governed: want 1 finding, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	if !strings.Contains(ev, "withheld: CPU — HorizontalPodAutoscaler shop/api scales this Deployment on its CPU utilization (target 50%)") {
		t.Errorf("the withheld dimension must be stated with its autoscaler:\n%s", ev)
	}
	if strings.Contains(fs[0].RemediationYAML, "cpu:") || !strings.Contains(fs[0].RemediationYAML, "memory:") {
		t.Errorf("the patch must carry the memory line only:\n%s", fs[0].RemediationYAML)
	}
	if strings.Contains(ev, "requests 1000m CPU") {
		t.Errorf("a governed CPU request was offered:\n%s", ev)
	}
}

// EACH REPLICA IS PRICED ON ITS OWN NODE (ENG-02). Two pools and a node the table does not know: the dollar is the
// sum over replicas of that node's price ÷ its allocatable, and the unpriced replica is counted, not guessed.
func TestRightsizing_EachReplicaIsPricedOnItsOwnNode(t *testing.T) {
	inv, usage := overProvisioned("n1", "n2", "n3")
	inv.Nodes = []corev1.Node{
		rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi"),
		rsNode("n2", "eu-central-1", "m6i.2xlarge", "8", "32Gi"),
		rsNode("n3", "eu-central-1", "no-such-type.large", "4", "16Gi"),
	}
	opts := Options{Usage: usage, UsageBasis: week}
	provider := providerFromNodes(inv.Nodes)
	price := func(n corev1.Node) float64 {
		usd, ok := opts.nodeMonthly(provider, collect.RegionOf(n), n.Labels[labelInstanceType], collect.ClassifyCapacityType(provider, n))
		if !ok {
			t.Fatalf("%s is not in the price table; the fixture needs two priced pools", n.Labels[labelInstanceType])
		}
		return usd
	}
	// Reclaim per replica: 1000m - ceil(500m×1.3 = 650m) = 350m. By hand, per replica on its node:
	want := 0.35/4*price(inv.Nodes[0]) + 0.35/8*price(inv.Nodes[1])
	fs := Rightsizing{}.Evaluate(inv, opts)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if got := fs[0].DollarImpactMonthly; math.Abs(got-want) > 0.01 {
		t.Fatalf("dollar = %.4f, want %.4f: the replicas on m6i.xlarge and m6i.2xlarge each at their own node's rate", got, want)
	}
	if ev := strings.Join(fs[0].Evidence, "\n"); !strings.Contains(ev, "priced 2 of 3 replicas") ||
		!strings.Contains(ev, "m6i.2xlarge ×1, m6i.xlarge ×1") {
		t.Errorf("the priced count and the types must be stated:\n%s", ev)
	}
}

// ONLY A PROVEN WINDOW BANKS A DOLLAR, AND ONE SAMPLE IS NEVER A P95 (ENG-04). The fleet sample said "instant p95
// usage" at confidence 0.75 with the dollars banked. A metrics.k8s.io sample, a VPA target, an hour of Prometheus
// and a usage record nobody recorded each give the candidate at $0, said as unverified.
func TestRightsizing_OnlyAProvenWindowBanksADollar(t *testing.T) {
	inv, usage := overProvisioned()
	for _, c := range []struct {
		name  string
		basis *types.UsageMethodology
		word  string
	}{
		{"instant", &types.UsageMethodology{Source: "metrics.k8s.io", Window: "instant", Confidence: types.UsageConfidenceLow}, "one-moment sample"},
		{"vpa", &types.UsageMethodology{Source: "vpa", Confidence: types.UsageConfidenceLow}, "VPA target"},
		{"an hour", &types.UsageMethodology{Source: "prometheus", Window: "1h", Confidence: types.UsageConfidenceLow}, "p95"},
		{"unrecorded", nil, "p95"},
	} {
		fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: c.basis})
		if len(fs) != 1 {
			t.Fatalf("%s: the candidate must still be offered, got %d findings", c.name, len(fs))
		}
		f := fs[0]
		all := strings.Join(append([]string{f.Title, f.Description, f.RemediationYAML}, f.Evidence...), "\n")
		if f.DollarImpactMonthly != 0 || !strings.Contains(all, "dollars withheld (basis: unverified)") {
			t.Errorf("%s: $%.2f banked, or the basis not said unverified:\n%s", c.name, f.DollarImpactMonthly, all)
		}
		if !strings.Contains(all, c.word) {
			t.Errorf("%s: the figure must be called %q:\n%s", c.name, c.word, all)
		}
		if c.word != "p95" && strings.Contains(all, "p95") {
			t.Errorf("%s: \"p95\" said of a figure that is not one:\n%s", c.name, all)
		}
		if f.Confidence > 0.5 {
			t.Errorf("%s: confidence %.2f for a candidate on an unproven basis", c.name, f.Confidence)
		}
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage, UsageBasis: week}); len(fs) != 1 || fs[0].DollarImpactMonthly == 0 {
		t.Fatal("a week of Prometheus at high confidence must bank the dollar")
	}
}

// A ROLLOUT DOES NOT ERASE THE WEEK (ENG-06). The live pods were created an hour ago by the last deploy; the week
// before it is in the series of the pods that deploy replaced, which carry the same controller-made names. Their
// busier p95 decides the recommendation, and the reading says it used them.
func TestRightsizing_UsageSurvivesARollout(t *testing.T) {
	inv, _ := overProvisioned()
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	inv.Meta.StartedAt = at
	for i := range inv.Pods {
		inv.Pods[i].Name = []string{"api-7d4f8b9c5d-xk2vq", "api-7d4f8b9c5d-m9wzt", "api-7d4f8b9c5d-pq4rl"}[i]
		inv.Pods[i].CreationTimestamp = metav1.NewTime(at.Add(-time.Hour))
	}
	usage := map[string]prom.ContainerUsage{}
	for _, p := range inv.Pods {
		usage[usageKey("shop", p.Name, "api")] = prom.ContainerUsage{CPUCoresP95: 0.1, CPUCoresMax: 0.2, MemBytesP95: 400 << 20, MemBytesMax: 410 << 20}
	}
	// The replaced ReplicaSet's pods: busier, and gone.
	for _, n := range []string{"api-5c9b7d6f8h-bbbbb", "api-5c9b7d6f8h-ccccc"} {
		usage[usageKey("shop", n, "api")] = prom.ContainerUsage{CPUCoresP95: 0.5, CPUCoresMax: 0.6, MemBytesP95: 400 << 20, MemBytesMax: 410 << 20}
	}
	// Not this workload's: another Deployment whose name starts the same, and a word the hash alphabet cannot spell.
	usage[usageKey("shop", "api-gateway-7d4f8b9c5d-xk2vq", "api")] = prom.ContainerUsage{CPUCoresP95: 0.9}
	usage[usageKey("shop", "api-canary-abcde", "api")] = prom.ContainerUsage{CPUCoresP95: 0.9}

	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %d", len(fs))
	}
	all := strings.Join(append([]string{fs[0].RemediationYAML}, fs[0].Evidence...), "\n")
	if !strings.Contains(all, "cpu: 650m") {
		t.Errorf("the recommendation must rest on the replaced pods' 500m p95 (×1.3 = 650m), not the live 100m:\n%s", all)
	}
	if !strings.Contains(all, "2 series from pods of this workload that are no longer running") {
		t.Errorf("the reading does not say it used the earlier pods:\n%s", all)
	}
	if fs[0].DollarImpactMonthly == 0 {
		t.Error("history that reaches past the rollout must still bank")
	}
}

// WITH NO EARLIER SERIES, POD AGE GATES THE DOLLAR (ENG-03). Pods an hour old cannot have seen a daily peak: the
// candidate is offered at $0 and the reason names their age.
func TestRightsizing_SeriesYoungerThanADayDoNotBank(t *testing.T) {
	inv, usage := overProvisioned()
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	inv.Meta.StartedAt = at
	for i := range inv.Pods {
		inv.Pods[i].CreationTimestamp = metav1.NewTime(at.Add(-3 * time.Hour))
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 || fs[0].DollarImpactMonthly != 0 {
		t.Fatalf("pods three hours old banked a saving: %+v", fs)
	}
	if all := strings.Join(fs[0].Evidence, "\n"); !strings.Contains(all, "was created 3 hours before the reading") {
		t.Errorf("the age is not said:\n%s", all)
	}
	for i := range inv.Pods {
		inv.Pods[i].CreationTimestamp = metav1.NewTime(at.Add(-72 * time.Hour))
	}
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage, UsageBasis: week}); len(fs) != 1 || fs[0].DollarImpactMonthly == 0 {
		t.Fatal("pods three days old must bank")
	}
}
