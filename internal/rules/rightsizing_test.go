package rules

import (
	"math"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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
			Containers: []corev1.Container{
				{Name: cname, Image: "img", Resources: corev1.ResourceRequirements{Requests: reqs}},
			},
		},
	}
}

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

	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage}); len(fs) != 0 {
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
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage}); len(fs) != 0 {
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d"})
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
	if fs := (Rightsizing{}).Evaluate(inv, Options{Usage: usage}); len(fs) != 0 {
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
	for _, f := range fs {
		if f.AffectedResources[0].Name == "api" {
			if !strings.Contains(strings.Join(f.Evidence, "\n"), "1 replica") {
				t.Errorf("api $ must scale by its own 1 replica:\n%v", f.Evidence)
			}
		}
	}
}

// TestRightsizing_DaemonSetScalesByNodeCount: a DaemonSet (Replicas=-1) targeting
// a nodeSelector subset must scale $ by the number of MATCHING nodes, not the
// transient matched-pod count. 2 of 3 nodes carry the selector label.
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
		}},
		// Only one pod currently scraped (the other is mid-rollout / scrape gap).
		Pods: []corev1.Pod{dsPod("agent-aaa")},
	}
	usage := map[string]prom.ContainerUsage{
		usageKey("obs", "agent-aaa", "agent"): {CPUCoresP95: 0.10, MemBytesP95: 50 * 1024 * 1024},
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	// 2 matching ssd nodes → "2 replica", scaled by node count not the 1 scraped pod.
	if !strings.Contains(ev, "2 replica") {
		t.Errorf("DaemonSet $ must scale by 2 matching nodes, not the 1 scraped pod:\n%s", ev)
	}
	if !strings.Contains(ev, "nodes the DaemonSet schedules onto") {
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
	long := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d"})
	if len(long) != 1 {
		t.Fatalf("want 1 finding over the full window, got %d", len(long))
	}
	if txt := textOf(long[0]); !strings.Contains(txt, "7d") {
		t.Errorf("a run with seven days of history lost its window:\n%s", txt)
	}

	// AND THE UNKNOWN WINDOW: no number, because the rule cannot tell how far back it looked.
	none := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage})
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
