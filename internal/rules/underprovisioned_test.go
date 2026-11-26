package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
)

// THE UNDER-PROVISIONED HALF (ENG-52): CPU p95 over the request, memory max at the limit and memory p95 over the
// request are each stated with their figures; no dollar; a dimension an autoscaler governs is left out.
func TestUnderProvisioned_StatesEachDimensionAndNoDollar(t *testing.T) {
	inv, _ := overProvisioned()
	inv.Meta.Collected = []string{"pods", "deployments", "statefulsets", "daemonsets", "horizontalpodautoscalers"}
	for i := range inv.Pods {
		inv.Pods[i].Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")}
	}
	inv.Deployments[0].Spec.Template.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")}
	usage := map[string]prom.ContainerUsage{}
	for _, p := range inv.Pods {
		// requests 1000m / 512Mi: CPU p95 1.4 cores, memory p95 300Mi (under), max 480Mi (94% of the limit)
		usage[usageKey("shop", p.Name, "api")] = prom.ContainerUsage{CPUCoresP95: 1.4, CPUCoresMax: 1.6, MemBytesP95: 300 << 20, MemBytesMax: 480 << 20}
	}
	fs := UnderProvisioned{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week})
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	for _, want := range []string{"CPU 7d p95 is 1400m against a request of 1000m", "memory max over 7d is 480Mi, 94% of its 512Mi limit",
		"no dollar is stated"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "evicted") {
		t.Errorf("memory p95 under the request was reported:\n%s", ev)
	}
	if fs[0].DollarImpactMonthly != 0 || fs[0].Severity != "medium" {
		t.Errorf("$%.2f, severity %s", fs[0].DollarImpactMonthly, fs[0].Severity)
	}
	// An autoscaler on CPU: running above the request is its target's business, and only the memory line stays.
	inv.HPAs = append(inv.HPAs, hpa("api", utilization(corev1.ResourceCPU, 80)))
	fs = UnderProvisioned{}.Evaluate(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week})
	if len(fs) != 1 || strings.Contains(strings.Join(fs[0].Evidence, "\n"), "CPU 7d p95") {
		t.Fatalf("a governed CPU dimension was reported: %+v", fs)
	}
	// Usage under every request: nothing.
	for k, u := range usage {
		u.CPUCoresP95, u.MemBytesMax = 0.2, 200<<20
		usage[k] = u
	}
	if fs := (UnderProvisioned{}).Evaluate(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week}); len(fs) != 0 {
		t.Fatalf("well-provisioned workload reported: %d", len(fs))
	}
}
