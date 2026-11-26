package rules

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A CONTAINER'S LAST LIFE ENDED OOMKILLED: REPORTED WITH ITS LIMIT AND TIME, AND NEVER OFFERED LESS MEMORY (ENG-30).
func TestOOMKilled_IsReportedAndRightsizingNeverLowersItsMemory(t *testing.T) {
	at := time.Date(2026, 11, 15, 3, 4, 5, 0, time.UTC)
	inv, usage := overProvisioned()
	for k, u := range usage {
		u.MemBytesP95, u.MemBytesMax = 100<<20, 110<<20 // memory over-provisioned on the numbers alone
		usage[k] = u
	}
	for i := range inv.Pods {
		inv.Pods[i].Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: qty("512Mi")}
		inv.Pods[i].Status.Phase = corev1.PodRunning
	}
	inv.Pods[1].Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "api", RestartCount: 7,
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled",
			ExitCode: 137, FinishedAt: metav1.NewTime(at)}}}}
	inv.Meta.Collected = []string{"pods", "deployments", "statefulsets", "daemonsets", "nodes"}

	fs := ContainerOOMKilled{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want one finding for the Deployment, got %d", len(fs))
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	if !strings.Contains(ev, `container "api": last terminated OOMKilled at 2026-11-15T03:04:05Z, memory limit 512Mi, restartCount = 7`) {
		t.Fatalf("the kill is not stated with its time, limit and restarts:\n%s", ev)
	}
	if types.FactStr(fs[0].Facts, "oom.finished") != "2026-11-15T03:04:05Z" || types.FactNum(fs[0].Facts, "oom.limit.memory") != 512<<20 {
		t.Fatalf("facts: %+v", fs[0].Facts)
	}

	rs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	for _, f := range rs {
		if strings.Contains(f.RemediationYAML, "memory:") {
			t.Fatalf("rightsizing offered less memory to a container OOM-killed at its limit:\n%s", f.RemediationYAML)
		}
		if !strings.Contains(strings.Join(f.Evidence, "\n"), "withheld: memory — container api's last life ended OOMKilled at 2026-11-15T03:04:05Z") {
			t.Errorf("the withheld memory is not said with the kill:\n%s", strings.Join(f.Evidence, "\n"))
		}
	}
	inv.Pods[1].Status.ContainerStatuses = nil
	if fs := (ContainerOOMKilled{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatal("no kill, and a finding")
	}
	_ = appsv1.Deployment{}
	_ = collect.Inventory{}
	_ = prom.ContainerUsage{}
}
