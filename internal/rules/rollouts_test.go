package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
)

func rolloutObj(ns, name string, replicas int64, template map[string]any, ref string) unstructured.Unstructured {
	spec := map[string]any{"replicas": replicas}
	if template != nil {
		spec["template"] = template
	}
	if ref != "" {
		spec["workloadRef"] = map[string]any{"kind": "Deployment", "name": ref}
	}
	u := unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

func rolloutPod(ns, name, rs string) corev1.Pod {
	ctrl := true
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app": "api"},
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs, Controller: &ctrl}}},
		Spec: corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "api", Image: "img",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: qty("1000m"), corev1.ResourceMemory: qty("512Mi")}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
}

// A ROLLOUT'S PODS ARE A WORKLOAD NOW (ENG-11): with an inline template the Rollout is rightsized at its own replica
// count and its patch names the Rollout; with a workloadRef the Deployment it names is, at the Rollout's count.
func TestRollouts_AreWorkloads(t *testing.T) {
	tmpl := map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "img",
			"resources": map[string]any{"requests": map[string]any{"cpu": "1000m", "memory": "512Mi"}}}}}}
	inv := &collect.Inventory{
		Nodes:        []corev1.Node{rsNode("n1", "eu-central-1", "m6i.xlarge", "4", "16Gi")},
		Pods:         []corev1.Pod{rolloutPod("shop", "api-6c9f8b7d5b-xk2vq", "api-6c9f8b7d5b"), rolloutPod("shop", "api-6c9f8b7d5b-m9wzt", "api-6c9f8b7d5b")},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvrRollouts: {rolloutObj("shop", "api", 4, tmpl, "")}},
	}
	inv.Meta.Collected = []string{"pods", "nodes", crKind(gvrRollouts)}
	usage := map[string]prom.ContainerUsage{}
	for _, p := range inv.Pods {
		usage[usageKey("shop", p.Name, "api")] = prom.ContainerUsage{CPUCoresP95: 0.1, CPUCoresMax: 0.2, MemBytesP95: 400 << 20, MemBytesMax: 410 << 20}
	}
	fs := Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 || !strings.Contains(fs[0].RemediationYAML, "kind: Rollout") ||
		!strings.Contains(strings.Join(fs[0].Evidence, "\n"), "× 4 replicas") {
		t.Fatalf("the Rollout was not rightsized at its own count: %+v", fs)
	}

	// workloadRef: the Deployment holds the template and is the workload, at the Rollout's replica count.
	inv.StackObjects[gvrRollouts] = []unstructured.Unstructured{rolloutObj("shop", "api", 4, nil, "api-template")}
	zero := int32(0)
	d := rsDeploy("shop", "api-template", 0, "api", "1000m", "512Mi")
	d.Spec.Replicas = &zero
	inv.Deployments = []appsv1.Deployment{d}
	inv.Meta.Collected = append(inv.Meta.Collected, "deployments")
	fs = Rightsizing{}.Evaluate(inv, Options{Usage: usage, UsageBasis: week})
	if len(fs) != 1 || !strings.Contains(fs[0].RemediationYAML, "kind: Deployment") || !strings.Contains(fs[0].RemediationYAML, "name: api-template") ||
		!strings.Contains(strings.Join(fs[0].Evidence, "\n"), "× 4 replicas") {
		t.Fatalf("the workloadRef Deployment was not the workload at the Rollout's count: %+v", fs)
	}
}
