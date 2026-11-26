package rules

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// ARGO ROLLOUTS AS WORKLOADS (ENG-11, docs/engine/controllers.md). A Rollout owns ReplicaSets the way a Deployment
// does, and its pods were part of no workload: rightsizing, probes, anti-affinity and the drain budget never saw them.
// Two shapes:
//   - an inline template: the Rollout is the workload, its template read through the prune allowlist (no env value);
//   - a workloadRef to a Deployment: the Deployment holds the template and Argo scales it to zero, so the Deployment
//     is the workload, its pods are the Rollout's, and its replica count is the Rollout's.

// rollout is what a rule needs of one Rollout.
type rollout struct {
	namespace, name string
	replicas        int32
	refDeployment   string // spec.workloadRef.name when it names a Deployment
	template        *corev1.PodTemplateSpec
}

// readRollouts is every Rollout the reading holds; nil when Rollouts were not read.
func readRollouts(inv *collect.Inventory) []rollout {
	objs, ok := crObjects(inv, gvrRollouts)
	if !ok {
		return nil
	}
	var out []rollout
	for _, o := range objs {
		r := rollout{namespace: o.GetNamespace(), name: o.GetName(), replicas: 1}
		if n, ok, _ := unstructured.NestedInt64(o.Object, "spec", "replicas"); ok {
			r.replicas = int32(n)
		} else if f, ok, _ := unstructured.NestedFloat64(o.Object, "spec", "replicas"); ok {
			r.replicas = int32(f)
		}
		if k, _, _ := unstructured.NestedString(o.Object, "spec", "workloadRef", "kind"); k == "Deployment" {
			r.refDeployment, _, _ = unstructured.NestedString(o.Object, "spec", "workloadRef", "name")
		}
		if t, ok, _ := unstructured.NestedMap(o.Object, "spec", "template"); ok {
			var pt corev1.PodTemplateSpec
			if runtime.DefaultUnstructuredConverter.FromUnstructured(t, &pt) == nil {
				r.template = &pt
			}
		}
		out = append(out, r)
	}
	return out
}

// rolloutIndex is the Rollouts by namespace/name.
func rolloutIndex(inv *collect.Inventory) map[string]rollout {
	out := map[string]rollout{}
	for _, r := range readRollouts(inv) {
		out[r.namespace+"/"+r.name] = r
	}
	return out
}
