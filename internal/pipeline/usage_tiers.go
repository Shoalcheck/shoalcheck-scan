package pipeline

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
)

// THE TIER-2 AND TIER-3 USAGE SOURCES, FROM WHAT THE READING ALREADY HOLDS (ENG-07). Both seams existed with nothing
// behind them outside the tests: a cluster without Prometheus read no usage at all, though its VPA recommendations
// and its metrics-server sample were one list away. They are read now with the read set (docs/engine/read-set.md),
// and these listers hand them to the usage resolver. Neither banks a dollar: a VPA target is the autoscaler's own
// estimate and a metrics-server sample is one moment (ENG-04).

var (
	vpaGVR        = schema.GroupVersionResource{Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"}
	podMetricsGVR = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}
)

// inventoryVPA gives each container of each pod a VPA targets the VPA's own recommendation for that container: the
// target as the figure, the upper bound as the maximum the memory floor respects.
type inventoryVPA struct{ inv *collect.Inventory }

func (v inventoryVPA) ListTargets(context.Context) (map[string]prom.ContainerUsage, error) {
	type rec struct{ cpu, mem, memMax float64 }
	byTarget := map[string]map[string]rec{} // ns/Kind/name → container → recommendation
	for _, o := range v.inv.StackObjects[vpaGVR] {
		kind, _, _ := unstructured.NestedString(o.Object, "spec", "targetRef", "kind")
		name, _, _ := unstructured.NestedString(o.Object, "spec", "targetRef", "name")
		recs, _, _ := unstructured.NestedSlice(o.Object, "status", "recommendation", "containerRecommendations")
		for _, r := range recs {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			c, _, _ := unstructured.NestedString(m, "containerName")
			cpu := quantity(m, "target", "cpu")
			mem := quantity(m, "target", "memory")
			memMax := quantity(m, "upperBound", "memory")
			if memMax < mem {
				memMax = mem
			}
			key := o.GetNamespace() + "/" + kind + "/" + name
			if byTarget[key] == nil {
				byTarget[key] = map[string]rec{}
			}
			byTarget[key][c] = rec{cpu, mem, memMax}
		}
	}
	out := map[string]prom.ContainerUsage{}
	for i := range v.inv.Pods {
		p := &v.inv.Pods[i]
		kind, name := podController(p)
		recs := byTarget[p.Namespace+"/"+kind+"/"+name]
		for _, c := range p.Spec.Containers {
			if r, ok := recs[c.Name]; ok {
				out[p.Namespace+"/"+p.Name+"/"+c.Name] = prom.ContainerUsage{Namespace: p.Namespace, Pod: p.Name, Container: c.Name,
					CPUCoresP95: r.cpu, CPUCoresMax: r.cpu, MemBytesP95: r.mem, MemBytesMax: r.memMax}
			}
		}
	}
	return out, nil
}

// inventoryMetrics is metrics-server's one sample per container.
type inventoryMetrics struct{ inv *collect.Inventory }

func (m inventoryMetrics) ListSnapshot(context.Context) (map[string]prom.ContainerUsage, error) {
	out := map[string]prom.ContainerUsage{}
	for _, o := range m.inv.StackObjects[podMetricsGVR] {
		cs, _, _ := unstructured.NestedSlice(o.Object, "containers")
		for _, c := range cs {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			name, _, _ := unstructured.NestedString(cm, "name")
			cpu := quantity(cm, "usage", "cpu")
			mem := quantity(cm, "usage", "memory")
			out[o.GetNamespace()+"/"+o.GetName()+"/"+name] = prom.ContainerUsage{Namespace: o.GetNamespace(), Pod: o.GetName(),
				Container: name, CPUCoresP95: cpu, CPUCoresMax: cpu, MemBytesP95: mem, MemBytesMax: mem}
		}
	}
	return out, nil
}

// quantity reads a Kubernetes quantity at a path as a number (cores, bytes); zero when absent or unparseable.
func quantity(m map[string]any, path ...string) float64 {
	s, ok, _ := unstructured.NestedString(m, path...)
	if !ok {
		return 0
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	return q.AsApproximateFloat64()
}

// podController is the workload a pod belongs to as a VPA names it: a ReplicaSet's pod belongs to the Deployment whose
// name is the ReplicaSet's without its pod-template-hash suffix.
func podController(p *corev1.Pod) (kind, name string) {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if h := p.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Deployment", strings.TrimSuffix(o.Name, "-"+h)
			}
		}
		return o.Kind, o.Name
	}
	return "", ""
}

// tierListers are the VPA and metrics listers the resolver gets: the caller's when it gave one, otherwise the
// inventory's when the reading read that kind, otherwise none.
func tierListers(opts Options, inv *collect.Inventory) (prom.VPALister, prom.MetricsLister) {
	vpa, met := opts.VPALister, opts.MetricsLister
	if vpa == nil && len(inv.StackObjects[vpaGVR]) > 0 {
		vpa = inventoryVPA{inv}
	}
	if met == nil && len(inv.StackObjects[podMetricsGVR]) > 0 {
		met = inventoryMetrics{inv}
	}
	return vpa, met
}
