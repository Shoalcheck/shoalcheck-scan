package rules

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// workload flattens Deployments/StatefulSets/DaemonSets into the shape
// rules actually inspect.
type workload struct {
	Kind      string
	Namespace string
	Name      string
	Replicas  int32 // -1 for DaemonSets (node-bound)
	PodSpec   corev1.PodSpec
	PodLabels map[string]string

	// apiVersion and specPath say where this spec lives in its object, for a remediation that names a path. The
	// three workload kinds leave both empty (apps/v1, .spec.template.spec); podTemplates sets them for the rest.
	apiVersion, specPath string
}

// templatePath is the JSONPath prefix of the pod spec inside the object.
func (w workload) templatePath() string {
	if w.specPath != "" {
		return w.specPath
	}
	return ".spec.template.spec" // the three workload kinds, built by workloads()
}

// objectAPIVersion is the object's apiVersion; the three workload kinds are apps/v1.
func (w workload) objectAPIVersion() string {
	if w.apiVersion != "" {
		return w.apiVersion
	}
	return "apps/v1"
}

func isSystemNamespace(ns string) bool { return types.IsSystemNamespace(ns) }

func workloads(inv *collect.Inventory, opts Options) []workload {
	var out []workload
	add := func(kind, ns, name string, replicas int32, spec corev1.PodSpec, labels map[string]string) {
		if !opts.IncludeSystem && isSystemNamespace(ns) {
			return
		}
		out = append(out, workload{Kind: kind, Namespace: ns, Name: name, Replicas: replicas, PodSpec: spec, PodLabels: labels})
	}
	for _, d := range inv.Deployments {
		r := int32(1)
		if d.Spec.Replicas != nil {
			r = *d.Spec.Replicas
		}
		add("Deployment", d.Namespace, d.Name, r, d.Spec.Template.Spec, d.Spec.Template.Labels)
	}
	for _, s := range inv.StatefulSets {
		r := int32(1)
		if s.Spec.Replicas != nil {
			r = *s.Spec.Replicas
		}
		add("StatefulSet", s.Namespace, s.Name, r, s.Spec.Template.Spec, s.Spec.Template.Labels)
	}
	for _, d := range inv.DaemonSets {
		add("DaemonSet", d.Namespace, d.Name, -1, d.Spec.Template.Spec, d.Spec.Template.Labels)
	}
	return out
}
