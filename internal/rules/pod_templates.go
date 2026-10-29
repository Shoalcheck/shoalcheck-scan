package rules

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// podTemplates is every pod spec the cluster runs, each judged ONCE, for the rules whose question is what a pod runs
// as and with — privilege, host access, the Pod Security fields, Secrets in its environment, its image references,
// its ServiceAccount token.
//
// WHY THIS IS NOT workloads(). workloads() is the Deployments, StatefulSets and DaemonSets, and for the rules that
// ask about replicas, budgets, spread and rollouts that is the right set. For the pod-security rules it was a blind
// spot: a privileged bare Pod, a Job that mounts the node's root filesystem and a CronJob that runs privileged every
// night were judged by no rule at all (found by the gate agent's review, planted on the engine bench since). A
// privileged pod is privileged whoever created it.
//
// WHAT "ONCE" MEANS. A spec is judged where an operator would change it:
//   - the three workload kinds, by their templates (as workloads() returns them);
//   - a CronJob by its job template, so the Jobs it spawns and their pods are not judged again;
//   - a Job not owned by a CronJob in this reading, by its template, so its pods are not judged again;
//   - a pod whose controller is one of the above is skipped — its spec is that controller's;
//   - a pod whose controller this product does not collect (a ReplicaSet with no Deployment, an operator's custom
//     resource) is judged once per controller, as the FIRST such pod — two pods of one Rollout are one finding, not
//     two. It is named as the Pod, because the Pod is what was read: a sentence about "Rollout jobs/ingest" would
//     claim a provenance no reading supports (B-141, internal/fixture/provenance_test.go);
//   - a pod with no controller (or a static pod, which a Node "owns") is judged as itself.
//
// Pods that have finished are not "run" and are skipped; their controllers, where collected, are not.
func podTemplates(inv *collect.Inventory, opts Options) []workload {
	out := workloads(inv, opts)
	keep := func(ns string) bool { return opts.IncludeSystem || !isSystemNamespace(ns) }

	cronJobs := map[string]bool{}
	for i := range inv.CronJobs {
		c := &inv.CronJobs[i]
		cronJobs[c.Namespace+"/"+c.Name] = true
		if !keep(c.Namespace) {
			continue
		}
		out = append(out, workload{Kind: "CronJob", Namespace: c.Namespace, Name: c.Name, Replicas: 1,
			PodSpec: c.Spec.JobTemplate.Spec.Template.Spec, PodLabels: c.Spec.JobTemplate.Spec.Template.Labels,
			apiVersion: "batch/v1", specPath: ".spec.jobTemplate.spec.template.spec"})
	}
	jobs := map[string]bool{}
	for i := range inv.Jobs {
		j := &inv.Jobs[i]
		jobs[j.Namespace+"/"+j.Name] = true
		if ref := jobControllerRef(j.OwnerReferences); ref != nil && ref.Kind == "CronJob" && cronJobs[j.Namespace+"/"+ref.Name] {
			continue // the CronJob's template is this Job's spec
		}
		if !keep(j.Namespace) {
			continue
		}
		out = append(out, workload{Kind: "Job", Namespace: j.Namespace, Name: j.Name, Replicas: 1,
			PodSpec: j.Spec.Template.Spec, PodLabels: j.Spec.Template.Labels,
			apiVersion: "batch/v1", specPath: ".spec.template.spec"})
	}

	judged := map[string]bool{}
	for _, w := range out {
		judged[w.Kind+"/"+w.Namespace+"/"+w.Name] = true
	}
	// Workloads in skipped namespaces are not in `out`, but their pods must not resurface as unowned either.
	isCollected := func(kind, ns, name string) bool {
		switch kind {
		case "StatefulSet":
			for i := range inv.StatefulSets {
				if inv.StatefulSets[i].Namespace == ns && inv.StatefulSets[i].Name == name {
					return true
				}
			}
		case "DaemonSet":
			for i := range inv.DaemonSets {
				if inv.DaemonSets[i].Namespace == ns && inv.DaemonSets[i].Name == name {
					return true
				}
			}
		case "Job":
			return jobs[ns+"/"+name]
		}
		return false
	}
	for i := range inv.Pods {
		p := inv.Pods[i]
		if !keep(p.Namespace) || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		ref := controllerRef(p)
		if ref == nil || ref.Kind == "Node" {
			out = append(out, workload{Kind: "Pod", Namespace: p.Namespace, Name: p.Name, Replicas: 1,
				PodSpec: p.Spec, PodLabels: p.Labels, apiVersion: "v1", specPath: ".spec"})
			continue
		}
		if ref.Kind == "ReplicaSet" && deploymentForReplicaSet(inv, p.Namespace, ref.Name) != nil {
			continue
		}
		if isCollected(ref.Kind, p.Namespace, ref.Name) {
			continue
		}
		key := ref.Kind + "/" + p.Namespace + "/" + ref.Name
		if judged[key] {
			continue // a second pod of a controller already judged by its first
		}
		judged[key] = true
		out = append(out, workload{Kind: "Pod", Namespace: p.Namespace, Name: p.Name, Replicas: 1,
			PodSpec: p.Spec, PodLabels: p.Labels, apiVersion: "v1", specPath: ".spec"})
	}
	return out
}

// jobControllerRef is controllerRef for an object's owner list rather than a pod's.
func jobControllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

// podTemplateKinds is what podTemplates reads, for the rules' RequiredKinds.
func podTemplateKinds(extra ...string) []string {
	return withWorkloads(append([]string{"cronjobs", "jobs", "pods"}, extra...)...)
}
