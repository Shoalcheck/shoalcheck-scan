package rules

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types2 "k8s.io/apimachinery/pkg/types"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ownerChain resolves a pod's controller chain (Pod → ReplicaSet → Deployment,
// or Pod → StatefulSet/DaemonSet/Job) from the Inventory's collected objects.
// Returns links with the OUTERMOST owner FIRST (e.g. [Deployment web,
// ReplicaSet web-7d4f8b9c5d]); empty for unowned pods.
//
// ReplicaSets are deliberately not collected (least-collection principle), so
// the RS→Deployment hop is inferred, not read: strip the pod-template-hash
// suffix from the ReplicaSet's name and accept the result ONLY if that
// Deployment actually exists in the inventory in the same namespace. Verified
// → [Deployment, ReplicaSet]. Unverified → the honest [ReplicaSet] alone;
// we never invent owners the collector didn't see.
func ownerChain(inv *collect.Inventory, pod corev1.Pod) []types.OwnerLink {
	return chainVia(pod, func(ns, rs string) *appsv1.Deployment { return deploymentForReplicaSet(inv, ns, rs) })
}

// chainVia is ownerChain with the ReplicaSet→Deployment hop supplied, so the walk over the inventory and the
// indexed lookup (ownerIndex) resolve a pod by ONE chain rule and cannot drift apart.
func chainVia(pod corev1.Pod, deploymentFor func(ns, rsName string) *appsv1.Deployment) []types.OwnerLink {
	ref := controllerRef(pod)
	if ref == nil {
		return nil
	}
	link := types.OwnerLink{Kind: ref.Kind, Name: ref.Name, UID: string(ref.UID)}
	if ref.Kind != "ReplicaSet" {
		// StatefulSet/DaemonSet/Job (and any other controller) own pods
		// directly — a single link is the full collected truth.
		return []types.OwnerLink{link}
	}
	if d := deploymentFor(pod.Namespace, ref.Name); d != nil {
		return []types.OwnerLink{
			{Kind: "Deployment", Name: d.Name, UID: string(d.UID)},
			link,
		}
	}
	return []types.OwnerLink{link}
}

// controllerRef picks the owner reference marked Controller=true, falling
// back to the first reference when the flag is absent (older controllers).
func controllerRef(pod corev1.Pod) *metav1.OwnerReference {
	for i := range pod.OwnerReferences {
		r := &pod.OwnerReferences[i]
		if r.Controller != nil && *r.Controller {
			return r
		}
	}
	if len(pod.OwnerReferences) > 0 {
		return &pod.OwnerReferences[0]
	}
	return nil
}

// deploymentForReplicaSet maps a ReplicaSet name back to its Deployment by
// stripping the trailing pod-template-hash segment ("web-7d4f8b9c5d" → "web")
// and verifying that Deployment exists in the same namespace. Returns nil
// when the name has no hash segment or no matching Deployment was collected.
func deploymentForReplicaSet(inv *collect.Inventory, ns, rsName string) *appsv1.Deployment {
	want, ok := replicaSetDeploymentName(rsName)
	if !ok {
		return nil
	}
	for j := range inv.Deployments {
		d := &inv.Deployments[j]
		if d.Namespace == ns && d.Name == want {
			return d
		}
	}
	return nil
}

// replicaSetDeploymentName strips the pod-template-hash segment from a ReplicaSet's name ("web-7d4f8b9c5d" →
// "web"), and reports false for a name that has none.
func replicaSetDeploymentName(rsName string) (string, bool) {
	i := strings.LastIndex(rsName, "-")
	if i <= 0 {
		return "", false
	}
	return rsName[:i], true
}

// ownerIndex resolves pods to their workloads through maps rather than a walk of every Deployment per pod.
//
// WHY IT EXISTS. ownerChain walks inv.Deployments for every pod it resolves, which is the right cost for one pod
// and the wrong one for a rule that resolves every pod in the cluster — and the drain family does that once per
// rule, and the placement-concentration rule did it once per pod per workload on every node. On 34,000 pods and
// 3,000 Deployments that is the difference between a sum and a product. The lookups answer exactly what the walks
// answer: where two objects share a namespace and name, the first in inventory order wins, as the walk's early
// return made it.
type ownerIndex struct {
	deployments  map[types2.NamespacedName]*appsv1.Deployment
	statefulSets map[types2.NamespacedName]*appsv1.StatefulSet
}

func newOwnerIndex(inv *collect.Inventory) *ownerIndex {
	x := &ownerIndex{deployments: map[types2.NamespacedName]*appsv1.Deployment{},
		statefulSets: map[types2.NamespacedName]*appsv1.StatefulSet{}}
	for i := range inv.Deployments {
		k := types2.NamespacedName{Namespace: inv.Deployments[i].Namespace, Name: inv.Deployments[i].Name}
		if x.deployments[k] == nil {
			x.deployments[k] = &inv.Deployments[i]
		}
	}
	for i := range inv.StatefulSets {
		k := types2.NamespacedName{Namespace: inv.StatefulSets[i].Namespace, Name: inv.StatefulSets[i].Name}
		if x.statefulSets[k] == nil {
			x.statefulSets[k] = &inv.StatefulSets[i]
		}
	}
	return x
}

// deploymentForReplicaSet is the package function of the same name, by lookup.
func (x *ownerIndex) deploymentForReplicaSet(ns, rsName string) *appsv1.Deployment {
	want, ok := replicaSetDeploymentName(rsName)
	if !ok {
		return nil
	}
	return x.deployments[types2.NamespacedName{Namespace: ns, Name: want}]
}

// chain is ownerChain, by lookup.
func (x *ownerIndex) chain(pod corev1.Pod) []types.OwnerLink {
	return chainVia(pod, x.deploymentForReplicaSet)
}
