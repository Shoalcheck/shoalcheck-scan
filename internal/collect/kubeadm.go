package collect

import corev1 "k8s.io/api/core/v1"

// kubeAPIServerKubeadmAnnotation is written by kubeadm into the API server's static pod manifest, and so carried by
// its mirror pod.
const kubeAPIServerKubeadmAnnotation = "kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint"

// kubeadmControlPlane is whether the Nodes and Pods a live collection read show a control plane kubeadm installed: a
// kube-system pod named kube-apiserver-<node>, carrying kubeadm's annotation, owned by a Node — as the kubelet's
// mirror of a static pod is — that this reading collected, with the same UID, and that carries the control-plane role
// label. Read in the bench's kind capture. A managed control plane (EKS, AKS, GKE) runs no API server pod a client can
// list.
//
// WHY THE OWNER'S UID AND ROLE. A pod is the easiest object to write; its owner reference is only a claim. The UID
// ties it to a Node the API server returned in this same reading, and a node-role label is one a kubelet cannot set
// on itself, so a look-alike needs writes to both pods in kube-system and Node labels — which is already more than a
// cluster-admin binding would add.
//
// Called once, at the end of a live Collect, and nowhere else: see Inventory.KubeadmControlPlane.
func kubeadmControlPlane(nodes []corev1.Node, pods []corev1.Pod) bool {
	controlPlane := map[string]string{} // name -> UID
	for _, n := range nodes {
		if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok && n.UID != "" {
			controlPlane[n.Name] = string(n.UID)
		}
	}
	for _, p := range pods {
		if p.Namespace != "kube-system" {
			continue
		}
		if _, ok := p.Annotations[kubeAPIServerKubeadmAnnotation]; !ok {
			continue
		}
		for _, o := range p.OwnerReferences {
			if uid, ok := controlPlane[o.Name]; ok && o.Kind == "Node" && string(o.UID) == uid &&
				p.Name == "kube-apiserver-"+o.Name {
				return true
			}
		}
	}
	return false
}
