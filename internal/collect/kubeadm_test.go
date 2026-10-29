package collect

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// kubeadm_test.go — THE KUBEADM MARK IS THE LIVE READING'S, AND ONLY ITS (security review of c7a9423b). The rule that
// skips kubeadm's own cluster-admin binding read the mark from the inventory after a pull request's objects were laid
// over it, so a change could carry a forged API server pod and pass its own binding. The mark is now computed once, at
// the end of a live collection, from the Nodes and Pods the API server returned, and requires the pod's owner to be a
// collected control-plane Node with the same UID.

func kubeadmNode(name, uid string, controlPlane bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: k8stypes.UID(uid), Labels: map[string]string{}}}
	if controlPlane {
		n.Labels["node-role.kubernetes.io/control-plane"] = ""
	}
	return n
}

func apiServerPod(node, ownerUID string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "kube-apiserver-" + node,
		Annotations:     map[string]string{"kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint": "172.18.0.5:6443"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: node, UID: k8stypes.UID(ownerUID)}},
	}}
}

func TestCollect_KubeadmControlPlaneIsShownOnlyByAControlPlaneNodesOwnMirrorPod(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *corev1.Node
		pod  *corev1.Pod
		want bool
	}{
		{"kubeadm's mirror pod on its control-plane node", kubeadmNode("cp-0", "u-1", true), apiServerPod("cp-0", "u-1"), true},
		{"an owner UID no collected Node has", kubeadmNode("cp-0", "u-1", true), apiServerPod("cp-0", "u-forged"), false},
		{"an owner Node that is not a control plane", kubeadmNode("cp-0", "u-1", false), apiServerPod("cp-0", "u-1"), false},
		{"no Node at all", nil, apiServerPod("cp-0", "u-1"), false},
		{"a Node and no pod", kubeadmNode("cp-0", "u-1", true), nil, false},
	} {
		cs := fake.NewSimpleClientset()
		if tc.node != nil {
			_ = cs.Tracker().Add(tc.node)
		}
		if tc.pod != nil {
			_ = cs.Tracker().Add(tc.pod)
		}
		inv, err := NewWithClient(cs).Collect(context.Background(), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if inv.KubeadmControlPlane != tc.want {
			t.Errorf("%s: KubeadmControlPlane = %v, want %v", tc.name, inv.KubeadmControlPlane, tc.want)
		}
	}
}

// A REPLAY CARRIES WHAT ITS LIVE COLLECTION SET AND COMPUTES NOTHING: a capture's own objects, or an empty cluster's,
// never become kubeadm evidence by being read back.
func TestCollect_AReplayNeverComputesTheKubeadmMark(t *testing.T) {
	inv := &Inventory{Nodes: []corev1.Node{*kubeadmNode("cp-0", "u-1", true)}, Pods: []corev1.Pod{*apiServerPod("cp-0", "u-1")}}
	got, err := FromInventory(inv).Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.KubeadmControlPlane {
		t.Error("a replayed inventory that did not carry the mark was given one from its own objects")
	}
}
