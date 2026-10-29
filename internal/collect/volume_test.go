package collect

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// WHAT A READING READ, IN THE UNITS ANOTHER READER WOULD NEED.
//
// The "what it would take another way" figures — tokens an agent needs just to read the same objects, hours by
// hand — stand on two measured quantities: how many objects this reading read, and how many bytes they occupy
// as `kubectl get -o yaml` prints them. kubectl omits managedFields by default, so this omits them too: on a
// busy cluster they are often the larger half of an object, and counting them would inflate every figure built
// on this one.
func TestVolume_CountsObjectsAndTheBytesKubectlWouldPrint(t *testing.T) {
	big := metav1.ManagedFieldsEntry{Manager: strings.Repeat("kube-controller-manager", 200)}
	inv := &Inventory{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "api", ManagedFields: []metav1.ManagedFieldsEntry{big}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "api-2", Namespace: "api"}},
		},
	}
	v := volumeOf(inv)
	if v == nil {
		t.Fatal("no volume for an inventory that read three objects")
	}
	if v.Objects != 3 {
		t.Errorf("objects = %d, want 3", v.Objects)
	}

	var want int64
	for _, o := range []any{
		corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
		corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "api"}},
		corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-2", Namespace: "api"}},
	} {
		b, err := yaml.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		want += int64(len(b))
	}
	if v.YAMLBytes != want {
		t.Errorf("yaml bytes = %d, want %d — the objects as kubectl prints them, managedFields omitted", v.YAMLBytes, want)
	}
	if len(inv.Pods[0].ManagedFields) != 1 {
		t.Error("measuring the inventory changed it: the pod lost its managedFields")
	}

	counts := map[string]int{}
	for _, k := range v.ByKind {
		counts[k.Kind] = k.Objects
	}
	if len(v.ByKind) != 2 || counts["pods"] != 2 || counts["nodes"] != 1 {
		t.Errorf("by kind = %+v, want pods 2 and nodes 1", v.ByKind)
	}
	if len(v.ByKind) == 2 && v.ByKind[0].Bytes < v.ByKind[1].Bytes {
		t.Errorf("by kind = %+v, want the largest kind first", v.ByKind)
	}
	var sum int64
	for _, k := range v.ByKind {
		sum += k.Bytes
	}
	if sum != v.YAMLBytes {
		t.Errorf("the kinds sum to %d bytes and the total says %d", sum, v.YAMLBytes)
	}
}

// AN EMPTY READ IS NOT A SMALL ONE. A reading that read nothing carries no volume rather than "0 objects,
// 0 bytes", which every figure downstream would turn into "an agent needs 0 tokens".
func TestVolume_NothingReadIsNoVolume(t *testing.T) {
	if v := volumeOf(&Inventory{}); v != nil {
		t.Errorf("volume of an empty inventory = %+v, want nil", v)
	}
}

// THE VOLUME IS THE SAME NUMBER HOWEVER IT IS COMPUTED. Measuring a large cluster's pods is spread over the
// machine's cores; the figure it states must be the serial sum to the byte, because it is printed and kept.
func TestVolume_AParallelMeasureIsTheSerialSum(t *testing.T) {
	pods := make([]corev1.Pod, 3001)
	for i := range pods {
		pods[i] = corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("p", 1+i%40), Namespace: "ns",
			Labels: map[string]string{"app": strings.Repeat("a", i%17)}}, Spec: corev1.PodSpec{NodeName: strings.Repeat("n", i%9)}}
	}
	var want int64
	for _, p := range pods {
		b, err := yaml.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		want += int64(len(b))
	}
	got := measure("pods", pods)
	if got.Objects != len(pods) || got.Bytes != want {
		t.Errorf("measure = %d objects, %d bytes; the serial sum is %d objects, %d bytes", got.Objects, got.Bytes, len(pods), want)
	}
}
