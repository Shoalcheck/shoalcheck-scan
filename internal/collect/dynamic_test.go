package collect

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGVRSetFromLists_PrefersServerVersionAndSkipsSubresources(t *testing.T) {
	lists := []*metav1.APIResourceList{
		{
			GroupVersion: "cert-manager.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "certificates", Namespaced: true, Kind: "Certificate"},
				{Name: "certificates/status", Namespaced: true, Kind: "Certificate"}, // subresource
			},
		},
		{
			// Server PREFERS v1beta1 here — ServerPreferredResources returns one
			// preferred version per group, so the set must carry v1beta1, not v1.
			GroupVersion: "networking.istio.io/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "virtualservices", Namespaced: true, Kind: "VirtualService"},
			},
		},
		{
			GroupVersion: "v1", // core
			APIResources: []metav1.APIResource{
				{Name: "pods", Namespaced: true, Kind: "Pod"},
			},
		},
	}
	set := gvrSetFromLists(lists)

	certGVR := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	if !set.Has(certGVR) {
		t.Errorf("set should contain %v", certGVR)
	}
	statusGVR := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates/status"}
	if set.Has(statusGVR) {
		t.Errorf("set must NOT contain subresource %v", statusGVR)
	}
	istioV1beta1 := schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"}
	if !set.Has(istioV1beta1) {
		t.Errorf("server-preferred version must be recorded: want %v in set", istioV1beta1)
	}
	istioV1 := schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"}
	if set.Has(istioV1) {
		t.Errorf("must not invent the non-served version %v (would 404 on List)", istioV1)
	}
	coreGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if !set.Has(coreGVR) {
		t.Errorf("core GVR %v should be present", coreGVR)
	}
}

func TestGVRSetFromLists_NilSafe(t *testing.T) {
	set := gvrSetFromLists(nil)
	if set == nil {
		t.Fatal("gvrSetFromLists(nil) must return a non-nil empty set, not nil")
	}
	if set.Has(schema.GroupVersionResource{Resource: "anything"}) {
		t.Error("empty set should report no membership")
	}
}

func TestListCR_PaginatesAndReadsUnstructuredInt64(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "widgets"}
	gvk := schema.GroupVersionKind{Group: "example.io", Version: "v1", Kind: "Widget"}

	scheme := runtime.NewScheme()
	// Register the LIST kind so the fake dynamic client returns our objects
	// instead of an empty typed result (fake-clientset version skew guard).
	scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind("WidgetList"), &unstructured.UnstructuredList{})

	objs := make([]runtime.Object, 0, 600)
	for i := 0; i < 600; i++ { // > pageSize(500) forces a Continue page
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		u.SetName(fmt.Sprintf("w-%d", i))
		u.SetNamespace("default")
		// spec.replicas as an int64 — the value a Phase-3 analyzer reads.
		if err := unstructured.SetNestedField(u.Object, int64(7), "spec", "replicas"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		objs = append(objs, u)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{gvr: "WidgetList"},
		objs...,
	)

	c := NewWithClients(nil, dyn, nil)
	got, err := c.ListCR(context.Background(), gvr, metav1.NamespaceAll)
	if err != nil {
		t.Fatalf("ListCR: %v", err)
	}
	if len(got) != 600 {
		t.Fatalf("ListCR returned %d objects, want 600 (pagination dropped a page?)", len(got))
	}
	// The honesty/safety point: read the int64 field via the typed helper.
	replicas, found, err := unstructured.NestedInt64(got[0].Object, "spec", "replicas")
	if err != nil || !found {
		t.Fatalf("NestedInt64(spec.replicas): found=%v err=%v", found, err)
	}
	if replicas != 7 {
		t.Errorf("spec.replicas = %d, want 7", replicas)
	}
}

func TestListCR_NilDynamicClientErrors(t *testing.T) {
	c := NewWithClient(nil) // no dynamic client injected
	_, err := c.ListCR(context.Background(), schema.GroupVersionResource{Resource: "widgets"}, "")
	if err == nil {
		t.Fatal("ListCR with nil dynamic client must return an error, not panic")
	}
}

// fakeDiscoveryFailing wraps the fake discovery client and forces
// ServerPreferredResources to return an ErrGroupDiscoveryFailed (a broken
// aggregated APIService — the common real-cluster case) ALONGSIDE the core
// group that DID resolve.
type fakeDiscoveryFailing struct {
	*fakediscovery.FakeDiscovery
}

func (f *fakeDiscoveryFailing) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	good := []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Namespaced: true, Kind: "Pod"},
				{Name: "services", Namespaced: true, Kind: "Service"},
			},
		},
	}
	err := &discovery.ErrGroupDiscoveryFailed{
		Groups: map[schema.GroupVersion]error{
			{Group: "metrics.k8s.io", Version: "v1beta1"}: fmt.Errorf("the server is currently unable to handle the request"),
		},
	}
	return good, err
}

func TestCollect_PartialDiscoveryIsNonFatal(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
	disco := &fakeDiscoveryFailing{FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &cs.Fake}}

	c := NewWithClients(cs, nil, disco)
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("partial discovery must NOT fail the run: %v", err)
	}
	coreGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if !inv.PresentGVRs.Has(coreGVR) {
		t.Errorf("the groups that DID resolve must still populate PresentGVRs; missing %v", coreGVR)
	}
	gotPartial := false
	for _, g := range inv.Meta.PartialDiscovery {
		if g == "metrics.k8s.io/v1beta1" {
			gotPartial = true
		}
	}
	if !gotPartial {
		t.Errorf("degraded group must be recorded so the report can say 'discovery incomplete'; PartialDiscovery = %v", inv.Meta.PartialDiscovery)
	}
}

func TestPresentGVRs_MembershipGate_AbsentCRDIsFalse(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
	disco := &fakeDiscoveryFailing{FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &cs.Fake}}

	c := NewWithClients(cs, nil, disco)
	inv, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// The fake serves no cert-manager group, so "Istio/cert-manager not present"
	// is a real observation (absent GVR), never an inferred-from-name guess.
	certManagerGVR := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	if inv.PresentGVRs.Has(certManagerGVR) {
		t.Errorf("membership gate must report absent CRD %v as false", certManagerGVR)
	}
}
