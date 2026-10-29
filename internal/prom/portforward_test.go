package prom

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestPortForward_CloseIdempotent asserts Close() is safe to call twice (a
// double-close on the stop channel must not panic). A leaked forward keeps an
// API-server stream open, so Close must always run, even on the error path.
func TestPortForward_CloseIdempotent(t *testing.T) {
	pf := &PortForward{stop: make(chan struct{}), done: make(chan struct{})}
	close(pf.done) // simulate the forward goroutine having exited
	if err := pf.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pf.Close(); err != nil {
		t.Fatalf("second Close (idempotent) must not error: %v", err)
	}
}

// TestPortForward_CloseNil asserts a nil *PortForward Close is a no-op (callers
// defer pf.Close() even on the error path where pf may be nil).
func TestPortForward_CloseNil(t *testing.T) {
	var pf *PortForward
	if err := pf.Close(); err != nil {
		t.Fatalf("nil Close must be a no-op: %v", err)
	}
}

// TestReadyEndpointPod picks a Ready endpoint pod's name/namespace from an
// EndpointSlice, skipping not-ready addresses.
func TestReadyEndpointPod(t *testing.T) {
	ready := true
	notReady := false
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "monitoring", Name: "prometheus-abc"},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: &notReady},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "monitoring", Name: "prometheus-0"}},
			{Conditions: discoveryv1.EndpointConditions{Ready: &ready},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "monitoring", Name: "prometheus-1"}},
		},
	}
	ns, name, ok := readyEndpointPod([]discoveryv1.EndpointSlice{*slice})
	if !ok {
		t.Fatal("must find a ready pod")
	}
	if ns != "monitoring" || name != "prometheus-1" {
		t.Errorf("got %s/%s, want monitoring/prometheus-1", ns, name)
	}
}

// TestReadyEndpointPod_NoneReady returns ok=false when every endpoint is
// not-ready, so the fallback fails honestly rather than forwarding to a dead pod.
func TestReadyEndpointPod_NoneReady(t *testing.T) {
	notReady := false
	slice := discoveryv1.EndpointSlice{
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: &notReady},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "monitoring", Name: "prometheus-0"}},
		},
	}
	if _, _, ok := readyEndpointPod([]discoveryv1.EndpointSlice{slice}); ok {
		t.Error("must not find a ready pod when all are not-ready")
	}
}
