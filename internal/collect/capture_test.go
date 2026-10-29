package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func sampleCapture() *Inventory {
	certs := schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	pods := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	inv := &Inventory{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a",
			Labels: map[string]string{"topology.kubernetes.io/region": "eu-central-1"}}}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}},
		PresentGVRs: GVRSet{
			certs: struct{}{},
			pods:  struct{}{},
		},
		StackObjects: StackObjectMap{certs: {{Object: map[string]interface{}{
			"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
			"metadata": map[string]interface{}{"namespace": "prod", "name": "api-tls"},
		}}}},
	}
	inv.Meta.StartedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	inv.Meta.Collected = []string{"nodes", "namespaces"}
	inv.Meta.Context = "prod-cluster"
	return inv
}

// The two struct-keyed maps are the whole of the problem, and this is the assertion that they round-trip.
func TestCapture_RoundTripsTheStructKeyedMaps(t *testing.T) {
	in := sampleCapture()
	path := filepath.Join(t.TempDir(), "nested", "capture.json")
	if err := SaveCapture(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadCapture(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(out.PresentGVRs) != len(in.PresentGVRs) {
		t.Fatalf("PresentGVRs: %d keys back from %d", len(out.PresentGVRs), len(in.PresentGVRs))
	}
	for gvr := range in.PresentGVRs {
		if !out.PresentGVRs.Has(gvr) {
			t.Errorf("PresentGVRs lost %s", gvr.String())
		}
	}
	if len(out.StackObjects) != len(in.StackObjects) {
		t.Fatalf("StackObjects: %d keys back from %d", len(out.StackObjects), len(in.StackObjects))
	}
	for gvr, objs := range in.StackObjects {
		got := out.StackObjects[gvr]
		if len(got) != len(objs) {
			t.Fatalf("StackObjects[%s]: %d object(s) back from %d", gvr.String(), len(got), len(objs))
		}
		n, _, _ := unstructured.NestedString(got[0].Object, "metadata", "name")
		if n != "api-tls" {
			t.Errorf("the CR came back as %q", n)
		}
	}
	// The core group's empty group name is the case a naive key format loses.
	if !out.PresentGVRs.Has(schema.GroupVersionResource{Version: "v1", Resource: "pods"}) {
		t.Error("the core group's GVR did not survive the key round-trip")
	}
}

// THE READING CLOCK TRAVELS, asserted against the captured value rather than against IsZero(). Both producer
// packages fall back to wall-clock now when it is zero, so a harness that dropped it would re-date every
// window silently — and every clock-anchored finding with it.
func TestCapture_CarriesTheReadingClock(t *testing.T) {
	in := sampleCapture()
	path := filepath.Join(t.TempDir(), "capture.json")
	if err := SaveCapture(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Meta.StartedAt.Equal(in.Meta.StartedAt) {
		t.Errorf("the reading clock came back as %s, want %s", out.Meta.StartedAt, in.Meta.StartedAt)
	}
	if out.Meta.Context != in.Meta.Context {
		t.Errorf("Meta.Context came back as %q", out.Meta.Context)
	}
	if len(out.Meta.Collected) != len(in.Meta.Collected) {
		t.Errorf("Meta.Collected came back with %d entries, want %d", len(out.Meta.Collected), len(in.Meta.Collected))
	}
}

// A CAPTURE FILE HOLDS CLUSTER OBJECTS, so it is written with the history store's posture. A 0644 capture in
// a shared home directory is the kind of defect nobody notices until it matters.
func TestCapture_IsWrittenPrivately(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	path := filepath.Join(dir, "capture.json")
	if err := SaveCapture(path, sampleCapture()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("the capture is mode %o, want 600", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("the capture's directory is mode %o, want 700", perm)
	}
}

// THE FILE'S BYTES ARE STABLE. A set and a map have no order; if either marshalled in map order, two captures
// of one inventory would differ and the file could not be compared or checksummed.
func TestCapture_BytesAreStable(t *testing.T) {
	in := sampleCapture()
	// More keys than one, or there is no order to get wrong.
	in.PresentGVRs[schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}] = struct{}{}
	in.PresentGVRs[schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}] = struct{}{}
	in.StackObjects[schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}] = nil
	first, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		again, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("marshal %d produced different bytes; a struct-keyed map is being written in map order", i)
		}
	}
}

// A malformed key fails loudly rather than dropping a GVR. A capture that silently lost a served resource
// would replay as a cluster where an operator is absent, which is an absence read as a fact.
func TestCapture_RefusesAMalformedKey(t *testing.T) {
	for _, bad := range []string{`["pods"]`, `["/pods"]`, `["v1/"]`, `[""]`} {
		var s GVRSet
		if err := s.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("%s was accepted as a GVR set", bad)
		}
	}
	var m StackObjectMap
	if err := m.UnmarshalJSON([]byte(`{"pods":[]}`)); err == nil {
		t.Error(`{"pods":[]} was accepted as a stack-object map`)
	}
}
