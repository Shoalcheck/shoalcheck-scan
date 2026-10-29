package collect

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// deploy builds a Deployment whose pod template carries podLabels.
func deploy(ns, name string, replicas int32, podLabels map[string]string) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
			},
		},
	}
}

// svc builds a Service of the given type with selector sel.
func svc(ns, name string, t corev1.ServiceType, sel map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ServiceSpec{Type: t, Selector: sel},
	}
}

// TestBuildTopologies_SelectorEdge: one namespace, two deployments, one Service
// selecting only one of them → one topology, two workload nodes, one service
// node, exactly one selector edge to the matched workload.
func TestBuildTopologies_SelectorEdge(t *testing.T) {
	inv := &Inventory{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "payments"}}},
		Deployments: []appsv1.Deployment{
			deploy("payments", "api", 3, map[string]string{"app": "api"}),
			deploy("payments", "worker", 2, map[string]string{"app": "worker"}),
		},
		Services: []corev1.Service{
			svc("payments", "api-svc", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}),
		},
	}

	topos := buildTopologies(inv, nil)
	if len(topos) != 1 {
		t.Fatalf("topologies = %d, want 1", len(topos))
	}
	tp := topos[0]
	if tp.Name != "payments" {
		t.Errorf("name = %q, want payments", tp.Name)
	}
	if len(tp.Workloads) != 2 {
		t.Errorf("workloads = %d, want 2", len(tp.Workloads))
	}
	if len(tp.Services) != 1 {
		t.Errorf("services = %d, want 1", len(tp.Services))
	}
	if len(tp.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 (%v)", len(tp.Edges), tp.Edges)
	}
	e := tp.Edges[0]
	if e.Kind != "selector" || e.From != "svc/api-svc" || e.To != "Deployment/api" {
		t.Errorf("edge = %+v, want selector svc/api-svc → Deployment/api", e)
	}

	// Verify the matched workload node id, kind, replicas.
	var api types.WorkloadNode
	for _, w := range tp.Workloads {
		if w.Name == "api" {
			api = w
		}
	}
	if api.ID != "Deployment/api" || api.Kind != "Deployment" || api.Replicas != 3 {
		t.Errorf("api node = %+v, want id=Deployment/api kind=Deployment replicas=3", api)
	}
}

// TestBuildTopologies_SeverityOverlay: a finding referencing a workload tints
// its node with severity + finding id; the highest severity wins.
func TestBuildTopologies_SeverityOverlay(t *testing.T) {
	inv := &Inventory{
		Namespaces:  []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}},
		Deployments: []appsv1.Deployment{deploy("shop", "cart", 1, map[string]string{"app": "cart"})},
	}
	findings := []types.Finding{
		{
			ID:                "f-medium",
			Severity:          types.SeverityMedium,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "shop", Name: "cart"}},
		},
		{
			ID:                "f-critical",
			Severity:          types.SeverityCritical,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "shop", Name: "cart"}},
		},
	}

	topos := buildTopologies(inv, findings)
	if len(topos) != 1 || len(topos[0].Workloads) != 1 {
		t.Fatalf("unexpected shape: %+v", topos)
	}
	w := topos[0].Workloads[0]
	if w.Severity != string(types.SeverityCritical) {
		t.Errorf("severity = %q, want critical (highest wins)", w.Severity)
	}
	if w.FindingID != "f-critical" {
		t.Errorf("findingId = %q, want f-critical", w.FindingID)
	}
}

// TestBuildTopologies_Excludes: system namespaces and namespaces with no
// workloads produce no topology.
func TestBuildTopologies_Excludes(t *testing.T) {
	inv := &Inventory{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "empty"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		},
		Deployments: []appsv1.Deployment{
			// A workload in kube-system must not create a topology.
			deploy("kube-system", "coredns", 2, map[string]string{"app": "coredns"}),
			deploy("app", "web", 1, map[string]string{"app": "web"}),
		},
	}
	topos := buildTopologies(inv, nil)
	if len(topos) != 1 {
		t.Fatalf("topologies = %d, want 1 (only 'app')", len(topos))
	}
	if topos[0].Name != "app" {
		t.Errorf("name = %q, want app", topos[0].Name)
	}
}

// TestBuildTopologies_Determinism: same inventory twice → byte-identical
// (DeepEqual) output.
func TestBuildTopologies_Determinism(t *testing.T) {
	mk := func() *Inventory {
		return &Inventory{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "zeta"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "alpha"}},
			},
			Deployments: []appsv1.Deployment{
				deploy("zeta", "z2", 1, map[string]string{"app": "z2"}),
				deploy("zeta", "z1", 1, map[string]string{"app": "z1"}),
				deploy("alpha", "a1", 1, map[string]string{"app": "a1"}),
			},
			StatefulSets: []appsv1.StatefulSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "alpha"},
					Spec: appsv1.StatefulSetSpec{
						Replicas: ptr32(2),
						Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "db"}}},
					},
				},
			},
			Services: []corev1.Service{
				svc("alpha", "svc-b", corev1.ServiceTypeClusterIP, map[string]string{"app": "a1"}),
				svc("alpha", "svc-a", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "db"}),
			},
		}
	}
	a := buildTopologies(mk(), nil)
	b := buildTopologies(mk(), nil)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("non-deterministic output:\n a=%+v\n b=%+v", a, b)
	}
}

// TestBuildTopologies_ServiceNode: a LoadBalancer Service node gets Type and a
// Note.
func TestBuildTopologies_ServiceNode(t *testing.T) {
	inv := &Inventory{
		Namespaces:  []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "edge"}}},
		Deployments: []appsv1.Deployment{deploy("edge", "gw", 1, map[string]string{"app": "gw"})},
		Services: []corev1.Service{
			svc("edge", "gw-lb", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "gw"}),
		},
	}
	topos := buildTopologies(inv, nil)
	if len(topos) != 1 || len(topos[0].Services) != 1 {
		t.Fatalf("unexpected shape: %+v", topos)
	}
	s := topos[0].Services[0]
	if s.ID != "svc/gw-lb" || s.Kind != "Service" || s.Type != string(corev1.ServiceTypeLoadBalancer) {
		t.Errorf("service node = %+v, want id=svc/gw-lb kind=Service type=LoadBalancer", s)
	}
	if s.Note == "" {
		t.Errorf("LoadBalancer service should carry a Note, got empty")
	}
}

func ptr32(i int32) *int32 { return &i }
