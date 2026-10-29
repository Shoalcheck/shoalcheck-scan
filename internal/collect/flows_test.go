package collect

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// TestBuildFlows_FromIngress: an Ingress (host → backend Service) whose Service
// selects a Deployment yields a gateway→service→workload flow chain — the
// declared-routing derivation, not the demo fixture.
func TestBuildFlows_FromIngress(t *testing.T) {
	inv := &Inventory{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
				},
			},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-svc", Namespace: "shop"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "web"}},
		}},
		Ingresses: []networkingv1.Ingress{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-ing", Namespace: "shop"},
			Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
				Host: "shop.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web-svc"}},
					}},
				}},
			}}},
		}},
	}

	flows := buildFlows(inv, nil)
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	steps := flows[0].Steps
	if len(steps) < 3 {
		t.Fatalf("want >=3 steps (gateway→service→workload), got %d: %+v", len(steps), steps)
	}
	if steps[0].Kind != "gateway" || steps[0].Label != "shop.example.com" {
		t.Errorf("step0 should be the ingress host gateway, got %+v", steps[0])
	}
	if steps[1].Kind != "service" || steps[1].Label != "web-svc" {
		t.Errorf("step1 should be the backend Service, got %+v", steps[1])
	}
	if steps[2].Label != "web" {
		t.Errorf("step2 should be the selected workload, got %+v", steps[2])
	}
}

// TestBuildFlows_DatastoreTyped: a workload whose name looks like a datastore
// is typed as such (read-only name heuristic).
func TestBuildFlows_DatastoreTyped(t *testing.T) {
	inv := &Inventory{
		StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Name: "postgres-primary", Namespace: "data"},
			Spec: appsv1.StatefulSetSpec{
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "pg"}}},
			},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-svc", Namespace: "data"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "pg"}},
		}},
	}
	flows := buildFlows(inv, nil)
	if len(flows) != 1 {
		t.Fatalf("want 1 LB flow, got %d", len(flows))
	}
	last := flows[0].Steps[len(flows[0].Steps)-1]
	if last.Kind != "datastore" {
		t.Errorf("postgres workload should be typed datastore, got %q", last.Kind)
	}
}

// TestBuildFlows_NoEntries: a cluster with no Ingress and no LoadBalancer/entry
// Service yields no flows (honest — nothing fabricated).
func TestBuildFlows_NoEntries(t *testing.T) {
	inv := &Inventory{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "jobs"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "worker"}}}},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "internal", Namespace: "jobs"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "worker"}},
		}},
	}
	if flows := buildFlows(inv, nil); len(flows) != 0 {
		t.Errorf("want 0 flows for a cluster with no external entry, got %d", len(flows))
	}
	_ = types.FlowDiagram{} // keep types import meaningful across edits
}
