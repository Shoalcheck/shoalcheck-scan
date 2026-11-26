package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A NODE WHOSE DRAIN CAN WAIT AN HOUR FOR ONE POD IS REPORTED WITH THE POD AND THE SERVICE PODS WITHOUT PRESTOP (ENG-33).
func TestNodeDrainDuration_StatesTheLongestWaitAndTheMissingHooks(t *testing.T) {
	hour, short := int64(3600), int64(30)
	pod := func(name, node string, grace *int64, app string, prestop bool) corev1.Pod {
		c := corev1.Container{Name: "c"}
		if prestop {
			c.Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"sleep", "5"}}}}
		}
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, Labels: map[string]string{"app": app}},
			Spec:   corev1.PodSpec{NodeName: node, TerminationGracePeriodSeconds: grace, Containers: []corev1.Container{c}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	inv := &collect.Inventory{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}, {ObjectMeta: metav1.ObjectMeta{Name: "n2"}}},
		Pods: []corev1.Pod{pod("db-0", "n1", &hour, "db", false), pod("web-a", "n1", &short, "web", false),
			pod("web-b", "n1", nil, "web", true), pod("web-c", "n2", nil, "web", false)},
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}}},
	}
	inv.Meta.Collected = []string{"nodes", "pods", "services"}
	fs := NodeDrainDuration{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].IDBasis.Name != "n1" || fs[0].Title != "Draining n1 can wait 1 hour for one pod to stop" {
		t.Fatalf("want n1 only, waiting an hour; got %+v", fs)
	}
	ev := strings.Join(fs[0].Evidence, "\n")
	if !strings.Contains(ev, "is 3600 (1 hour), pod app/db-0") || !strings.Contains(ev, "1 of the 2 pods behind a Service on it has no preStop hook") {
		t.Fatalf("evidence:\n%s", ev)
	}
}
