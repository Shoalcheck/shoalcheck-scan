package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

func webhookConfig(name string, hooks ...map[string]any) unstructured.Unstructured {
	l := make([]any, len(hooks))
	for i, h := range hooks {
		l[i] = h
	}
	u := unstructured.Unstructured{Object: map[string]any{"webhooks": l}}
	u.SetName(name)
	return u
}

func hook(name, policy, ns, svc string) map[string]any {
	h := map[string]any{"name": name, "rules": []any{map[string]any{"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"pods"}}}}
	if policy != "" {
		h["failurePolicy"] = policy
	}
	if svc != "" {
		h["clientConfig"] = map[string]any{"service": map[string]any{"namespace": ns, "name": svc}}
	} else {
		h["clientConfig"] = map[string]any{}
	}
	return h
}

func readySlice(ns, svc string, nodes ...string) discoveryv1.EndpointSlice {
	t := true
	s := discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: svc + "-x",
		Labels: map[string]string{discoveryv1.LabelServiceName: svc}}, AddressType: discoveryv1.AddressTypeIPv4}
	for i, n := range nodes {
		node := n
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{Addresses: []string{"10.0.0." + string(rune('1'+i))},
			Conditions: discoveryv1.EndpointConditions{Ready: &t}, NodeName: &node})
	}
	return s
}

// A FAIL-CLOSED WEBHOOK WITH NO READY ENDPOINT, OR WITH EVERY ONE ON ONE NODE, IS REPORTED; ONE THAT FAILS OPEN, ONE
// CALLED BY URL AND ONE SPREAD OVER NODES ARE NOT (ENG-41).
func TestWebhookUnbacked(t *testing.T) {
	svc := func(ns, name string) corev1.Service {
		return corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": name}}}
	}
	inv := &collect.Inventory{
		Services:       []corev1.Service{svc("policy", "dead"), svc("policy", "lonely"), svc("policy", "spread"), svc("policy", "open")},
		EndpointSlices: []discoveryv1.EndpointSlice{readySlice("policy", "lonely", "n1", "n1"), readySlice("policy", "spread", "n1", "n2")},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{
			gvrValidatingWebhooks: {webhookConfig("policy-hooks", hook("dead.policy", "", "policy", "dead"),
				hook("lonely.policy", "Fail", "policy", "lonely"), hook("spread.policy", "Fail", "policy", "spread"),
				hook("open.policy", "Ignore", "policy", "open"), hook("url.policy", "Fail", "", ""))},
		},
	}
	inv.Meta.Collected = []string{"services", "endpointslices", crKind(gvrValidatingWebhooks)}
	fs := WebhookUnbacked{}.Evaluate(inv, Options{})
	got := map[string]string{}
	for _, f := range fs {
		got[f.Title] = string(f.Severity)
	}
	if len(fs) != 2 || got["Webhook dead.policy fails closed with no ready endpoint behind it"] != "high" ||
		got["Webhook lonely.policy fails closed and every ready endpoint is on node n1"] != "medium" {
		t.Fatalf("findings: %v", got)
	}
	if ev := strings.Join(fs[0].Evidence, "\n"); !strings.Contains(ev, "CREATE, UPDATE of pods") {
		t.Errorf("what it intercepts is not said:\n%s", ev)
	}
	// Not read: nothing said.
	inv.Meta.Collected = []string{"services", "endpointslices"}
	if fs := (WebhookUnbacked{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Fatalf("webhooks not read, %d findings", len(fs))
	}
}

// AN AGGREGATED APISERVICE THAT IS NOT AVAILABLE IS REPORTED WITH ITS REASON; A LOCAL ONE IS NOT (ENG-42).
func TestAPIServiceUnavailable(t *testing.T) {
	api := func(name, svc, status, reason string) unstructured.Unstructured {
		u := unstructured.Unstructured{Object: map[string]any{
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Available", "status": status, "reason": reason}}}}}
		if svc != "" {
			u.Object["spec"] = map[string]any{"service": map[string]any{"namespace": "kube-system", "name": svc}}
		}
		u.SetName(name)
		return u
	}
	inv := &collect.Inventory{StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{gvrAPIServices: {
		api("v1beta1.metrics.k8s.io", "metrics-server", "False", "MissingEndpoints"),
		api("v1.apps", "", "False", ""),
		api("v1beta1.custom.metrics.k8s.io", "adapter", "True", "Passed"),
	}}}
	inv.Meta.Collected = []string{crKind(gvrAPIServices)}
	fs := APIServiceUnavailable{}.Evaluate(inv, Options{})
	if len(fs) != 1 || !strings.Contains(fs[0].Description, "Available=False (MissingEndpoints)") {
		t.Fatalf("findings: %+v", fs)
	}
}
