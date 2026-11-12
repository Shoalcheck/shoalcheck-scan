package collect

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const leaked = "hunter2-prod-db-password"

// An Argo CD Application the way a real cluster serves it: Helm values inline in the spec, the same values in
// kubectl's last-applied annotation, and again in status.sync.comparedTo. Each is a route the password could
// take into a capture file.
func argoApp() *unstructured.Unstructured {
	values := "db:\n  password: " + leaked + "\n"
	spec := map[string]any{
		"project": "default",
		"source": map[string]any{
			"repoURL": "https://charts.example.com", "chart": "orders",
			"helm": map[string]any{"values": values, "parameters": []any{map[string]any{"name": "token", "value": leaked}}},
		},
	}
	lastApplied, _ := json.Marshal(map[string]any{"spec": spec})
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]any{
			"name": "orders", "namespace": "argocd", "uid": "u-1", "generation": int64(7),
			"resourceVersion":   "991",
			"creationTimestamp": "2026-10-01T10:00:00Z",
			"labels":            map[string]any{"team": "payments"},
			"annotations":       map[string]any{"kubectl.kubernetes.io/last-applied-configuration": string(lastApplied)},
			"managedFields":     []any{map[string]any{"manager": "argocd", "fieldsV1": map[string]any{"f:spec": map[string]any{}}}},
		},
		"spec": spec,
		"status": map[string]any{
			"health": map[string]any{"status": "Degraded", "message": "db " + leaked},
			"sync": map[string]any{"status": "OutOfSync",
				"comparedTo": map[string]any{"source": map[string]any{"helm": map[string]any{"values": values}}}},
		},
	}}
}

func TestPruneCR_KeepsWhatIsReadAndNothingThatCarriesAValue(t *testing.T) {
	in := argoApp()
	spec := in.Object["spec"]
	out := PruneCR(schema.GroupResource{Group: "argoproj.io", Resource: "applications"}, in)

	b, err := json.Marshal(out.Object)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), leaked) {
		t.Fatalf("the pruned object still carries the secret:\n%s", b)
	}
	for _, f := range []string{"labels", "managedFields", "last-applied-configuration", "comparedTo", "message"} {
		if strings.Contains(string(b), f) {
			t.Errorf("the pruned object keeps %q, which nothing reads", f)
		}
	}

	if out.GetName() != "orders" || out.GetNamespace() != "argocd" || out.GetUID() != "u-1" || out.GetGeneration() != 7 ||
		out.GetResourceVersion() != "991" || out.Object["metadata"].(map[string]any)["creationTimestamp"] == nil || out.GetKind() != "Application" {
		t.Errorf("identity fields lost: %v", out.Object["metadata"])
	}
	if s, _, _ := unstructured.NestedString(out.Object, "status", "health", "status"); s != "Degraded" {
		t.Errorf("status.health.status = %q, want Degraded: the Argo analyzer reads it", s)
	}
	if s, _, _ := unstructured.NestedString(out.Object, "status", "sync", "status"); s != "OutOfSync" {
		t.Errorf("status.sync.status = %q, want OutOfSync", s)
	}
	if got, want := out.GetAnnotations()[SpecDigestAnnotation], SpecDigest(spec); got == "" || got != want {
		t.Errorf("spec digest = %q, want %q: the gate tells a changed spec from an unchanged one by it", got, want)
	}
}

// A kind with no rule keeps its identity and nothing else: an analyzer added without declaring its fields
// finds nothing to read, which fails its own tests, rather than a spec reaching a capture unpruned.
func TestPruneCR_AnUndeclaredKindKeepsOnlyItsIdentity(t *testing.T) {
	in := argoApp()
	out := PruneCR(schema.GroupResource{Group: "example.com", Resource: "widgets"}, in)
	if _, ok := out.Object["spec"]; ok {
		t.Error("an undeclared kind kept its spec")
	}
	if _, ok := out.Object["status"]; ok {
		t.Error("an undeclared kind kept its status")
	}
	if out.GetName() != "orders" {
		t.Error("an undeclared kind lost its name")
	}
}

func TestPruneCR_ListsKeepOnlyTheDeclaredFieldsOfEachElement(t *testing.T) {
	in := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]any{"name": "edge", "namespace": "infra"},
		"spec":     map[string]any{"listeners": []any{map[string]any{"name": "https", "tls": map[string]any{"certificateRefs": []any{"x"}}}}},
		"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Programmed", "status": "False", "message": "cert " + leaked}},
			"listeners":  []any{map[string]any{"name": "https", "conditions": []any{map[string]any{"type": "Accepted", "status": "True", "reason": "x"}}}},
		},
	}}
	out := PruneCR(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}, in)
	b, _ := json.Marshal(out.Object)
	if strings.Contains(string(b), leaked) || strings.Contains(string(b), "certificateRefs") {
		t.Fatalf("kept more than declared:\n%s", b)
	}
	conds, _, _ := unstructured.NestedSlice(out.Object, "status", "conditions")
	if len(conds) != 1 || conds[0].(map[string]any)["type"] != "Programmed" || conds[0].(map[string]any)["status"] != "False" {
		t.Errorf("status.conditions = %v, want type and status kept", conds)
	}
	ls, _, _ := unstructured.NestedSlice(out.Object, "status", "listeners")
	if len(ls) != 1 {
		t.Fatalf("status.listeners = %v", ls)
	}
	lc := ls[0].(map[string]any)["conditions"].([]any)
	if lc[0].(map[string]any)["type"] != "Accepted" {
		t.Errorf("listener conditions = %v", lc)
	}
}
