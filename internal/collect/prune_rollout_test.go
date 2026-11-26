package collect

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// A ROLLOUT'S TEMPLATE IS KEPT FOR ITS RULES AND NEVER WITH AN ENV VALUE (ENG-11): the variable's name stays, its value
// and its valueFrom go, as dropEnvValues does for the kinds read typed.
func TestPruneCR_RolloutTemplateDropsEnvValues(t *testing.T) {
	u := unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"replicas": int64(3), "template": map[string]any{
		"metadata": map[string]any{"labels": map[string]any{"app": "api"}, "annotations": map[string]any{"secret": "s3cr3t-annotation"}},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "img",
			"env": []any{map[string]any{"name": "DB_PASSWORD", "value": "hunter2-literal"},
				map[string]any{"name": "TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "tok", "key": "k"}}}},
			"resources": map[string]any{"requests": map[string]any{"cpu": "1"}}}}}}}}}
	out := PruneCR(schema.GroupResource{Group: "argoproj.io", Resource: "rollouts"}, &u)
	b, _ := json.Marshal(out.Object)
	s := string(b)
	for _, gone := range []string{"hunter2-literal", "secretKeyRef", "s3cr3t-annotation"} {
		if strings.Contains(s, gone) {
			t.Errorf("%q survived the prune: %s", gone, s)
		}
	}
	for _, kept := range []string{`"DB_PASSWORD"`, `"TOKEN"`, `"cpu":"1"`, `"app":"api"`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%s was pruned: %s", kept, s)
		}
	}
}
