package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE VOLUME AND AUTOSCALER SERIES ARE JOINED BY THEIR OWN LABELS, and a claim without a capacity is left out: a
// fill without its denominator is not a fill.
func TestVolumeFillAndAutoscalerHistory_Join(t *testing.T) {
	row := func(m map[string]string, v string) any { return map[string]any{"metric": m, "value": []any{0, v}} }
	pvc := func(name string) map[string]string {
		return map[string]string{"namespace": "data", "persistentvolumeclaim": name}
	}
	hpa := map[string]string{"namespace": "shop", "horizontalpodautoscaler": "api"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		var rows []any
		switch {
		case strings.Contains(q, "capacity_bytes"):
			rows = []any{row(pvc("pg-0"), "1000")}
		case strings.HasPrefix(q, "max by (namespace, persistentvolumeclaim) (kubelet_volume_stats_used_bytes)"):
			rows = []any{row(pvc("pg-0"), "600"), row(pvc("orphan"), "5")}
		case strings.Contains(q, "max_over_time(kubelet_volume_stats_used_bytes"):
			rows = []any{row(pvc("pg-0"), "650")}
		case strings.Contains(q, "deriv("):
			rows = []any{row(pvc("pg-0"), "0.001")}
		case strings.Contains(q, ">= bool"):
			rows = []any{row(hpa, "0.25")}
		case strings.Contains(q, "<= bool"):
			rows = []any{row(hpa, "0.5")}
		case strings.HasPrefix(q, "changes("):
			rows = []any{row(hpa, "12")}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": rows}})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	v, err := c.VolumeFill7d(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v["data/pg-0"].UsedNowBytes != 600 || v["data/pg-0"].UsedMaxBytes != 650 || v["data/pg-0"].GrowthPerDay != 86.4 {
		t.Fatalf("volumes: %+v", v)
	}
	a, err := c.AutoscalerHistory7d(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h := a["shop/api"]; h.AtMaxShare != 0.25 || h.AtMinShare != 0.5 || h.Changes != 12 || h.Name != "api" {
		t.Fatalf("autoscalers: %+v", a)
	}
}
