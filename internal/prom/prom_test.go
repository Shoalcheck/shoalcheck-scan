package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// buildInfoResponse is the /api/v1/status/buildinfo response shape.
func serveBuildInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   map[string]any{"version": "2.45.0"},
	})
}

// readyResponse is the /-/ready response shape (plain 200).
func serveReady(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Prometheus is Ready.\n"))
}

// serve404 always returns 404 — simulates an endpoint that doesn't speak Prometheus.
func serve404(w http.ResponseWriter, _ *http.Request) {
	http.NotFound(w, nil)
}

func TestQueryAppliesAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": []any{}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthBearerStatic, Token: "abc"})
	if _, err := c.Query(context.Background(), "up"); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if gotAuth != "Bearer abc" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer abc")
	}
}

func TestPing_BuildInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status/buildinfo" {
			serveBuildInfo(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping via buildinfo: %v", err)
	}
}

func TestPing_Ready(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/ready":
			serveReady(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping via /-/ready fallback: %v", err)
	}
}

func TestPing_404Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(serve404))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("Ping to 404-only server must return an error")
	}
}

func vectorResponse(metric map[string]string, value float64) map[string]any {
	return map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "vector",
			"result": []any{
				map[string]any{
					"metric": metric,
					"value":  []any{1718000000, "42.5"},
				},
			},
		},
	}
}

func TestQuery_SuccessVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query().Get("query")
		if q == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vectorResponse(
			map[string]string{"__name__": "up", "job": "prometheus"},
			42.5,
		))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	samples, err := c.Query(context.Background(), `up{job="prometheus"}`)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("want 1 sample, got %d", len(samples))
	}
	if samples[0].Value != 42.5 {
		t.Errorf("value = %v, want 42.5", samples[0].Value)
	}
	if samples[0].Metric["job"] != "prometheus" {
		t.Errorf("metric label job = %q, want prometheus", samples[0].Metric["job"])
	}
}

func TestQuery_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":    "error",
			"errorType": "bad_data",
			"error":     "invalid expression",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	_, err := c.Query(context.Background(), `{bad query`)
	if err == nil {
		t.Fatal("error status from Prometheus must return an error")
	}
}

func TestQuery_NonVectorResultType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "matrix",
				"result":     []any{},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	_, err := c.Query(context.Background(), `rate(up[5m])`)
	if err == nil {
		t.Fatal("non-vector resultType must return an error")
	}
}

func TestQuery_EmptyVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result":     []any{},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	samples, err := c.Query(context.Background(), `up`)
	if err != nil {
		t.Fatalf("empty vector must not error: %v", err)
	}
	if len(samples) != 0 {
		t.Errorf("want 0 samples for empty vector, got %d", len(samples))
	}
}

func TestNewClientWithTimeout_QueriesLikeDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vectorResponse(map[string]string{"__name__": "up"}, 1))
	}))
	defer srv.Close()

	c := NewClientWithTimeout(srv.URL, PromAuth{Mode: AuthNone}, 30*time.Second)
	samples, err := c.Query(context.Background(), "up")
	if err != nil {
		t.Fatalf("Query via NewClientWithTimeout: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("want 1 sample, got %d", len(samples))
	}
}
