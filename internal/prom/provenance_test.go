package prom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// provenance_test.go — B-145's tests. THE TOPOLOGIES ARE THE TEST CASES.
//
// Every one of these is a real deployment the founder named: a plain in-cluster Prometheus, a Thanos
// holding twelve clusters, a central observability cluster reached over a tunnel, and a source with no
// kube-state-metrics at all. The product must reach a DIFFERENT tier on each, and the two that matter most
// are the ones an earlier version would have got wrong in opposite directions: the plain install must be
// PROVEN (a check that fires on the correct case is not a check), and the multi-cluster source must be
// UNPROVEN even though it answers every query perfectly.

// promStub answers PromQL by prefix, so a test states the source's behaviour rather than its wire format.
func promStub(t *testing.T, answers map[string]float64) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q == "" {
			_ = r.ParseForm()
			q = r.Form.Get("query")
		}
		for prefix, v := range answers {
			if strings.HasPrefix(q, prefix) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "success",
					"data": map[string]any{
						"resultType": "vector",
						"result": []any{map[string]any{
							"metric": map[string]string{},
							"value":  []any{0, fmt.Sprintf("%g", v)},
						}},
					},
				})
				return
			}
		}
		// An empty vector: the query was understood and matched nothing.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": []any{}},
		})
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, PromAuth{Mode: AuthNone})
}

func uids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("11111111-2222-3333-4444-%012d", i)
	}
	return out
}

func TestProveCluster_TheTopologies(t *testing.T) {
	ctx := context.Background()

	t.Run("a plain in-cluster Prometheus is PROVEN", func(t *testing.T) {
		// The commonest topology and an entirely correct one. A check that withholds here would withhold
		// usage on most clusters in the world, which is a worse defect than the one it fixes.
		c := promStub(t, map[string]float64{
			`count(kube_pod_info{uid=~`: 40,  // our sampled UIDs are all there
			`count(kube_pod_info)`:      412, // and the source sees only our pods
		})
		p := c.ProveCluster(ctx, uids(412), 412)
		if !p.Proven() {
			t.Errorf("a single-cluster source was not proven: %s — %s", p.Method, p.Detail)
		}
	})

	t.Run("a Thanos holding twelve clusters is UNPROVEN", func(t *testing.T) {
		// B-145 itself. Every query answers perfectly; the containment check passes because our cluster IS
		// in there. Only the exclusivity measurement separates this from the case above.
		c := promStub(t, map[string]float64{
			`count(kube_pod_info{uid=~`: 40,
			`count(kube_pod_info)`:      4900, // ~12 clusters' worth
		})
		p := c.ProveCluster(ctx, uids(412), 412)
		if p.Proven() {
			t.Fatal("a source holding twelve clusters was accepted as this cluster's — this is B-145")
		}
		if p.PodsInSource != 4900 || p.PodsCollected != 412 {
			t.Errorf("the verdict does not carry the numbers it was decided on: %+v", p)
		}
		if !strings.Contains(p.Detail, "4900") || !strings.Contains(p.Detail, "412") {
			t.Errorf("the reason does not state the measurement a reader would need to check it: %s", p.Detail)
		}
	})

	t.Run("a source that does not know this cluster is UNPROVEN", func(t *testing.T) {
		// A central observability cluster reached over a tunnel, pointed at the wrong tenant. It answers,
		// it is healthy, and none of it is ours.
		c := promStub(t, map[string]float64{
			`count(kube_pod_info)`: 900,
			// no answer for the uid matcher: the empty vector falls through
		})
		p := c.ProveCluster(ctx, uids(412), 412)
		if p.Proven() {
			t.Error("a source containing none of this cluster's pods was accepted as this cluster's")
		}
		if !strings.Contains(p.Detail, "UID") && !strings.Contains(p.Detail, "uid") {
			t.Errorf("the reason does not name what failed: %s", p.Detail)
		}
	})

	t.Run("no kube-state-metrics means the tier CANNOT BE PROVEN, which is not the same as wrong", func(t *testing.T) {
		// A bare Prometheus scraping cAdvisor only. Usage queries would work perfectly; there is simply no
		// identifier to prove the source is ours. §6c.2: that is Tier 1b working correctly, not a gap.
		c := promStub(t, map[string]float64{}) // every query returns an empty vector
		p := c.ProveCluster(ctx, uids(412), 412)
		if p.Proven() {
			t.Error("a source with no kube_pod_info at all was accepted as proven")
		}
	})

	t.Run("a cluster moving under the reading is still PROVEN", func(t *testing.T) {
		// The two counts are taken seconds apart against a live cluster, and KSM and the API server
		// disagree briefly during a rollout. A check that cannot tolerate that fires on healthy clusters.
		c := promStub(t, map[string]float64{
			`count(kube_pod_info{uid=~`: 38,
			`count(kube_pod_info)`:      455, // 10% more than collected, mid-rollout
		})
		p := c.ProveCluster(ctx, uids(412), 412)
		if !p.Proven() {
			t.Errorf("a cluster mid-rollout was treated as multi-tenant: %s", p.Detail)
		}
	})

	t.Run("with no pods collected there is nothing to prove WITH", func(t *testing.T) {
		c := promStub(t, map[string]float64{`count(kube_pod_info)`: 412})
		p := c.ProveCluster(ctx, nil, 0)
		if p.Proven() {
			t.Error("proven without any identifier to prove it with")
		}
	})
}

// The tolerance has to separate "same cluster, moving" from "another cluster is in here", and those differ
// by a FACTOR rather than by a percentage. This pins the boundary so a later widening is a decision.
func TestProveCluster_ToleranceSeparatesMovementFromTenancy(t *testing.T) {
	ctx := context.Background()
	const collected = 400
	for _, c := range []struct {
		name     string
		inSource int
		want     bool
	}{
		{"exactly equal", 400, true},
		{"20% more — a rollout", 480, true},
		{"25% more — the boundary", 500, true},
		{"26% more — past it", 504, false},
		{"double — a second cluster", 800, false},
	} {
		cl := promStub(t, map[string]float64{
			`count(kube_pod_info{uid=~`: 40,
			`count(kube_pod_info)`:      float64(c.inSource),
		})
		got := cl.ProveCluster(ctx, uids(collected), collected).Proven()
		if got != c.want {
			t.Errorf("%s: %d in source vs %d collected -> proven=%v, want %v",
				c.name, c.inSource, collected, got, c.want)
		}
	}
}

// The sample is bounded, and bounding it must not change the answer for a cluster larger than the sample.
func TestProveCluster_SamplesUIDsWithoutChangingTheVerdict(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q == "" {
			_ = r.ParseForm()
			q = r.Form.Get("query")
		}
		if strings.HasPrefix(q, `count(kube_pod_info{uid=~`) {
			asked = q
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{"resultType": "vector", "result": []any{map[string]any{
				"metric": map[string]string{}, "value": []any{0, "40"}}}},
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, PromAuth{Mode: AuthNone})
	if !c.ProveCluster(context.Background(), uids(9000), 9000).Proven() {
		t.Error("a 9,000-pod cluster was not proven")
	}
	if n := strings.Count(asked, "|") + 1; n > 40 {
		t.Errorf("the identity query carried %d UIDs; it is bounded to 40 so the URL stays sane", n)
	}
	// DETERMINISTIC: two runs against one cluster must ask the same question, or the check's answer could
	// differ between runs for reasons that have nothing to do with the cluster.
	first := asked
	_ = c.ProveCluster(context.Background(), uids(9000), 9000)
	if asked != first {
		t.Error("two runs against the same cluster asked different identity queries")
	}
}

// The set of providers that need proving must be exactly the set that CAN be wrong. A VPA or
// metrics.k8s.io provider reached through the audited cluster's own kubeconfig has no topology in which it
// answers for a different cluster; a Prometheus URL has many. If this ever inverts — a provider that can be
// misdirected stops implementing the interface — usage from it would be trusted unproven, silently, which
// is B-145 returning under a new name.
func TestClusterProver_IsImplementedByExactlyTheSourcesThatCanBeWrong(t *testing.T) {
	var p any = &promProvider{}
	if _, ok := p.(ClusterProver); !ok {
		t.Error("the Prometheus provider does not implement ClusterProver, so its source would be " +
			"trusted without proof — that is B-145")
	}
	// The in-cluster providers must NOT implement it: a proof requirement on a source that cannot be
	// misdirected would withhold correct figures for no reason.
	for name, v := range map[string]any{
		"vpaProvider":     &vpaProvider{},
		"metricsProvider": &metricsProvider{},
	} {
		if _, ok := v.(ClusterProver); ok {
			t.Errorf("%s implements ClusterProver; it is reached through the audited cluster's own "+
				"kubeconfig and cannot answer for another cluster, so requiring proof of it would "+
				"withhold correct figures", name)
		}
	}
}
