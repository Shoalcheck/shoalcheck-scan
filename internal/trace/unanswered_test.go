package trace

import (
	"errors"
	"net/http"
	"testing"
)

// "21 never got an answer" is a dead end, and this pins the fix.
//
// A real 3-cluster fleet run reported 120 requests: 99 in the audit and 21 before it, with 21 unanswered. The
// operator could not tell from that sentence whether the audit had failed or something before it had — and the
// difference is total. Reproduced, one pre-flight probe of a single unreachable cluster issues exactly 21
// requests and none of them is answered, while all 99 audit requests came back ok. So the honest reading was
// "one cluster you clicked on never replied", and the sentence said something that sounded like data loss.
//
// A count with no attribution is not a measurement anyone can act on, so the tally attributes unanswered round
// trips to their phase and their cluster.
func TestTally_UnansweredRequestsAreAttributed(t *testing.T) {
	r := New(nil)

	// Driven through the recorder's own transport wrapper, so this exercises the same path a real request
	// takes rather than a shortcut into the accounting.
	dead := r.Wrap(TargetAPIServer)(fnRT(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connect: connection refused")
	}))
	alive := r.Wrap(TargetAPIServer)(fnRT(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))

	// Pre-flight against a cluster that does not answer.
	r.SetPhase(PhasePreflight)
	r.SetCluster("aks-somewhere-unreachable")
	for i := 0; i < 3; i++ {
		do(t, dead, "https://k/api/v1/pods")
	}
	// Then a run that works.
	r.SetPhase(PhaseRun)
	r.SetCluster("kind-local")
	for i := 0; i < 5; i++ {
		do(t, alive, "https://k/api/v1/services")
	}

	t.Run("the live tally splits them by phase and names the cluster", func(t *testing.T) {
		got := r.Tally()
		if got.NoResponse != 3 {
			t.Fatalf("NoResponse = %d, want 3", got.NoResponse)
		}
		if got.NoResponsePreflight != 3 {
			t.Errorf("NoResponsePreflight = %d, want 3 — the whole point is that the AUDIT was clean",
				got.NoResponsePreflight)
		}
		if n := got.NoResponseByCluster["aks-somewhere-unreachable"]; n != 3 {
			t.Errorf("NoResponseByCluster[unreachable] = %d, want 3; got map %v", n, got.NoResponseByCluster)
		}
		if _, ok := got.NoResponseByCluster["kind-local"]; ok {
			t.Errorf("a cluster that answered every request appears in the unanswered breakdown: %v",
				got.NoResponseByCluster)
		}
	})

	// The recorder keeps TWO accounting paths — live increments and a recomputation over the stored
	// requests — and this project has already shipped a bug where a field existed in one and not the other.
	// They must agree for every field, not only the ones somebody remembered.
	t.Run("the recomputed tally agrees with the live one", func(t *testing.T) {
		live, recomputed := r.Tally(), r.TallySince(0)
		if live.NoResponse != recomputed.NoResponse ||
			live.NoResponsePreflight != recomputed.NoResponsePreflight {
			t.Errorf("live {%d unanswered, %d in pre-flight} vs recomputed {%d, %d}",
				live.NoResponse, live.NoResponsePreflight, recomputed.NoResponse, recomputed.NoResponsePreflight)
		}
		for k, v := range live.NoResponseByCluster {
			if recomputed.NoResponseByCluster[k] != v {
				t.Errorf("cluster %q: live %d, recomputed %d", k, v, recomputed.NoResponseByCluster[k])
			}
		}
		if len(live.NoResponseByCluster) != len(recomputed.NoResponseByCluster) {
			t.Errorf("breakdown sizes differ: live %v, recomputed %v",
				live.NoResponseByCluster, recomputed.NoResponseByCluster)
		}
	})
}

func do(t *testing.T, rt http.RoundTripper, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if resp, err := rt.RoundTrip(req); err == nil && resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}
