package pipeline

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A measured run always carries the guard's count, zero included, so a reading made with the guard can say
// "refused nothing" as a measurement. A refused request stays out of Total.
func TestAttachSessionTrace_CarriesTheGuardsCount(t *testing.T) {
	rec := trace.New(nil)
	rt := rec.Wrap(trace.TargetAPIServer)(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}))
	get := func(path string) {
		u, _ := url.Parse("https://k" + path)
		resp, _ := rt.RoundTrip(&http.Request{Method: "GET", URL: u, Header: http.Header{}})
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}

	get("/api/v1/pods")
	clean := &types.AuditReport{}
	attachSessionTrace(clean, rec, 0, "")
	if st := clean.Methodology.SessionTrace; st.Refused == nil || *st.Refused != 0 || st.RefusedKinds != nil {
		t.Fatalf("a clean measured run: Refused=%v kinds=%v, want a non-nil 0 and no kinds", st.Refused, st.RefusedKinds)
	}

	get("/api/v1/namespaces/prod/secrets")
	get("/api/v1/namespaces/prod/pods/api-0/exec")
	refused := &types.AuditReport{}
	attachSessionTrace(refused, rec, 0, "")
	st := refused.Methodology.SessionTrace
	if st.Total != 1 {
		t.Errorf("Total = %d, want 1: refused requests were never issued", st.Total)
	}
	if st.Refused == nil || *st.Refused != 2 || st.RefusedKinds["secrets"] != 1 || st.RefusedKinds["pods/exec"] != 1 {
		t.Errorf("Refused=%v kinds=%v, want 2 with secrets:1 pods/exec:1", st.Refused, st.RefusedKinds)
	}
}
