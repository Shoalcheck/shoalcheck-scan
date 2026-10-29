package pipeline

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A SELF-HOSTED TRACKER'S HOSTNAME IS A CUSTOMER IDENTIFIER, AND THE REPORT MUST NOT CARRY IT.
//
// trace.Request gained a Host field so the ticket path's summary can name what it contacted from the
// operator's own terminal. That field must not travel into the report: `jira.acme-payments.internal` names
// the customer, the report is the artifact that leaves their control, and internal/redact tokenizes a
// registry of known strings — a tracker host is in no registry.
//
// The appendix's posture is Resource, Scope and a WHITELIST of discovery routes and nothing else. This test
// is the guard on that posture, asserted against the encoded JSON rather than the struct, because the
// question is what ships.
func TestSessionTrace_NeverCarriesAnExternalHost(t *testing.T) {
	rec := trace.New(nil)
	rt := rec.Wrap(trace.TargetTracker)(okRoundTripper())
	postTo(t, rt, "https://jira.acme-payments.internal/rest/api/3/issue?projectKey=SECRET")
	rt2 := rec.Wrap(trace.TargetAPIServer)(okRoundTripper())
	getFrom(t, rt2, "https://k8s.example/api/v1/pods")

	ar := &types.AuditReport{}
	attachSessionTrace(ar, rec, 0, "")
	st := ar.Methodology.SessionTrace
	if st == nil {
		t.Fatal("no appendix was attached, so this test measured nothing")
	}

	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob := string(b)
	for _, leak := range []string{"jira.acme-payments.internal", "acme-payments", "projectKey", "SECRET", "/rest/api"} {
		if strings.Contains(blob, leak) {
			t.Errorf("the report's session trace carries %q:\n%s", leak, blob)
		}
	}

	// NON-VACUITY: the tracker request must actually be IN the appendix, or "no host" is true because
	// nothing was recorded. A request we issued and did not report is the one thing the trace exists to
	// prevent, so it appears — as a row named for what it is.
	if st.External != 1 {
		t.Errorf("SessionTrace.External = %d, want 1 — the request was dropped from the appendix entirely", st.External)
	}
	if st.ObjectWrites != 0 {
		t.Errorf("SessionTrace.ObjectWrites = %d, want 0 — a POST to a tracker reached the object-write claim", st.ObjectWrites)
	}
	var external, cluster int
	for _, row := range st.Rows {
		if row.Class == "external" {
			external++
			if row.Resource != "tracker" {
				t.Errorf("an external row is named %q, want \"tracker\"", row.Resource)
			}
			if len(row.Paths) != 0 {
				t.Errorf("an external row carries paths %v — the tracker's route is the operator's own path space", row.Paths)
			}
		}
		if row.Class == "read" {
			cluster++
		}
	}
	if external != 1 {
		t.Errorf("%d external row(s) in the appendix, want 1", external)
	}
	if cluster != 1 {
		t.Errorf("%d cluster read row(s), want 1 — the fixture is not the shape this test needs", cluster)
	}
	if st.Total != 2 {
		t.Errorf("SessionTrace.Total = %d, want 2", st.Total)
	}
}

type rtFn func(*http.Request) (*http.Response, error)

func (f rtFn) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okRoundTripper() http.RoundTripper {
	return rtFn(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
}

func postTo(t *testing.T, rt http.RoundTripper, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	req := &http.Request{Method: "POST", URL: u, Header: http.Header{}}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("post %s: %v", raw, err)
	}
}

func getFrom(t *testing.T, rt http.RoundTripper, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	req := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("get %s: %v", raw, err)
	}
}
