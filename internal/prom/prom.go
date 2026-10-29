// Package prom is a minimal Prometheus HTTP API client for usage queries.
package prom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

// Client is a minimal Prometheus HTTP API client.
type Client struct {
	baseURL string
	http    *http.Client
	auth    PromAuth
}

// Option configures a Client at construction.
type Option func(*clientOptions)

type clientOptions struct {
	recorder recorderInstaller
}

// recorderInstaller is the narrow shape needed from a request recorder, kept as a local interface so this
// package's signatures do not name internal/trace.
type recorderInstaller interface {
	Wrap(trace.Target) func(http.RoundTripper) http.RoundTripper
}

// WithTransportRecorder makes every request this Client sends countable.
//
// It is needed because a rest.Config recorder cannot see these requests at all. Under --prometheus-url the
// client talks straight to an operator-supplied endpoint, and under the opt-in port-forward it talks to a
// local socket — in both cases through a plain http.Client whose nil Transport means http.DefaultTransport,
// which no client-go wrapper touches. Without this, the identical audit reports wildly different request
// totals depending only on how it happened to reach Prometheus.
//
// In service-proxy mode the transport ALREADY carries the recorder from underneath (it is built from the
// collector's own rest.Config), and the recorder's chain walk returns it unchanged rather than counting
// twice. That is deliberately handled inside the recorder rather than by this call site deciding which
// mode it is in: a call site that has to remember drifts.
func WithTransportRecorder(r recorderInstaller) Option {
	return func(o *clientOptions) { o.recorder = r }
}

// newClient is the transport-injection seam and the ONLY constructor of a *Client, which is what makes it
// the single place a Prometheus recorder has to be installed. 10s default timeout when hc is nil.
func newClient(baseURL string, hc *http.Client, auth PromAuth, opts ...Option) *Client {
	var o clientOptions
	for _, fn := range opts {
		fn(&o)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	if o.recorder != nil {
		// A nil Transport means http.DefaultTransport, so name it explicitly rather than wrapping nil.
		base := hc.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		wrapped := *hc // do not mutate a caller's client
		wrapped.Transport = o.recorder.Wrap(trace.TargetPrometheus)(base)
		hc = &wrapped
	}
	return &Client{baseURL: baseURL, http: hc, auth: auth}
}

// NewClient returns a Client targeting baseURL (e.g. "http://127.0.0.1:9090")
// with the given auth applied to every request. A 10-second timeout is applied.
func NewClient(baseURL string, auth PromAuth, opts ...Option) *Client {
	return newClient(baseURL, nil, auth, opts...)
}

// NewClientWithTimeout returns a Client whose per-request budget is d. Mesh
// aggregation (sum(rate(...)) by (8 labels) over a 5m+ window) is heavier than
// the usage queries, so the service-map caller uses 30s here, not the 10s
// default NewClient applies. Everything else — Ping, Query, the auth handling,
// the Prometheus HTTP API contract — is identical.
func NewClientWithTimeout(baseURL string, auth PromAuth, d time.Duration, opts ...Option) *Client {
	return newClient(baseURL, &http.Client{Timeout: d}, auth, opts...)
}

// Ping verifies the endpoint speaks the Prometheus HTTP API.
// It first tries GET /api/v1/status/buildinfo (Prometheus ≥ 2.14 and compatible
// forks) and falls back to GET /-/ready (plain 2xx). Either a 2xx on buildinfo
// or a 2xx on /-/ready satisfies the check.
func (c *Client) Ping(ctx context.Context) error {
	if err := c.pingBuildInfo(ctx); err == nil {
		return nil
	}
	return c.pingReady(ctx)
}

func (c *Client) pingBuildInfo(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/status/buildinfo", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("buildinfo returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) pingReady(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/-/ready", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("/-/ready returned HTTP %d; endpoint does not appear to be a Prometheus-compatible API", resp.StatusCode)
	}
	return nil
}

// Sample is one element of an instant query vector result.
type Sample struct {
	// Metric holds the label set (including __name__ when present).
	Metric map[string]string
	// Value is the sample's numeric value.
	Value float64
}

// queryResponse is the envelope returned by /api/v1/query.
type queryResponse struct {
	Status    string          `json:"status"`
	ErrorType string          `json:"errorType,omitempty"`
	Error     string          `json:"error,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type queryData struct {
	ResultType string            `json:"resultType"`
	Result     []json.RawMessage `json:"result"`
}

type vectorSample struct {
	Metric map[string]string `json:"metric"`
	// Value is [unixTimestamp, stringValue] per the Prometheus API spec.
	Value []json.RawMessage `json:"value"`
}

// Query runs an instant PromQL query (GET /api/v1/query?query=...) and returns
// the result vector as []Sample. It returns an error if:
//   - the response status is not "success", or
//   - the resultType is not "vector".
func (c *Client) Query(ctx context.Context, promql string) ([]Sample, error) {
	endpoint := c.baseURL + "/api/v1/query?query=" + url.QueryEscape(promql)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("prom: build request: %w", err)
	}
	if cav := c.auth.apply(req); cav != "" {
		// Non-fatal: the request is sent as prepared; the unmet-auth caveat is
		// surfaced via Methodology by the resolver, not here.
		_ = cav
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prom: query request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("prom: read body: %w", err)
	}

	var qr queryResponse
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("prom: parse response: %w", err)
	}
	if qr.Status != "success" {
		return nil, fmt.Errorf("prom: query failed: %s: %s", qr.ErrorType, qr.Error)
	}

	var data queryData
	if err := json.Unmarshal(qr.Data, &data); err != nil {
		return nil, fmt.Errorf("prom: parse data: %w", err)
	}
	if data.ResultType != "vector" {
		return nil, fmt.Errorf("prom: expected resultType=vector, got %q", data.ResultType)
	}

	samples := make([]Sample, 0, len(data.Result))
	for i, raw := range data.Result {
		var vs vectorSample
		if err := json.Unmarshal(raw, &vs); err != nil {
			return nil, fmt.Errorf("prom: parse sample[%d]: %w", i, err)
		}
		if len(vs.Value) < 2 {
			return nil, fmt.Errorf("prom: sample[%d] value tuple too short", i)
		}
		// Value[1] is a quoted string per the Prometheus API spec.
		var valStr string
		if err := json.Unmarshal(vs.Value[1], &valStr); err != nil {
			return nil, fmt.Errorf("prom: sample[%d] parse value string: %w", i, err)
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			return nil, fmt.Errorf("prom: sample[%d] parse float %q: %w", i, valStr, err)
		}
		samples = append(samples, Sample{Metric: vs.Metric, Value: v})
	}
	return samples, nil
}
