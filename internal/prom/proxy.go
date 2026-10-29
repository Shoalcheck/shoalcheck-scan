package prom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/rest"
)

// ConnectMode names how a Client reaches Prometheus. Recorded for the report's
// methodology stamp so the connect path is always disclosed.
type ConnectMode string

const (
	ModeDirectURL    ConnectMode = "direct-url"       // explicit --prometheus-url
	ModeServiceProxy ConnectMode = "api-server-proxy" // GET services/<svc>:<port>/proxy (pure read)
	ModePortForward  ConnectMode = "port-forward"     // create pods/portforward (opt-in)
)

// NewServiceProxyClient returns a Client that targets an in-cluster Service via
// the API server's read-only Service proxy, authenticated with the SAME
// rest.Config used for collection. PromQL queries are GET, so the only verb
// exercised is `get` on services/proxy — no cluster mutation, no stream.
//
//	<host>/api/v1/namespaces/<ns>/services/<scheme>:<name>:<port>/proxy
//
// The base URL is built by string concatenation against cfg.Host, NOT via
// url.Parse/url.JoinPath, which would percent-encode the colons in the
// <scheme>:<name>:<port> segment and break the proxy address. The credentials
// live in the rest.TransportFor round-tripper, so the prom-level PromAuth is
// AuthNone — there is exactly one credential, and it is the kubeconfig's.
func NewServiceProxyClient(cfg *rest.Config, ep Endpoint, opts ...Option) (*Client, error) {
	rt, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(cfg.Host, "/") +
		"/api/v1/namespaces/" + ep.Namespace +
		"/services/" + ep.Scheme + ":" + ep.Name + ":" + strconv.Itoa(int(ep.Port)) +
		"/proxy"
	hc := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	return newClient(base, hc, PromAuth{Mode: AuthNone}, opts...), nil
}

// MaxProbeCandidates bounds how many ranked Services a dialer will try before it gives
// up, so a cluster with a large monitoring stack cannot turn pre-flight into a long wait.
// RankEndpoints already discards the implausible candidates when a plausible one exists,
// so in practice this cap is reached only on unusual clusters — and when it is reached,
// the returned error says so rather than implying nothing was found.
//
// Exported because the OPT-IN port-forward fallback must honour the same bound, and for a
// stronger reason than symmetry: that path issues `create pods/portforward`, the one
// non-read verb this process can send to a cluster. How many non-read verbs a run issues
// must not scale with how many unrelated Services happen to be named like Prometheus — on
// a stock kube-prometheus-stack that is eleven. One exported number rather than two
// matching literals, because two literals drift and the drift is invisible.
const MaxProbeCandidates = 4

// maxProbeCandidates is retained as the package-internal spelling used by the read path.
const maxProbeCandidates = MaxProbeCandidates

// DialFirstServiceProxy returns a Client for the first candidate that actually answers
// the Prometheus API over the API-server service proxy, together with the Endpoint it
// landed on.
//
// This exists because name-based detection cannot be trusted as the final word. A stock
// kube-prometheus-stack install exposes eleven Services whose names contain
// "prometheus" — the operator's webhook on 443, the node-exporter, six scrape-target
// stubs — and picking one of those silently costs the audit every usage dollar and
// downgrades the service map to DECLARED. Ranking orders the guesses; this function
// decides, by asking.
//
// It never mutates anything: the only verb exercised is `get` on services/proxy.
func DialFirstServiceProxy(ctx context.Context, cfg *rest.Config, eps []Endpoint, opts ...Option) (*Client, Endpoint, error) {
	if cfg == nil {
		return nil, Endpoint{}, errors.New("no authenticated rest.Config")
	}
	if len(eps) == 0 {
		return nil, Endpoint{}, errors.New("no Prometheus-compatible Service candidates")
	}

	tried := 0
	var lastErr error
	for _, ep := range eps {
		if tried >= maxProbeCandidates {
			break
		}
		tried++
		c, err := NewServiceProxyClient(cfg, ep, opts...)
		if err != nil {
			lastErr = err
			continue
		}
		if err := c.Ping(ctx); err != nil {
			lastErr = err
			continue
		}
		return c, ep, nil
	}

	suffix := ""
	if tried < len(eps) {
		suffix = fmt.Sprintf(" (stopped after %d of %d candidates)", tried, len(eps))
	}
	if lastErr == nil {
		lastErr = errors.New("unreachable")
	}
	return nil, Endpoint{}, fmt.Errorf("no candidate answered the Prometheus API%s: %w", suffix, lastErr)
}
