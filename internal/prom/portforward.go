package prom

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForward holds a live in-process forward to a single pod port. Close() stops
// it. Establishing it exercises `create` on pods/portforward — this does NOT
// mutate the cluster (it opens a proxied stream, the same primitive Lens/k9s
// use), but security teams see a non-read verb, so it is OPT-IN and disclosed
// (ConnectMode == ModePortForward).
type PortForward struct {
	LocalURL string
	stop     chan struct{}
	done     chan struct{}
	closed   bool
}

// Close stops the forward. It is idempotent: a second call (and a nil receiver)
// is a no-op. A leaked forward keeps an API-server stream open, so callers must
// always defer Close.
func (p *PortForward) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	close(p.stop)
	if p.done != nil {
		<-p.done
	}
	return nil
}

// readyEndpointPod returns the namespace/name of the first Ready endpoint pod
// across the given slices, or ok=false when none are ready.
func readyEndpointPod(slices []discoveryv1.EndpointSlice) (ns, name string, ok bool) {
	for _, s := range slices {
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.TargetRef.Name != "" {
				return ep.TargetRef.Namespace, ep.TargetRef.Name, true
			}
		}
	}
	return "", "", false
}

// DialServiceProxyFallback opens an in-process port-forward to a Ready pod
// backing the Service and returns a *Client over http://127.0.0.1:<assigned>.
// Used ONLY when the service-proxy is blocked (opt-in). Callers must defer
// pf.Close(). It exercises `create pods/portforward` + read of EndpointSlices.
func DialServiceProxyFallback(cfg *rest.Config, cs kubernetes.Interface, ep Endpoint, opts ...Option) (*Client, *PortForward, error) {
	ctx := context.Background()
	slices, err := cs.DiscoveryV1().EndpointSlices(ep.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + ep.Name,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("port-forward: list endpointslices: %w", err)
	}
	podNS, podName, ok := readyEndpointPod(slices.Items)
	if !ok {
		return nil, nil, fmt.Errorf("port-forward: no ready endpoint pod for service %s/%s", ep.Namespace, ep.Name)
	}

	roundTripper, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("port-forward: spdy roundtripper: %w", err)
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", podNS, podName)
	hostURL, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("port-forward: parse host: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost,
		&url.URL{Scheme: hostURL.Scheme, Host: hostURL.Host, Path: path})

	stop := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan struct{})
	fw, err := portforward.New(dialer,
		[]string{"0:" + strconv.Itoa(int(ep.Port))}, stop, ready, io.Discard, io.Discard)
	if err != nil {
		return nil, nil, fmt.Errorf("port-forward: new forwarder: %w", err)
	}
	errc := make(chan error, 1)
	go func() {
		defer close(done)
		errc <- fw.ForwardPorts()
	}()
	select {
	case <-ready:
	case ferr := <-errc:
		close(stop)
		return nil, nil, fmt.Errorf("port-forward: forward failed: %w", ferr)
	}
	ports, err := fw.GetPorts()
	if err != nil || len(ports) == 0 {
		close(stop)
		<-done
		return nil, nil, fmt.Errorf("port-forward: read assigned port: %w", err)
	}
	local := "http://127.0.0.1:" + strconv.Itoa(int(ports[0].Local))
	pf := &PortForward{LocalURL: local, stop: stop, done: done}
	// The tunnel's local socket is a plain http.Client with no client-go transport anywhere near it, so
	// it needs its own recorder. The SPDY upgrade itself was already recorded by the rest.Config
	// recorder — as `create pods/portforward`, ClassStream — because spdy.RoundTripperFor runs the
	// config's wrappers. What is NOT counted per request is the traffic inside the tunnel after the 101:
	// those are SPDY frames on a hijacked connection, not HTTP requests, which is why the appendix says
	// one stream was opened rather than implying every query through it was individually observed.
	return NewClient(local, PromAuth{Mode: AuthNone}, opts...), pf, nil
}
