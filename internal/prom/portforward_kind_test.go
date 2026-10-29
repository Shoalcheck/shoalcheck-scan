//go:build kind

package prom

import (
	"context"
	"os"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// TestDialServiceProxyFallback_Kind requires a kind cluster with an in-cluster Prometheus Service. It is
// behind the `kind` build tag, so `make ci` never runs it — and until 2026-09-09 nothing else did either.
//
//	make kind-prom-check          # or, by hand:
//	KUBECONFIG=<kind kubeconfig> go test -tags kind ./internal/prom/ \
//	  -run TestDialServiceProxyFallback_Kind -v
//
// THE DEFAULT SERVICE NAME USED TO BE `prometheus-server`, WHICH THIS PROJECT'S OWN TESTBED DOES NOT HAVE.
// `scripts/kind-mesh-up.sh` installs kube-prometheus-stack under the release name `assay-prom`, so the
// service is `assay-prom-kube-prometheus-prometheus`. Anybody following the instruction above got a
// connection failure rather than a result — which is the worst outcome for a test whose whole job is to
// prove a code path works, because the failure looks like the code path being broken.
//
// First live run, 2026-09-09 against `kind-assay-mesh`: LocalURL assigned, a real Ping through it, and
// Close idempotent. The port-forward path is deliberately sensitive here — a port-forward is a `create`,
// which is why `shoalcheck-mcp` refuses `run_audit` — and it had no live verification before this.
func TestDialServiceProxyFallback_Kind(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("set KUBECONFIG to a kind cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	ns := envOr("PROM_NS", "monitoring")
	// The name this repository's own testbed actually creates; see the note above.
	name := envOr("PROM_SVC", "assay-prom-kube-prometheus-prometheus")
	ep := Endpoint{Namespace: ns, Name: name, Port: 9090, Scheme: "http"}

	c, pf, err := DialServiceProxyFallback(cfg, cs, ep)
	if err != nil {
		t.Fatalf("DialServiceProxyFallback: %v", err)
	}
	defer pf.Close()
	if pf.LocalURL == "" {
		t.Fatal("LocalURL must be assigned")
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping over port-forward: %v", err)
	}
	if err := pf.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := pf.Close(); err != nil {
		t.Fatalf("Close idempotent: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
