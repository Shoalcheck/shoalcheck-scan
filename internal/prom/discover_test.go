package prom

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func svc(ns, name string, labels map[string]string, ports []corev1.ServicePort) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Ports: ports,
		},
	}
}

func namedPort(name string, port int32) corev1.ServicePort {
	return corev1.ServicePort{
		Name:       name,
		Port:       port,
		TargetPort: intstr.FromInt(int(port)),
	}
}

func numericPort(port int32) corev1.ServicePort {
	return corev1.ServicePort{
		Port:       port,
		TargetPort: intstr.FromInt(int(port)),
	}
}

func TestDetect_KubePrometheusStack(t *testing.T) {
	// Typical kube-prometheus-stack service in monitoring namespace.
	services := []corev1.Service{
		svc("monitoring", "kube-prometheus-stack-prometheus", nil,
			[]corev1.ServicePort{namedPort("http-web", 9090)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("kube-prometheus-stack service must be detected")
	}
	if !strings.Contains(hint, "monitoring") {
		t.Errorf("hint must mention the namespace: %s", hint)
	}
	if !strings.Contains(hint, "9090") {
		t.Errorf("hint must mention port 9090: %s", hint)
	}
	if !strings.Contains(hint, "port-forward") {
		t.Errorf("hint must include port-forward command: %s", hint)
	}
}

func TestDetect_VictoriaMetrics(t *testing.T) {
	services := []corev1.Service{
		svc("observability", "vmselect", nil,
			[]corev1.ServicePort{namedPort("http", 8481)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("vmselect service must be detected")
	}
	if !strings.Contains(hint, "observability") {
		t.Errorf("hint must mention the namespace: %s", hint)
	}
	if !strings.Contains(hint, "8481") {
		t.Errorf("hint must mention port 8481: %s", hint)
	}
}

func TestDetect_NoMatch(t *testing.T) {
	services := []corev1.Service{
		svc("default", "my-api", nil,
			[]corev1.ServicePort{namedPort("http", 8080)}),
		svc("kube-system", "kube-dns", nil,
			[]corev1.ServicePort{namedPort("dns", 53)}),
	}
	found, hint := Detect(services)
	if found {
		t.Errorf("no prometheus-compatible service should produce found=false, got hint=%q", hint)
	}
	if hint != "" {
		t.Errorf("hint must be empty when not found, got %q", hint)
	}
}

func TestDetect_LabelOnlyMatch(t *testing.T) {
	// Service name doesn't match, but label app.kubernetes.io/name does.
	services := []corev1.Service{
		svc("monitoring", "observability-svc", map[string]string{
			"app.kubernetes.io/name": "prometheus",
		}, []corev1.ServicePort{numericPort(9090)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("label-only match must be detected (app.kubernetes.io/name=prometheus)")
	}
	if !strings.Contains(hint, "9090") {
		t.Errorf("hint must mention port 9090: %s", hint)
	}
}

func TestDetect_PreferredNamespace(t *testing.T) {
	// Two matches: prefer monitoring namespace over random namespace.
	services := []corev1.Service{
		svc("random-ns", "prometheus", nil,
			[]corev1.ServicePort{namedPort("web", 9090)}),
		svc("monitoring", "prometheus-server", nil,
			[]corev1.ServicePort{namedPort("http", 9090)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("should detect prometheus service")
	}
	// The monitoring-namespace variant should be preferred.
	if !strings.Contains(hint, "monitoring") {
		t.Errorf("monitoring namespace should be preferred, hint = %s", hint)
	}
}

func TestDetect_FallbackPort9090(t *testing.T) {
	// Service has no named port — should fall back to default port 9090.
	services := []corev1.Service{
		svc("default", "prometheus", nil,
			[]corev1.ServicePort{numericPort(9090)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("prometheus-named service must be detected")
	}
	if !strings.Contains(hint, "9090") {
		t.Errorf("should use port 9090: %s", hint)
	}
}

func TestDetect_MimirQueryFrontend(t *testing.T) {
	services := []corev1.Service{
		svc("observability", "mimir-query-frontend", nil,
			[]corev1.ServicePort{namedPort("http", 8080)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("mimir-query service must be detected")
	}
	_ = hint
}

func TestDetect_ThanosQuery(t *testing.T) {
	services := []corev1.Service{
		svc("monitoring", "thanos-query", nil,
			[]corev1.ServicePort{namedPort("http", 10902)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("thanos-query service must be detected")
	}
	if !strings.Contains(hint, "10902") {
		t.Errorf("hint must mention port 10902: %s", hint)
	}
}

func TestDetectEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		services  []corev1.Service
		wantFound bool
		wantNS    string
		wantName  string
		wantPort  int32
		wantSchem string
	}{
		{
			name: "preferred namespace beats non-preferred",
			services: []corev1.Service{
				svc("random-ns", "prometheus", nil, []corev1.ServicePort{namedPort("web", 9090)}),
				svc("monitoring", "prometheus-server", nil, []corev1.ServicePort{namedPort("http", 9090)}),
			},
			wantFound: true, wantNS: "monitoring", wantName: "prometheus-server", wantPort: 9090, wantSchem: "http",
		},
		{
			name: "named http port wins over numeric default",
			services: []corev1.Service{
				svc("monitoring", "kube-prometheus-stack-prometheus", nil,
					[]corev1.ServicePort{namedPort("http-web", 9090), numericPort(9091)}),
			},
			wantFound: true, wantNS: "monitoring", wantName: "kube-prometheus-stack-prometheus", wantPort: 9090, wantSchem: "http",
		},
		{
			name: "scheme https for port named https",
			services: []corev1.Service{
				svc("monitoring", "prometheus", nil, []corev1.ServicePort{namedPort("https", 9090)}),
			},
			wantFound: true, wantNS: "monitoring", wantName: "prometheus", wantPort: 9090, wantSchem: "https",
		},
		{
			name: "scheme https for port 443",
			services: []corev1.Service{
				svc("monitoring", "prometheus", nil, []corev1.ServicePort{numericPort(443)}),
			},
			wantFound: true, wantNS: "monitoring", wantName: "prometheus", wantPort: 443, wantSchem: "https",
		},
		{
			name:      "no candidate",
			services:  []corev1.Service{svc("default", "my-api", nil, []corev1.ServicePort{namedPort("http", 8080)})},
			wantFound: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, found := DetectEndpoint(tc.services)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if ep.Namespace != tc.wantNS || ep.Name != tc.wantName || ep.Port != tc.wantPort || ep.Scheme != tc.wantSchem {
				t.Errorf("endpoint = %+v, want ns=%s name=%s port=%d scheme=%s",
					ep, tc.wantNS, tc.wantName, tc.wantPort, tc.wantSchem)
			}
		})
	}
}

// TestDetectHintUnchanged is the regression guard on the frozen Detect signature:
// Detect still returns the same hint string after being reimplemented on DetectEndpoint.
func TestDetectHintUnchanged(t *testing.T) {
	services := []corev1.Service{
		svc("monitoring", "kube-prometheus-stack-prometheus", nil,
			[]corev1.ServicePort{namedPort("http-web", 9090)}),
	}
	found, hint := Detect(services)
	if !found {
		t.Fatal("Detect must still find the service")
	}
	for _, want := range []string{"monitoring", "9090", "port-forward", "--prometheus-url"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint missing %q: %s", want, hint)
		}
	}
}

// --- regression: the real kube-prometheus-stack service set (B-002) ---------------
//
// The pre-existing TestDetect_KubePrometheusStack passes because its fixture holds a
// SINGLE service. A real `helm install kube-prometheus-stack` creates eleven, and
// several of them contain the substring "prometheus" while being nothing of the sort:
// the operator's webhook service, the node-exporter, and six scrape-target stubs in
// kube-system. Captured live from a stock chart install (release name "kps"),
// in the order the API server returns them.
func kubePrometheusStackServices() []corev1.Service {
	return []corev1.Service{
		// kube-system scrape-target stubs — all match the "prometheus" keyword.
		svc("kube-system", "kps-kube-prometheus-coredns", nil,
			[]corev1.ServicePort{namedPort("http-metrics", 9153)}),
		svc("kube-system", "kps-kube-prometheus-kube-controller-manager", nil,
			[]corev1.ServicePort{namedPort("http-metrics", 10257)}),
		svc("kube-system", "kps-kube-prometheus-kube-etcd", nil,
			[]corev1.ServicePort{namedPort("http-metrics", 2381)}),
		svc("kube-system", "kps-kube-prometheus-kube-proxy", nil,
			[]corev1.ServicePort{namedPort("http-metrics", 10249)}),
		svc("kube-system", "kps-kube-prometheus-kube-scheduler", nil,
			[]corev1.ServicePort{namedPort("http-metrics", 10259)}),
		svc("kube-system", "kps-kube-prometheus-kubelet",
			map[string]string{"app.kubernetes.io/name": "kubelet"},
			[]corev1.ServicePort{namedPort("https-metrics", 10250), namedPort("cadvisor", 4194), namedPort("http-metrics", 10255)}),
		// monitoring — alphabetically the operator sorts BEFORE prometheus, which is
		// exactly how "first candidate wins" picked a webhook endpoint.
		svc("monitoring", "kps-kube-prometheus-operator",
			map[string]string{"app.kubernetes.io/name": "kube-prometheus-stack-prometheus-operator"},
			[]corev1.ServicePort{namedPort("https", 443)}),
		svc("monitoring", "kps-kube-prometheus-prometheus", nil,
			[]corev1.ServicePort{namedPort("http-web", 9090), namedPort("reloader-web", 8080)}),
		svc("monitoring", "kps-prometheus-node-exporter",
			map[string]string{"app.kubernetes.io/name": "prometheus-node-exporter"},
			[]corev1.ServicePort{namedPort("http-metrics", 9100)}),
		headlessSvc("monitoring", "prometheus-operated", nil,
			[]corev1.ServicePort{namedPort("http-web", 9090)}),
	}
}

func TestDetectEndpoint_FullKubePrometheusStackPicksTheQueryAPI(t *testing.T) {
	ep, found := DetectEndpoint(kubePrometheusStackServices())
	if !found {
		t.Fatal("a stock kube-prometheus-stack install must yield an endpoint")
	}
	if ep.Name != "kps-kube-prometheus-prometheus" || ep.Port != 9090 {
		t.Errorf("DetectEndpoint = %s/%s:%d (scheme %s); want monitoring/kps-kube-prometheus-prometheus:9090 — "+
			"picking the operator's webhook or an exporter costs the client all usage $ and the OBSERVED map",
			ep.Namespace, ep.Name, ep.Port, ep.Scheme)
	}
	if ep.Scheme != "http" {
		t.Errorf("Scheme = %q, want http for port 9090", ep.Scheme)
	}
}

func TestRankEndpoints_QueryAPIsBeforeOperatorsExportersAndHeadless(t *testing.T) {
	ranked := RankEndpoints(kubePrometheusStackServices())
	if len(ranked) == 0 {
		t.Fatal("RankEndpoints returned nothing for a stock kube-prometheus-stack install")
	}
	if ranked[0].Name != "kps-kube-prometheus-prometheus" {
		t.Errorf("ranked[0] = %s/%s:%d, want the ClusterIP Prometheus first",
			ranked[0].Namespace, ranked[0].Name, ranked[0].Port)
	}

	pos := map[string]int{}
	for i, ep := range ranked {
		pos[ep.Name] = i
	}
	real, ok := pos["kps-kube-prometheus-prometheus"]
	if !ok {
		t.Fatal("the real Prometheus must appear in the ranking")
	}
	// The headless operated service is a genuine Prometheus API, so it stays in the
	// list — but the API-server service proxy needs a ClusterIP, so it must rank lower.
	if operated, ok := pos["prometheus-operated"]; ok && operated < real {
		t.Errorf("headless prometheus-operated ranked %d, before the ClusterIP service at %d", operated, real)
	}
	for _, junk := range []string{
		"kps-kube-prometheus-operator",
		"kps-prometheus-node-exporter",
		"kps-kube-prometheus-kubelet",
		"kps-kube-prometheus-kube-etcd",
	} {
		if at, ok := pos[junk]; ok && at < real {
			t.Errorf("%s ranked %d, ahead of the real Prometheus at %d — it serves no query API", junk, at, real)
		}
	}
}

// headlessSvc builds a Service with clusterIP None, as the operator's
// "<name>-operated" service is declared.
func headlessSvc(ns, name string, labels map[string]string, ports []corev1.ServicePort) corev1.Service {
	s := svc(ns, name, labels, ports)
	s.Spec.ClusterIP = corev1.ClusterIPNone
	return s
}
