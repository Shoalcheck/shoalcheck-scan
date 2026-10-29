package prom

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// preferredNamespaces lists the namespaces in which a Prometheus-compatible
// endpoint is most commonly deployed, in preference order.
var preferredNamespaces = []string{
	"monitoring",
	"observability",
	"prometheus",
}

// nameKeywords are substrings that identify a Prometheus-compatible service by name.
var nameKeywords = []string{
	"prometheus",
	"vmselect",
	"victoria-metrics",
	"mimir-query",
	"thanos-query",
}

// labelNames are values of the app.kubernetes.io/name label that identify
// a Prometheus-compatible endpoint.
var labelNames = map[string]bool{
	"prometheus":       true,
	"victoria-metrics": true,
	"mimir":            true,
	"thanos-query":     true,
}

// Endpoint is a resolved Prometheus-compatible Service: enough to build either a
// port-forward target or an API-server service-proxy path. It carries no
// connection — DetectEndpoint never dials.
type Endpoint struct {
	Namespace string
	Name      string
	Port      int32
	Scheme    string // "http" | "https"
}

// Detect scans collected Services for a well-known Prometheus-compatible
// endpoint and returns a human hint. It does NOT connect — the CLI runs
// outside the cluster; reachability is the user's responsibility (port-forward
// or an explicit --prometheus-url flag).
//
// When multiple candidates are found, services in the preferred namespaces
// (monitoring, observability, prometheus) are preferred. Detect wraps
// DetectEndpoint so the human hint and the structured Endpoint never diverge.
func Detect(services []corev1.Service) (found bool, hint string) {
	ep, ok := DetectEndpoint(services)
	if !ok {
		return false, ""
	}
	return true, buildHint(ep)
}

// DetectEndpoint scans collected Services and returns the best Prometheus-
// compatible Service as a structured Endpoint. found=false when none match.
// It does NOT connect. Scheme is "https" when the chosen port is named "https"
// or its number is 443, else "http".
func DetectEndpoint(services []corev1.Service) (ep Endpoint, found bool) {
	ranked := RankEndpoints(services)
	if len(ranked) == 0 {
		return Endpoint{}, false
	}
	return ranked[0], true
}

// nonQueryKeywords mark a Service that carries the "prometheus" substring while
// serving no query API: the operator's webhook, the exporters, and the scrape-target
// stubs a kube-prometheus-stack install creates in kube-system. Selecting one of these
// costs the client every usage dollar and the OBSERVED service map, so they are ranked
// below anything that looks like a real query endpoint.
var nonQueryKeywords = []string{
	"operator", "exporter", "alertmanager", "pushgateway", "grafana",
	"state-metrics", "kubelet", "coredns", "kube-etcd", "kube-proxy",
	"kube-scheduler", "kube-controller-manager", "blackbox", "adapter",
	"config-reloader", "thanos-sidecar",
}

// queryNameSignals mark a Service that most likely IS a query API.
var queryNameSignals = []string{
	"vmselect", "thanos-query", "mimir-query",
}

// scoreCandidate grades how likely a candidate Service is to answer PromQL. It is a
// heuristic and is treated as one: RankEndpoints only orders, and the app confirms by
// dialing. Nothing here is allowed to be load-bearing on its own.
func scoreCandidate(svc corev1.Service, port int32) int {
	name := strings.ToLower(svc.Name)
	score := 0

	// Canonical Prometheus: port 9090 exposed under the web/http-web name.
	for _, p := range svc.Spec.Ports {
		if p.Port == 9090 && (strings.EqualFold(p.Name, "web") || strings.EqualFold(p.Name, "http-web")) {
			score += 4
			break
		}
	}
	if port == 9090 {
		score += 2
	}
	if name == "prometheus" ||
		strings.HasSuffix(name, "-prometheus") ||
		strings.HasSuffix(name, "prometheus-server") ||
		strings.HasSuffix(name, "prometheus-operated") {
		score += 3
	}
	for _, kw := range queryNameSignals {
		if strings.Contains(name, kw) {
			score += 3
			break
		}
	}
	if appName, ok := svc.Labels["app.kubernetes.io/name"]; ok && labelNames[strings.ToLower(appName)] {
		score += 3
	}
	// Namespace preference is deliberately NOT scored here — RankEndpoints applies it as
	// a separate ordering tier, so that a plausible Prometheus in an unusual namespace
	// still outranks an exporter that merely happens to live in "monitoring".

	for _, kw := range nonQueryKeywords {
		if strings.Contains(name, kw) {
			score -= 6
			break
		}
	}
	// The API-server service proxy resolves a ClusterIP; a headless Service (as the
	// operator's "<name>-operated" is declared) is still a real Prometheus, so it stays
	// a candidate — just not the first one tried.
	if svc.Spec.ClusterIP == corev1.ClusterIPNone {
		score -= 3
	}
	// Exporter shape: the chosen port is a "*-metrics" scrape port rather than a UI/API port.
	if port != 9090 && strings.HasSuffix(strings.ToLower(portName(svc, port)), "-metrics") {
		score -= 2
	}
	return score
}

// portName returns the declared name of the given port, or "" when unnamed.
func portName(svc corev1.Service, port int32) string {
	for _, p := range svc.Spec.Ports {
		if p.Port == port {
			return p.Name
		}
	}
	return ""
}

// RankEndpoints returns Prometheus-compatible candidates, best first. Like
// DetectEndpoint it never dials — ranking is a heuristic over names, ports and
// labels, and the CALLER is expected to confirm empirically by trying them in order.
//
// That division of labour is the whole point. A stock kube-prometheus-stack install
// produces eleven Services whose names contain "prometheus", of which exactly one is a
// query API; before this existed, "first candidate wins" selected the operator's
// webhook endpoint on port 443 and the audit silently lost all usage $ and fell back to
// a DECLARED service map. No naming heuristic deserves to be the final word — hence a
// ranking here and a live probe in the caller.
//
// Candidates that score below zero (operators, exporters, scrape stubs) are dropped
// unless nothing scores better, so the caller never spends its probe budget dialling
// webhook endpoints.
func RankEndpoints(services []corev1.Service) []Endpoint {
	type scored struct {
		ep    Endpoint
		score int
	}
	var all []scored
	for _, svc := range services {
		if !isPrometheusCandidate(svc) {
			continue
		}
		port := selectPort(svc)
		all = append(all, scored{
			ep: Endpoint{
				Namespace: svc.Namespace,
				Name:      svc.Name,
				Port:      port,
				Scheme:    schemeFor(svc, port),
			},
			score: scoreCandidate(svc, port),
		})
	}
	if len(all) == 0 {
		return nil
	}

	// Ordering tiers, in this order — each tier only breaks ties left by the one above:
	//
	//  1. plausible before implausible (score >= 0). A negative score means the name
	//     says operator/exporter/scrape-stub, and no namespace should rescue it: this is
	//     what keeps a "monitoring" exporter from beating a real Prometheus that happens
	//     to live in "platform-observability".
	//  2. preferred namespace (monitoring / observability / prometheus) — the documented
	//     long-standing behaviour, preserved deliberately.
	//  3. score desc — canonical 9090/web ports and prometheus-shaped names first.
	//  4. namespace then name — so the same cluster always yields the same probe order,
	//     which keeps the app's live-probe fallthrough reproducible.
	sort.SliceStable(all, func(i, j int) bool {
		pi, pj := all[i].score >= 0, all[j].score >= 0
		if pi != pj {
			return pi
		}
		ni, nj := isPreferredNamespace(all[i].ep.Namespace), isPreferredNamespace(all[j].ep.Namespace)
		if ni != nj {
			return ni
		}
		if all[i].score != all[j].score {
			return all[i].score > all[j].score
		}
		if all[i].ep.Namespace != all[j].ep.Namespace {
			return all[i].ep.Namespace < all[j].ep.Namespace
		}
		return all[i].ep.Name < all[j].ep.Name
	})

	// Drop the sub-zero candidates only when something better exists; on a cluster
	// where every match looks like an exporter, the caller should still get to try them
	// rather than be told no Prometheus exists.
	keepNegatives := all[0].score < 0
	out := make([]Endpoint, 0, len(all))
	for _, s := range all {
		if s.score < 0 && !keepNegatives {
			break
		}
		out = append(out, s.ep)
	}
	return out
}

// schemeFor returns "https" when the chosen port is named "https" or numbered
// 443, else "http". Mis-detecting the scheme yields a proxy error the pipeline's
// degrade-gracefully path catches as usage-less, never a crash.
func schemeFor(svc corev1.Service, port int32) string {
	for _, p := range svc.Spec.Ports {
		if p.Port == port && strings.EqualFold(p.Name, "https") {
			return "https"
		}
	}
	if port == 443 {
		return "https"
	}
	return "http"
}

// isPrometheusCandidate returns true when the service name or label indicates
// a Prometheus-compatible query API.
func isPrometheusCandidate(svc corev1.Service) bool {
	name := strings.ToLower(svc.Name)
	for _, kw := range nameKeywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	if appName, ok := svc.Labels["app.kubernetes.io/name"]; ok {
		if labelNames[strings.ToLower(appName)] {
			return true
		}
	}
	return false
}

// isPreferredNamespace returns true when ns is in the preferred list.
func isPreferredNamespace(ns string) bool {
	for _, p := range preferredNamespaces {
		if ns == p {
			return true
		}
	}
	return false
}

// selectPort picks the best port to expose in the hint:
//  1. First port named "http", "web", or "http-web" (in that preference order).
//  2. Any port whose number is 9090 (Prometheus default).
//  3. The first port in the list (whatever number it has).
//  4. 9090 as a last-resort default when the service has no ports.
func selectPort(svc corev1.Service) int32 {
	preferred := []string{"http", "web", "http-web"}
	for _, name := range preferred {
		for _, p := range svc.Spec.Ports {
			if strings.EqualFold(p.Name, name) {
				return p.Port
			}
		}
	}
	for _, p := range svc.Spec.Ports {
		if p.Port == 9090 {
			return p.Port
		}
	}
	if len(svc.Spec.Ports) > 0 {
		return svc.Spec.Ports[0].Port
	}
	return 9090
}

// buildHint constructs the user-facing message explaining how to reach the endpoint.
func buildHint(ep Endpoint) string {
	return fmt.Sprintf(
		"prometheus found: %s/%s:%d — reach it via: "+
			"kubectl port-forward -n %s svc/%s %d:%d, "+
			"then pass --prometheus-url http://127.0.0.1:%d",
		ep.Namespace, ep.Name, ep.Port,
		ep.Namespace, ep.Name, ep.Port, ep.Port,
		ep.Port,
	)
}
