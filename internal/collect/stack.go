package collect

import (
	"fmt"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// detectStack identifies well-known platform components from workload and
// namespace names/labels — read-only, no extra API calls.
//
// Matching priority (first match per layer wins):
//  1. deployment/daemonset name prefix
//  2. namespace name
//  3. label app.kubernetes.io/name or app.kubernetes.io/part-of
//
// Observability is special: up to 3 tools are collected and joined as
// "Prometheus + Grafana + Loki".
func detectStack(inv *Inventory) []types.StackEntry {
	// ---- helpers -------------------------------------------------------

	// checkLabels returns true if any of the given label keys matches one of
	// the given prefixes (case-insensitive).
	matchLabel := func(labels map[string]string, prefixes []string) (string, bool) {
		for _, key := range []string{"app.kubernetes.io/name", "app.kubernetes.io/part-of"} {
			v := labels[key]
			if v == "" {
				continue
			}
			vl := strings.ToLower(v)
			for _, p := range prefixes {
				if strings.HasPrefix(vl, strings.ToLower(p)) {
					return v, true
				}
			}
		}
		return "", false
	}

	matchName := func(name string, prefixes []string) bool {
		nl := strings.ToLower(name)
		for _, p := range prefixes {
			if strings.HasPrefix(nl, strings.ToLower(p)) {
				return true
			}
		}
		return false
	}

	matchNS := func(nsName string, prefixes []string) bool {
		nl := strings.ToLower(nsName)
		for _, p := range prefixes {
			if strings.HasPrefix(nl, strings.ToLower(p)) {
				return true
			}
		}
		return false
	}

	// singleLayer tries to find a single matching tool across all workloads
	// and namespaces.  Returns (displayName, note, found).
	singleLayer := func(prefixes []string, displayName string) (string, string, bool) {
		// 1. daemonsets by name
		for _, ds := range inv.DaemonSets {
			if matchName(ds.Name, prefixes) {
				return displayName, fmt.Sprintf("detected: daemonset %s/%s", ds.Namespace, ds.Name), true
			}
		}
		// 2. deployments by name
		for _, d := range inv.Deployments {
			if matchName(d.Name, prefixes) {
				return displayName, fmt.Sprintf("detected: deployment %s/%s", d.Namespace, d.Name), true
			}
		}
		// 3. namespaces by name
		for _, ns := range inv.Namespaces {
			if matchNS(ns.Name, prefixes) {
				return displayName, fmt.Sprintf("detected: namespace %s", ns.Name), true
			}
		}
		// 4. daemonset labels
		for _, ds := range inv.DaemonSets {
			if _, ok := matchLabel(ds.Labels, prefixes); ok {
				return displayName, fmt.Sprintf("detected: daemonset %s/%s (label)", ds.Namespace, ds.Name), true
			}
		}
		// 5. deployment labels
		for _, d := range inv.Deployments {
			if _, ok := matchLabel(d.Labels, prefixes); ok {
				return displayName, fmt.Sprintf("detected: deployment %s/%s (label)", d.Namespace, d.Name), true
			}
		}
		// 6. namespace labels
		for _, ns := range inv.Namespaces {
			if _, ok := matchLabel(ns.Labels, prefixes); ok {
				return displayName, fmt.Sprintf("detected: namespace %s (label)", ns.Name), true
			}
		}
		return "", "", false
	}

	// ---- layer definitions (deterministic order) -----------------------

	var results []types.StackEntry

	// --- CNI ---
	cniTools := []struct {
		prefixes    []string
		displayName string
	}{
		{[]string{"cilium"}, "Cilium"},
		{[]string{"calico-node"}, "Calico"},
		{[]string{"aws-node"}, "AWS VPC CNI"},
		{[]string{"kube-flannel"}, "Flannel"},
		{[]string{"weave-net"}, "Weave Net"},
	}
	for _, tool := range cniTools {
		if name, note, ok := singleLayer(tool.prefixes, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "CNI", Name: name, Note: note})
			break
		}
	}

	// --- GitOps ---
	gitopsTools := []struct {
		prefixes    []string
		nsPrefix    []string
		displayName string
	}{
		{[]string{"argocd-"}, []string{"argocd"}, "Argo CD"},
		{[]string{"flux-"}, []string{"flux-system"}, "Flux"},
	}
	for _, tool := range gitopsTools {
		// combine workload prefixes + namespace prefixes for the search
		combined := append(tool.prefixes, tool.nsPrefix...) //nolint:gocritic
		if name, note, ok := singleLayer(combined, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "GitOps", Name: name, Note: note})
			break
		}
	}

	// --- Observability (up to 3, joined) ---
	type obsCandidate struct {
		prefixes    []string
		displayName string
	}
	obsCandidates := []obsCandidate{
		{[]string{"prometheus"}, "Prometheus"},
		{[]string{"grafana"}, "Grafana"},
		{[]string{"datadog-agent"}, "Datadog"},
		{[]string{"loki"}, "Loki"},
		{[]string{"victoria-metrics"}, "Victoria Metrics"},
		{[]string{"fluent-bit", "fluentd"}, "Fluent Bit/d"},
	}
	var obsNames []string
	var obsNotes []string
	for _, cand := range obsCandidates {
		if len(obsNames) >= 3 {
			break
		}
		if name, note, ok := singleLayer(cand.prefixes, cand.displayName); ok {
			obsNames = append(obsNames, name)
			obsNotes = append(obsNotes, note)
		}
	}
	if len(obsNames) > 0 {
		results = append(results, types.StackEntry{
			Layer: "Observability",
			Name:  strings.Join(obsNames, " + "),
			Note:  strings.Join(obsNotes, "; "),
		})
	}

	// --- Autoscaling ---
	autoscalingTools := []struct {
		prefixes    []string
		displayName string
	}{
		{[]string{"karpenter"}, "Karpenter"},
		{[]string{"cluster-autoscaler"}, "Cluster Autoscaler"},
		{[]string{"keda"}, "KEDA"},
	}
	for _, tool := range autoscalingTools {
		if name, note, ok := singleLayer(tool.prefixes, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "Autoscaling", Name: name, Note: note})
			break
		}
	}

	// --- Ingress ---
	ingressTools := []struct {
		prefixes    []string
		displayName string
	}{
		{[]string{"ingress-nginx", "nginx-ingress"}, "NGINX Ingress"},
		{[]string{"traefik"}, "Traefik"},
		{[]string{"istio-ingressgateway"}, "Istio Gateway"},
		{[]string{"envoy-gateway"}, "Envoy Gateway"},
		{[]string{"kong"}, "Kong"},
	}
	for _, tool := range ingressTools {
		if name, note, ok := singleLayer(tool.prefixes, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "Ingress", Name: name, Note: note})
			break
		}
	}

	// --- Service mesh ---
	meshTools := []struct {
		prefixes    []string
		displayName string
	}{
		{[]string{"istiod"}, "Istio"},
		{[]string{"linkerd-destination", "linkerd"}, "Linkerd"},
	}
	for _, tool := range meshTools {
		if name, note, ok := singleLayer(tool.prefixes, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "Service mesh", Name: name, Note: note})
			break
		}
	}

	// --- Certificates ---
	if name, note, ok := singleLayer([]string{"cert-manager"}, "cert-manager"); ok {
		results = append(results, types.StackEntry{Layer: "Certificates", Name: name, Note: note})
	}

	// --- Secrets ---
	secretsTools := []struct {
		prefixes    []string
		displayName string
	}{
		{[]string{"external-secrets"}, "External Secrets"},
		{[]string{"sealed-secrets"}, "Sealed Secrets"},
		{[]string{"vault"}, "Vault"},
	}
	for _, tool := range secretsTools {
		if name, note, ok := singleLayer(tool.prefixes, tool.displayName); ok {
			results = append(results, types.StackEntry{Layer: "Secrets", Name: name, Note: note})
			break
		}
	}

	if len(results) == 0 {
		return nil
	}
	return results
}
