package collect

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// buildFleetLinkage extracts the read-only, org-scoped fingerprint used to
// detect genuine cross-cluster links (see types.FleetLinkage). Everything here
// is a value an unrelated org could not coincidentally share — private image
// digests/registries and the cluster's own hostnames — never shared workload
// names (which every cluster has and which prove nothing).
func buildFleetLinkage(inv *Inventory) *types.FleetLinkage {
	digests := map[string]bool{}
	registries := map[string]bool{}
	addImage := func(ref string) {
		host, repo, digest := parseImageRef(ref)
		if !isPrivateRegistry(host) {
			return // public images (nginx, argocd, …) collide across all clusters
		}
		registries[host] = true
		if digest != "" {
			digests[host+"/"+repo+"@"+digest] = true
		}
	}
	for i := range inv.Pods {
		for _, c := range inv.Pods[i].Spec.Containers {
			addImage(c.Image)
		}
		for _, c := range inv.Pods[i].Spec.InitContainers {
			addImage(c.Image)
		}
	}
	for i := range inv.Deployments {
		for _, c := range inv.Deployments[i].Spec.Template.Spec.Containers {
			addImage(c.Image)
		}
	}
	for i := range inv.StatefulSets {
		for _, c := range inv.StatefulSets[i].Spec.Template.Spec.Containers {
			addImage(c.Image)
		}
	}
	for i := range inv.DaemonSets {
		for _, c := range inv.DaemonSets[i].Spec.Template.Spec.Containers {
			addImage(c.Image)
		}
	}

	served := map[string]bool{}
	for i := range inv.Ingresses {
		for _, r := range inv.Ingresses[i].Spec.Rules {
			if h := normHost(r.Host); h != "" {
				served[h] = true
			}
		}
		for _, t := range inv.Ingresses[i].Spec.TLS {
			for _, h := range t.Hosts {
				if nh := normHost(h); nh != "" {
					served[nh] = true
				}
			}
		}
	}

	outbound := map[string]bool{}
	for i := range inv.Services {
		s := &inv.Services[i]
		if s.Spec.Type != corev1.ServiceTypeExternalName || s.Spec.ExternalName == "" {
			continue
		}
		h := normHost(s.Spec.ExternalName)
		if h == "" || isPublicExternalHost(h) || strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".svc.cluster.local") || strings.HasSuffix(h, ".local") {
			continue
		}
		outbound[h] = true
	}

	return &types.FleetLinkage{
		PrivateImageDigests: sortedKeys(digests),
		PrivateRegistries:   sortedKeys(registries),
		ServedHosts:         sortedKeys(served),
		OutboundHosts:       sortedKeys(outbound),
	}
}

// normHost lower-cases a hostname, trims a trailing dot, and drops wildcards
// (which can't be matched exactly across clusters).
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" || strings.Contains(h, "*") {
		return ""
	}
	return h
}

// parseImageRef splits an image reference into (registryHost, repoPath, digest).
// A bare image (no host, or first component without "." / ":" / "localhost")
// defaults to docker.io. The tag is dropped; the @sha256 digest is preserved.
func parseImageRef(ref string) (host, repo, digest string) {
	s := ref
	if i := strings.Index(s, "@"); i >= 0 {
		digest = s[i+1:]
		s = s[:i]
	}
	if slash := strings.Index(s, "/"); slash >= 0 {
		first := s[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			host, repo = first, s[slash+1:]
		} else {
			host, repo = "docker.io", s
		}
	} else {
		host, repo = "docker.io", s
	}
	// strip a trailing :tag from the repo (only if the colon is in the last segment)
	if c := strings.LastIndex(repo, ":"); c >= 0 && !strings.Contains(repo[c:], "/") {
		repo = repo[:c]
	}
	return strings.ToLower(host), repo, digest
}

// isPrivateRegistry reports whether a registry host is org-scoped (a shared one
// is real evidence two clusters belong to the same org). Public/multi-tenant
// hosts (docker.io, registry.k8s.io, quay.io, ghcr.io, gcr.io, mcr, public
// ECR …) are excluded — every cluster pulls from them, so a match is noise.
func isPrivateRegistry(host string) bool {
	if host == "" {
		return false
	}
	switch host {
	case "docker.io", "index.docker.io", "registry-1.docker.io",
		"registry.k8s.io", "k8s.gcr.io", "gcr.io", "quay.io",
		"public.ecr.aws", "ecr-public.aws.com", "mcr.microsoft.com",
		"ghcr.io", "docker.elastic.co", "registry.gitlab.com",
		"cgr.dev", "registry.access.redhat.com", "registry.redhat.io":
		return false
	}
	if strings.HasSuffix(host, ".gcr.io") || strings.HasSuffix(host, ".pkg.dev") {
		return false // public GCR mirrors / ambiguous GAR — exclude to avoid false links
	}
	if strings.HasSuffix(host, ".azurecr.io") { // ACR instance = one org
		return true
	}
	if strings.Contains(host, ".dkr.ecr.") && strings.HasSuffix(host, ".amazonaws.com") { // ECR (account-scoped)
		return true
	}
	// Self-hosted registry (Harbor / Artifactory / Nexus / private GitLab): a
	// domain host not matched above. A bare org name (no dot) is treated as a
	// docker.io org → public.
	return strings.Contains(host, ".")
}

// isPublicExternalHost reports whether an ExternalName target is a shared public
// SaaS / managed-cloud endpoint (both clusters calling Stripe or an RDS host is
// a shared dependency, NOT a cluster-to-cluster link).
func isPublicExternalHost(h string) bool {
	for _, suf := range []string{
		".amazonaws.com", ".googleapis.com", ".windows.net", ".azure.com",
		".cloudfront.net", ".azurewebsites.net", ".blob.core.windows.net",
		".cache.amazonaws.com", ".rds.amazonaws.com", ".cosmos.azure.com",
	} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	for _, d := range []string{"stripe.com", "sentry.io", "datadoghq.com", "googleapis.com", "amazonaws.com"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
