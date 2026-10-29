package collect

import "strings"

// ResourceAccess describes one read-only access the collector performs. It is
// the single source of truth shared by Collect(), the `audit --show-permissions`
// command, and the RBAC drift test — so the published ClusterRole, the printed
// permission preview, and what the code actually lists can never silently
// diverge.
type ResourceAccess struct {
	APIGroup string // "" for core/v1
	Resource string // plural, lowercase (matches RBAC and the "kind" step labels)
	Verbs    []string

	// Opportunistic marks a CRD read that runs only when the GVR is present in
	// discovery (PresentGVRs). Always-collected core kinds leave this false. The
	// RBAC contract still requires a grant for it (it MAY be read); the
	// actual-collection test only requires the always-collected set.
	Opportunistic bool
}

// readOnly is get+list — a one-time snapshot, never watch.
var readOnly = []string{"get", "list"}

// CollectedResources returns every resource the collector reads, in collection
// order. SECURITY CONTRACT: this list never contains secrets, configmaps, or
// any subresource/verb beyond get+list. Adding a step() to Collect without
// adding it here (or vice versa) fails TestRBACContractMatchesCollector.
func CollectedResources() []ResourceAccess {
	return []ResourceAccess{
		{"", "nodes", readOnly, false},
		{"", "namespaces", readOnly, false},
		{"", "pods", readOnly, false},
		{"", "services", readOnly, false},
		{"discovery.k8s.io", "endpointslices", readOnly, false},
		{"", "serviceaccounts", readOnly, false},
		{"", "resourcequotas", readOnly, false},
		{"", "limitranges", readOnly, false},
		{"", "persistentvolumes", readOnly, false},
		{"", "persistentvolumeclaims", readOnly, false},
		{"apps", "deployments", readOnly, false},
		{"apps", "statefulsets", readOnly, false},
		{"apps", "daemonsets", readOnly, false},
		{"policy", "poddisruptionbudgets", readOnly, false},
		{"rbac.authorization.k8s.io", "clusterrolebindings", readOnly, false},
		{"rbac.authorization.k8s.io", "rolebindings", readOnly, false},
		{"rbac.authorization.k8s.io", "clusterroles", readOnly, false},
		{"rbac.authorization.k8s.io", "roles", readOnly, false},
		{"networking.k8s.io", "networkpolicies", readOnly, false},
		{"networking.k8s.io", "ingresses", readOnly, false},
		{"autoscaling", "horizontalpodautoscalers", readOnly, false},
		{"batch", "cronjobs", readOnly, false},
		// Jobs, bounded and with the truncation disclosed — founder decision §10 Q2.
		{"batch", "jobs", readOnly, false},
		// The three class objects. Each is named by something else and was previously echoed rather than
		// resolved — a name repeated without resolving is a name that cannot be told from a typo.
		// CustomResourceDefinitions — the conversion-webhook declaration the upgrade family reads. Spec
		// only, narrowed to four fields on the way in (see collect/crd.go).
		{"apiextensions.k8s.io", "customresourcedefinitions", readOnly, false},
		{"storage.k8s.io", "storageclasses", readOnly, false},
		{"networking.k8s.io", "ingressclasses", readOnly, false},
		{"scheduling.k8s.io", "priorityclasses", readOnly, false},

		// Stack-analyzer CRDs — status/spec reads only; opportunistic (only
		// listed when present in PresentGVRs). Declared here so the published
		// ClusterRole and TestRBACContractMatchesCollector stay in lockstep, while
		// TestCollectedResourcesMatchActualCollection skips them (a fake cluster
		// serves none).
		{"cert-manager.io", "certificates", readOnly, true},
		{"security.istio.io", "peerauthentications", readOnly, true},
		{"security.istio.io", "authorizationpolicies", readOnly, true},
		{"networking.istio.io", "destinationrules", readOnly, true},
		{"policy.linkerd.io", "servers", readOnly, true},
		{"argoproj.io", "applications", readOnly, true},
		{"kustomize.toolkit.fluxcd.io", "kustomizations", readOnly, true},
		{"helm.toolkit.fluxcd.io", "helmreleases", readOnly, true},
		{"cilium.io", "ciliumnetworkpolicies", readOnly, true},
		{"cilium.io", "ciliumclusterwidenetworkpolicies", readOnly, true},
		{"projectcalico.org", "globalnetworkpolicies", readOnly, true},
		{"projectcalico.org", "networkpolicies", readOnly, true},
		{"keda.sh", "scaledobjects", readOnly, true},
		{"kafka.strimzi.io", "kafkas", readOnly, true},
		{"gateway.networking.k8s.io", "gateways", readOnly, true},
		{"gateway.networking.k8s.io", "httproutes", readOnly, true},
		// The monitoring stack. AlertmanagerConfig is the routing object; Alertmanager's MAIN
		// configuration lives in a Secret and is NOT granted here and never will be — the receivers it
		// holds are credentials.
		{"monitoring.coreos.com", "servicemonitors", readOnly, true},
		{"monitoring.coreos.com", "podmonitors", readOnly, true},
		{"monitoring.coreos.com", "alertmanagerconfigs", readOnly, true},
		{"monitoring.coreos.com", "prometheuses", readOnly, true},
	}
}

// StepToTuple maps a collector STEP NAME to the canonical (apiGroup/resource) tuple the session trace records.
//
// This is the join the design round called an unnamed blocker: Dependencies.Kinds are step names, session-trace
// rows are apiGroup/resource paths, and nothing in the tree connected them. The spec's answer was to hand-write a
// twenty-line table. It is not needed — CollectedResources() already holds exactly this pairing, and it is already
// asserted against deploy/rbac.yaml and against the collector's own step() calls by TestRBACContractMatchesCollector.
// Deriving from the existing source of truth means the join cannot drift from the grants, which a second table
// would eventually do.
//
// Two shapes are not resource steps and are returned unchanged: "server-resources", which is discovery, and any
// "cr:<resource>.<group>" step, which already carries its group.
func StepToTuple(step string) (string, bool) {
	if step == "" {
		return "", false
	}
	if step == "server-resources" {
		return "nonResourceURL", true
	}
	if strings.HasPrefix(step, CRStepPrefix) {
		// cr:certificates.cert-manager.io -> cert-manager.io/certificates
		body := strings.TrimPrefix(step, CRStepPrefix)
		if i := strings.Index(body, "."); i > 0 {
			return body[i+1:] + "/" + body[:i], true
		}
		return body, true
	}
	for _, r := range CollectedResources() {
		if r.Resource != step {
			continue
		}
		if r.APIGroup == "" {
			return "core/" + r.Resource, true
		}
		return r.APIGroup + "/" + r.Resource, true
	}
	return "", false
}
