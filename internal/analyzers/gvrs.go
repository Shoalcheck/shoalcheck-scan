package analyzers

import "k8s.io/apimachinery/pkg/runtime/schema"

// CRD GVRs the analyzers gate on. The VERSION here is the one Phase-0 discovery
// is expected to serve, but membership in inv.PresentGVRs is checked with the
// server-PREFERRED version captured by gvrSetFromLists — so a cluster serving
// e.g. cert-manager v1alpha2 instead of v1 is matched by the same Group+Resource
// because Phase-0 records the served version. We therefore declare the COMMON
// stable versions here; gating tolerates skew because PresentGVRs carries the
// real served version and analyzers read StackObjects by the SAME key the
// collector used. These constants only drive the RBAC union + the StackObjects
// map key — never a hardcoded served version in a List call.
//
// NOTE: StackObjects is keyed by the GVR the collector actually listed (the
// server-preferred version). Analyzers therefore look up StackObjects by GROUP
// + RESOURCE, ignoring version, via stackObjects() in analyzers.go — never by a
// fixed version literal.

func certManagerGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}}
}

func ciliumGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
		{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"},
	}
}

func calicoGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "projectcalico.org", Version: "v3", Resource: "globalnetworkpolicies"},
		{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"},
	}
}

func istioGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"},
		{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"},
		{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"},
	}
}

func linkerdGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "policy.linkerd.io", Version: "v1beta1", Resource: "servers"},
	}
}

func argoGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"},
	}
}

func fluxGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"},
		{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
	}
}

func kedaGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}}
}

func strimziGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{{Group: "kafka.strimzi.io", Version: "v1beta2", Resource: "kafkas"}}
}

func gatewayGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"},
	}
}
