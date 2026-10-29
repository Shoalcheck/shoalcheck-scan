package collect

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Capacity-type node-label keys. These ride FREE on the corev1.Node objects the
// collector already lists (collect.go) — reading them is ZERO RBAC change;
// permissions.go is untouched. Values differ by provisioner: EKS managed node
// groups use UPPERCASE (ON_DEMAND/SPOT); Karpenter, AKS, and GKE use lowercase.
// A classifier MUST therefore normalize case and check every key.
const (
	// AWS EKS managed node groups. Values are UPPERCASE: ON_DEMAND | SPOT.
	labelEKSCapacityType = "eks.amazonaws.com/capacityType"
	// AWS Karpenter. Different key, lowercase values: on-demand | spot.
	labelKarpenterCapacityType = "karpenter.sh/capacity-type"
	// Azure AKS spot node pool. Detection by ABSENCE: present (=spot) ⇒ spot;
	// ABSENT ⇒ on-demand (Regular). There is NO positive regular/ondemand marker.
	labelAKSScaleSetPriority = "kubernetes.azure.com/scalesetpriority"
	// GCP GKE spot / legacy preemptible. Either set to "true" ⇒ spot.
	labelGKESpot        = "cloud.google.com/gke-spot"
	labelGKEPreemptible = "cloud.google.com/gke-preemptible"
	// Self-managed / kops / kubeadm community marker. Only a POSITIVE "spot"
	// value means spot; absence is genuinely unknown (never on-demand).
	labelCommunityLifecycle = "node.kubernetes.io/lifecycle"
)

// ClassifyCapacityType is the SINGLE, provider-aware classifier shared by both
// cost seams (collect's assemble and rules' node_headroom/rightsizing) so cluster
// spend and per-finding savings can never disagree on whether a pool is spot.
//
// It is provider-aware by design (an adversarial must-fix): AKS detects
// on-demand by ABSENCE of the spot label, while a self-managed node with no
// marker is genuinely unknown. A provider-blind classifier would mislabel AKS
// on-demand nodes as unknown and unknown nodes as on-demand. The honesty
// invariant is: a no-capacity-label node is NEVER silently defaulted to
// on-demand — it is CapacityUnknown unless the provider's semantics make
// absence meaningful (AKS / GKE), or a positive spot marker is present.
//
// provider accepts either the Kubernetes provider tag ("eks"/"aks"/"gke"/
// "kind"/"onprem"/"unknown") or the cloud name ("aws"/"azure"/"gcp"); both
// normalize internally.
func ClassifyCapacityType(provider string, n corev1.Node) types.CapacityType {
	switch normalizeCloudKind(provider) {
	case "aws":
		// EKS managed node group: UPPERCASE ON_DEMAND | SPOT.
		if v := n.Labels[labelEKSCapacityType]; v != "" {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "spot":
				return types.CapacitySpot
			case "on_demand", "on-demand", "ondemand":
				return types.CapacityOnDemand
			}
		}
		// Karpenter: lowercase spot | on-demand.
		if v := n.Labels[labelKarpenterCapacityType]; v != "" {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "spot":
				return types.CapacitySpot
			case "on-demand", "on_demand", "ondemand":
				return types.CapacityOnDemand
			}
		}
		// AWS with no capacity label: genuinely unknown, never assumed on-demand.
		return types.CapacityUnknown
	case "azure":
		// AKS: presence of the spot priority label ⇒ spot; ABSENCE ⇒ on-demand
		// (deterministic — there is no positive regular marker).
		if v, ok := n.Labels[labelAKSScaleSetPriority]; ok && strings.EqualFold(strings.TrimSpace(v), "spot") {
			return types.CapacitySpot
		}
		return types.CapacityOnDemand
	case "gcp":
		// GKE: gke-spot=true OR legacy gke-preemptible=true ⇒ spot; absent ⇒ on-demand.
		if isTrue(n.Labels[labelGKESpot]) || isTrue(n.Labels[labelGKEPreemptible]) {
			return types.CapacitySpot
		}
		return types.CapacityOnDemand
	default:
		// kind / onprem / unknown: only a POSITIVE community marker means spot;
		// otherwise unknown. Never default a no-label node to on-demand.
		if v := n.Labels[labelCommunityLifecycle]; strings.EqualFold(strings.TrimSpace(v), "spot") {
			return types.CapacitySpot
		}
		return types.CapacityUnknown
	}
}

// normalizeCloudKind maps the provider spellings either seam might hold
// (Kubernetes tags eks/aks/gke or cloud names aws/azure/gcp) onto the three
// cloud keys the classifier branches on. Anything else (kind/onprem/unknown/"")
// passes through as the default no-cloud case.
func normalizeCloudKind(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws", "eks":
		return "aws"
	case "azure", "aks":
		return "azure"
	case "gcp", "gke", "google":
		return "gcp"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

// isTrue reports whether a label value is the GKE boolean "true" (case-insensitive).
func isTrue(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "true") }
