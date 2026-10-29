package collect

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// labeledNode builds a bare node carrying only the given labels — enough to
// exercise the capacity classifier without the zone/region/type scaffolding.
func labeledNode(labels map[string]string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n", Labels: labels}}
}

func TestClassifyCapacityType(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		labels   map[string]string
		want     types.CapacityType
	}{
		// AWS EKS managed node group — UPPERCASE values, case must normalize.
		{"eks mng spot uppercase", "eks", map[string]string{"eks.amazonaws.com/capacityType": "SPOT"}, types.CapacitySpot},
		{"eks mng ondemand uppercase", "eks", map[string]string{"eks.amazonaws.com/capacityType": "ON_DEMAND"}, types.CapacityOnDemand},
		{"aws cloud-name alias spot", "aws", map[string]string{"eks.amazonaws.com/capacityType": "spot"}, types.CapacitySpot},

		// AWS Karpenter — different key, lowercase values.
		{"karpenter spot", "aws", map[string]string{"karpenter.sh/capacity-type": "spot"}, types.CapacitySpot},
		{"karpenter on-demand", "aws", map[string]string{"karpenter.sh/capacity-type": "on-demand"}, types.CapacityOnDemand},
		// EKS key wins when both present and the MNG key is decisive.
		{"eks key precedence over karpenter", "eks", map[string]string{
			"eks.amazonaws.com/capacityType": "SPOT",
			"karpenter.sh/capacity-type":     "on-demand",
		}, types.CapacitySpot},

		// AWS with NO capacity label ⇒ unknown, never on-demand.
		{"aws no label is unknown", "eks", map[string]string{"node.kubernetes.io/instance-type": "m6i.large"}, types.CapacityUnknown},

		// Azure AKS — detection by ABSENCE.
		{"aks spot present", "aks", map[string]string{"kubernetes.azure.com/scalesetpriority": "spot"}, types.CapacitySpot},
		{"aks absence is on-demand", "aks", map[string]string{"node.kubernetes.io/instance-type": "Standard_D4lds_v5"}, types.CapacityOnDemand},
		{"aks empty value is on-demand", "azure", map[string]string{"kubernetes.azure.com/scalesetpriority": ""}, types.CapacityOnDemand},

		// GCP GKE — gke-spot or legacy preemptible.
		{"gke spot true", "gke", map[string]string{"cloud.google.com/gke-spot": "true"}, types.CapacitySpot},
		{"gke preemptible true", "gcp", map[string]string{"cloud.google.com/gke-preemptible": "true"}, types.CapacitySpot},
		{"gke absence is on-demand", "gke", map[string]string{"node.kubernetes.io/instance-type": "e2-standard-4"}, types.CapacityOnDemand},
		{"gke spot false is on-demand", "gke", map[string]string{"cloud.google.com/gke-spot": "false"}, types.CapacityOnDemand},

		// Self-managed / kind / onprem — positive community marker only.
		{"onprem lifecycle spot", "onprem", map[string]string{"node.kubernetes.io/lifecycle": "spot"}, types.CapacitySpot},
		{"kind no marker is unknown", "kind", map[string]string{}, types.CapacityUnknown},
		{"unknown provider no marker is unknown", "unknown", map[string]string{"node.kubernetes.io/instance-type": "m6i.large"}, types.CapacityUnknown},
		{"empty provider no marker is unknown", "", nil, types.CapacityUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyCapacityType(c.provider, labeledNode(c.labels))
			if got != c.want {
				t.Errorf("ClassifyCapacityType(%q, %v) = %q, want %q", c.provider, c.labels, got, c.want)
			}
			if !got.Valid() {
				t.Errorf("classifier returned an invalid CapacityType %q", got)
			}
		})
	}
}

// TestClassifyCapacityType_NeverDefaultsNoLabelToOnDemandOnAWS is the explicit
// honesty regression guard: a no-capacity-label node on AWS is unknown, NOT
// on-demand. (A provider-blind classifier is the footgun this prevents.)
func TestClassifyCapacityType_NeverDefaultsNoLabelToOnDemandOnAWS(t *testing.T) {
	got := ClassifyCapacityType("eks", labeledNode(map[string]string{}))
	if got == types.CapacityOnDemand {
		t.Fatalf("no-label AWS node classified on-demand — must be unknown (honesty invariant)")
	}
	if got != types.CapacityUnknown {
		t.Fatalf("no-label AWS node = %q, want unknown", got)
	}
}
