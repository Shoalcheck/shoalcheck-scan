package pipeline

import "testing"

// TestFriendlyClusterName covers the context→display-name mapping used by
// RunFleet so the sidebar/header shows a short cluster name instead of a raw
// kube context (notably an EKS ARN). Each case documents one provider shape or
// edge case; the helper must be pure and total (never panic, always non-empty).
func TestFriendlyClusterName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "EKS ARN strips to name after cluster/",
			in:   "arn:aws:eks:eu-north-1:444455556666:cluster/dev-cluster",
			want: "dev-cluster",
		},
		{
			name: "EKS ARN with dotted cluster name",
			in:   "arn:aws:eks:us-east-1:111122223333:cluster/prod.eu-1",
			want: "prod.eu-1",
		},
		{
			name: "GKE context uses last underscore segment",
			in:   "gke_my-project_europe-west1_prod-cluster",
			want: "prod-cluster",
		},
		{
			name: "GKE context with zonal location",
			in:   "gke_acme-pay-prod_us-central1-a_payments",
			want: "payments",
		},
		{
			name: "AKS context already friendly — unchanged",
			in:   "aks-shop-dev-westus3-01",
			want: "aks-shop-dev-westus3-01",
		},
		{
			name: "plain name unchanged",
			in:   "kind-cluster",
			want: "kind-cluster",
		},
		{
			name: "empty string falls back to cluster",
			in:   "",
			want: "cluster",
		},
		{
			name: "malformed ARN without cluster/ returned as-is",
			in:   "arn:aws:eks:eu-north-1:444455556666:nodegroup/ng-1",
			want: "arn:aws:eks:eu-north-1:444455556666:nodegroup/ng-1",
		},
		{
			name: "EKS ARN with trailing slash falls back to whole context",
			in:   "arn:aws:eks:eu-north-1:444455556666:cluster/",
			want: "arn:aws:eks:eu-north-1:444455556666:cluster/",
		},
		{
			name: "GKE prefix with no trailing segment returned as-is",
			in:   "gke_",
			want: "gke_",
		},
		{
			name: "GKE context with trailing underscore returned as-is",
			in:   "gke_proj_region_",
			want: "gke_proj_region_",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := friendlyClusterName(c.in); got != c.want {
				t.Errorf("friendlyClusterName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
