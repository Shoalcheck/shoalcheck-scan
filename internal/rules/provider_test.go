package rules

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

func nodeWith(providerID, itype, region string) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n", Labels: map[string]string{}}}
	n.Spec.ProviderID = providerID
	if itype != "" {
		n.Labels[labelInstanceType] = itype
	}
	if region != "" {
		n.Labels["topology.kubernetes.io/region"] = region
	}
	n.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("4"),
		corev1.ResourceMemory: resource.MustParse("16Gi"),
	}
	return n
}

// A cluster that gives no cloud signal must not be PRICED as one.
//
// providerFromNodes ended in `return "aws"`, and its comment said so openly: the default existed to "preserve
// existing behaviour for AWS-format fixtures". That is a test convenience deciding what a customer's report
// says. A bare-metal or kind cluster whose nodes carry no providerID would be priced against AWS tables, and
// the dollars that came out would be fabricated — the one thing this project's honesty policy names outright.
//
// internal/collect derives the SAME fact honestly (kind:// -> "kind", empty -> "unknown"), so the two halves of
// the codebase disagreed about the same cluster, and the half that produced money was the dishonest one.
func TestProviderFromNodes_NoSignalIsNotAWS(t *testing.T) {
	cases := []struct {
		name  string
		nodes []corev1.Node
		want  string
	}{
		{"no providerID and no instance type", []corev1.Node{nodeWith("", "", "")}, ""},
		{"kind node", []corev1.Node{nodeWith("kind://docker/shoalcheck/worker", "", "")}, ""},
		{"on-prem with an opaque label", []corev1.Node{nodeWith("", "bare-metal-r640", "")}, ""},
		{"aws providerID wins", []corev1.Node{nodeWith("aws:///eu-central-1a/i-abc", "", "")}, "aws"},
		{"azure providerID wins", []corev1.Node{nodeWith("azure:///subscriptions/x", "", "")}, "azure"},
		{"gce providerID wins", []corev1.Node{nodeWith("gce://p/z/n", "", "")}, "gcp"},
		{"aws instance-type shape is a real signal", []corev1.Node{nodeWith("", "m6i.xlarge", "")}, "aws"},
		{"azure sku shape", []corev1.Node{nodeWith("", "Standard_D4as_v5", "")}, "azure"},
		{"gcp family shape", []corev1.Node{nodeWith("", "e2-standard-4", "")}, "gcp"},
	}
	for _, c := range cases {
		if got := providerFromNodes(c.nodes); got != c.want {
			t.Errorf("%s: providerFromNodes = %q, want %q", c.name, got, c.want)
		}
	}
}

// And the consequence that matters: no provider means no dollar. A rule that priced an unknown cluster would
// put a number in front of a buyer that nothing supports.
func TestNodeHeadroom_UnknownProviderProducesNoDollar(t *testing.T) {
	nodes := []corev1.Node{
		nodeWith("", "", "eu-central-1"), nodeWith("", "", "eu-central-1"),
		nodeWith("", "", "eu-central-1"), nodeWith("", "", "eu-central-1"),
	}
	for i := range nodes {
		nodes[i].Name = string(rune('a' + i))
		nodes[i].Labels["kubernetes.io/hostname"] = nodes[i].Name
	}
	inv := &collect.Inventory{Nodes: nodes, Meta: collect.Meta{
		Collected: []string{"nodes", "pods"},
	}}
	for _, f := range (NodeHeadroom{}).Evaluate(inv, Options{}) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("a cluster with no cloud signal produced $%.2f/mo: %s",
				f.DollarImpactMonthly, f.Title)
		}
	}
}
