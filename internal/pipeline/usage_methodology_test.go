package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"

	"k8s.io/client-go/kubernetes/fake"
)

func TestRunStampsUsageMethodologyNone(t *testing.T) {
	// No PrometheusURL, no VPA/metrics → Tier 4 none; report stamps the
	// usageMethodology AND adds a DataSources note saying "no usage source".
	col := collect.NewWithClient(fake.NewSimpleClientset())
	ar, err := Run(context.Background(), Options{Collector: col, ClusterName: "t"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ar.Methodology.UsageMethodology == nil {
		t.Fatal("UsageMethodology must be stamped even for the none tier")
	}
	if ar.Methodology.UsageMethodology.Source != "none" {
		t.Errorf("usage source = %q, want none", ar.Methodology.UsageMethodology.Source)
	}
	joined := strings.Join(ar.Methodology.DataSources, " | ")
	if !strings.Contains(joined, "no usage source") {
		t.Errorf("DataSources must note absent usage, got %q", joined)
	}
}

func TestRunStampsUsageMethodologyVPA(t *testing.T) {
	col := collect.NewWithClient(fake.NewSimpleClientset())
	ar, err := Run(context.Background(), Options{
		Collector:   col,
		ClusterName: "t",
		VPALister:   stubVPA{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	um := ar.Methodology.UsageMethodology
	if um == nil || um.Source != "vpa" || um.Confidence != prom.UsageConfidenceLow {
		t.Errorf("usage methodology = %+v, want source=vpa confidence=low", um)
	}
}

type stubVPA struct{}

func (stubVPA) ListTargets(context.Context) (map[string]prom.ContainerUsage, error) {
	return map[string]prom.ContainerUsage{}, nil
}
