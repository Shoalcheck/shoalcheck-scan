package pipeline

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/progress"
)

// THE LIVE SCREEN IS A TERMINAL TOO. SanitizeControls scrubs the reading at the end of the run, but the audit's
// terminal workbench draws from progress events as they arrive — an unpriced node's instance-type label, the
// region label, an API error's text — so a node labelled with an escape sequence cleared the screen of
// `shoalcheck audit` before the reading was ever scrubbed (review of the night batch, 2026-10-21). Every event
// is scrubbed on its way out of the pipeline.
func TestRun_EmitsNoTerminalControlsInProgress(t *testing.T) {
	const evil = "m5.\x1b[2J\x1b[32mlarge\x1b]0;owned\x07"
	cs := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{
		"node.kubernetes.io/instance-type": evil,
		"topology.kubernetes.io/region":    "eu-\x1b[31mwest-1",
	}}})
	var seen []string
	_, err := Run(context.Background(), Options{Collector: collect.NewWithClient(cs), ClusterName: "t",
		Progress: func(e progress.Event) {
			if n := e.NodeSeen; n != nil {
				seen = append(seen, n.InstanceType)
			}
			if n := e.NodePriced; n != nil {
				seen = append(seen, n.InstanceType)
			}
			if p := e.Pricing; p != nil {
				seen = append(seen, p.Region)
			}
		}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("no node or pricing event carried a label — the test measured nothing")
	}
	for _, s := range seen {
		if strings.ContainsAny(s, "\x1b\x07") {
			t.Errorf("a progress event carried terminal controls: %q", s)
		}
	}
}
