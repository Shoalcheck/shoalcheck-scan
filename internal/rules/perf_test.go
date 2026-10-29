package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// TestRules_LargeInventoryPerf runs every registered rule against a ~500-
// workload inventory and asserts the full pass stays within budget. Real
// clusters reach this scale; the threshold is generous to avoid flaky CI.
func TestRules_LargeInventoryPerf(t *testing.T) {
	// THE DENOMINATOR. A loop over a registry that can be empty asserts something about every
	// member and nothing about the set, so an empty one passes having checked nothing.
	if n := len(All()); n < 80 {
		t.Fatalf("the registry holds %d rule(s); this test was written against a larger one and "+
			"would read as full coverage while measuring a fraction", n)
	}

	const n = 500
	inv := &collect.Inventory{}
	for i := 0; i < n; i++ {
		d := deploy(fmt.Sprintf("ns-%d", i%40), fmt.Sprintf("app-%d", i), int32(1+i%3), nil)
		inv.Deployments = append(inv.Deployments, d)
	}

	start := time.Now()
	total := 0
	for _, r := range All() {
		total += len(r.Evaluate(inv, Options{}))
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("evaluating %d rules over %d workloads took %v, budget 2s", len(All()), n, elapsed)
	}
	t.Logf("%d rules over %d workloads → %d findings in %v", len(All()), n, total, elapsed)
}
