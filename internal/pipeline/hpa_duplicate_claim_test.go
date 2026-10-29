package pipeline

import (
	"strings"
	"testing"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ONE FACT, ONE FINDING — ACROSS BOTH PRODUCERS.
//
// internal/rules and internal/analyzers are separate registries that never see each other, and each was
// checked against itself. `k8s.reliability.hpa-pinned-at-max` fires when status.currentReplicas equals
// spec.maxReplicas AND the autoscaler published ScalingLimited=True — its own report that it wanted a count
// it may not reach. `stack.hpa.pinned-at-max` fired on the arithmetic alone. So on any HPA carrying that
// condition BOTH fired, and one reading printed the same fact about the same object twice, once with the
// weaker evidence.
//
// That is a count defect before it is a duplication: the document's headline is a number of findings, the
// queue is a list of things to do, and an operator handed two rows for one autoscaler has to work out for
// themselves that they are one. Nothing in either package could have caught it, which is why this test is
// here rather than in one of them — internal/pipeline is the only place that imports both.
//
// THE TWO CASES ARE DIFFERENT CLAIMS AND BOTH ARE WORTH KEEPING. With the condition, the strongest available
// statement is the autoscaler's own. Without it — no metrics source, so the HPA controller never writes the
// condition, which is exactly the state of a cluster with no metrics-server — the arithmetic is all there is,
// and it is still true. So the analyzer keeps the case the registry rule cannot reach and gives up the one it
// can.
func TestHPAAtCeiling_OneFindingNotTwo(t *testing.T) {
	at := func(withCondition bool) []types.Finding {
		h := autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "api"},
			Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: ptr(int32(2)), MaxReplicas: 5},
			Status:     autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: 5},
		}
		if withCondition {
			h.Status.Conditions = []autoscalingv2.HorizontalPodAutoscalerCondition{{
				Type:    autoscalingv2.ScalingLimited,
				Status:  corev1.ConditionTrue,
				Reason:  "TooManyReplicas",
				Message: "the desired replica count is more than the maximum replica count",
			}}
		}
		inv := &collect.Inventory{HPAs: []autoscalingv2.HorizontalPodAutoscaler{h}}
		// observed() gates the registry rule: a run that never listed HPAs must stay silent, so the step
		// has to appear as collected or the rule is silent for the wrong reason and this test proves nothing.
		inv.Meta.Collected = []string{"horizontalpodautoscalers"}

		var out []types.Finding
		for _, r := range rules.All() {
			out = append(out, r.Evaluate(inv, rules.Options{})...)
		}
		for _, a := range analyzers.All() {
			out = append(out, a.Analyze(inv)...)
		}
		return out
	}

	pinned := func(fs []types.Finding) []string {
		var ids []string
		for _, f := range fs {
			if strings.Contains(f.RuleID, "pinned-at-max") {
				ids = append(ids, f.RuleID)
			}
		}
		return ids
	}

	// WITH the condition: the registry rule's claim is strictly stronger, so it is the only one.
	got := pinned(at(true))
	if len(got) != 1 {
		t.Errorf("an HPA at its ceiling carrying ScalingLimited=True produced %d pinned-at-max findings "+
			"(%v): one fact about one object, printed once", len(got), got)
	} else if got[0] != "k8s.reliability.hpa-pinned-at-max" {
		t.Errorf("with ScalingLimited=True the surviving finding is %s; it should be the one that carries "+
			"the autoscaler's own statement as evidence", got[0])
	}

	// WITHOUT it: the registry rule cannot speak, and the arithmetic is still true.
	got = pinned(at(false))
	if len(got) != 1 {
		t.Errorf("an HPA at its ceiling with no ScalingLimited condition produced %d pinned-at-max "+
			"findings (%v): a cluster with no metrics source must still be told", len(got), got)
	} else if got[0] != "stack.hpa.pinned-at-max" {
		t.Errorf("with no condition published the surviving finding is %s; the registry rule requires the "+
			"condition, so this case belongs to the analyzer", got[0])
	}
}

func ptr[T any](v T) *T { return &v }
