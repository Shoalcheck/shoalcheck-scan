package verdict

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func nsFinding(yaml string) types.Finding {
	return types.Finding{
		ID:                "f-gov",
		RuleID:            "k8s.namespace.no-resource-governance",
		Title:             "Namespace bookinfo has neither a LimitRange nor a ResourceQuota",
		AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: "bookinfo"}},
		RemediationYAML:   yaml,
	}
}

const cleanLimitRange = `apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: bookinfo
spec:
  limits:
    - type: Container
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      default:
        cpu: 500m
        memory: 512Mi
`

const cleanQuota = `apiVersion: v1
kind: ResourceQuota
metadata:
  name: caps
  namespace: bookinfo
spec:
  hard:
    requests.cpu: "8"
`

// A LimitRange is judged by its KIND, not by the words inside it.
//
// The pod-template scan is a substring search over the whole remediation, and `limits:` is the
// LimitRange's own top-level spec key — so every LimitRange convicted itself. Measured on the live
// testbed: 112 findings, safe-now=0, with k8s.namespace.no-resource-governance demoted to
// needs-review by that one marker while isHedged said false. The single shape the closed loop is
// built for was the one shape it could never reach, which made EPIC 2's gate — a real fix clearing
// a real flag on the testbed — unreachable in principle.
func TestClassify_ALimitRangeIsNotAPodTemplateEdit(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want SafetyClass
	}{
		{"a clean LimitRange", cleanLimitRange, SafeNow},
		{"a clean ResourceQuota", cleanQuota, SafeNow},
		{"both, in one remediation", cleanLimitRange + "---\n" + cleanQuota, SafeNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(nsFinding(tc.yaml)); got != tc.want {
				t.Errorf("Classify = %q, want %q — this is the shape the closed loop exists for", got, tc.want)
			}
		})
	}
}

// And the intent the old ordering protected is kept: a bundle is judged by its disruptive half. The
// point was never that `limits:` is harmless — it is that a LimitRange's OWN limits are not a pod
// template. A container resources block still convicts, and it convicts the whole remediation.
func TestClassify_ABundledPodTemplateEditStillConvicts(t *testing.T) {
	deploymentEdit := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: reviews
  namespace: bookinfo
spec:
  template:
    spec:
      containers:
        - name: reviews
          resources:
            limits:
              cpu: 500m
`
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"a pod-template edit on its own", deploymentEdit},
		{"a LimitRange bundled with one", cleanLimitRange + "---\n" + deploymentEdit},
		{"the same, disruptive half first", deploymentEdit + "---\n" + cleanLimitRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(nsFinding(tc.yaml)); got != NeedsReview {
				t.Errorf("Classify = %q, want needs-review — applying this rolls every pod in the workload", got)
			}
		})
	}
}

// A hedged remediation stays Manual whatever its kind. The kind fix must not reach past the hedge:
// text telling the operator to work something out first is not a blind apply.
func TestClassify_TheHedgeStillWins(t *testing.T) {
	// The hedge is scanned in the REMEDIATION, not the description, and that distinction is
	// deliberate: "ensure the workload has two replicas" is how rules phrase a recommendation in
	// prose, and treating that as a hedge pushed ordinary findings to Manual (B-013). So this test
	// puts the precondition where the scan looks — the first draft put it in Description and failed
	// for that reason, which was the test being wrong rather than the code.
	hedged := nsFinding(strings.Replace(cleanLimitRange, "  limits:",
		"  # verify these against real usage first\n  limits:", 1))
	if got := Classify(hedged); got == SafeNow {
		t.Errorf("Classify = %q; a manifest whose own comment says to verify first is not safe-now", got)
	}

	// And the shape the live testbed actually ships: a LimitRange whose body calls itself a starting
	// point. Judging documents by kind removed the accident that used to catch this, so the hedge has
	// to catch it on purpose — otherwise the loop offers as its safest step the one manifest the rule
	// says not to apply blind.
	realWorld := nsFinding(strings.Replace(cleanLimitRange, "      defaultRequest:",
		"      defaultRequest:   # starting point — right-size from usage before applying", 1))
	if got := Classify(realWorld); got == SafeNow {
		t.Errorf("Classify = %q for the governance rule's real remediation; its own text says "+
			"\"starting point — right-size from usage before applying\"", got)
	}
}
