package verdict

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A handoff for a reviewed change has to say what applying it DOES.
//
// The loop was restricted to SafeNow, and SafeNow turned out to occur on no real cluster: the only
// rule emitting an additive kind ships a manifest that honestly calls itself a starting point. A
// feature that cannot happen is worth less than one that tells the truth about a change, so the
// handoff now covers reviewed changes too — and the price of that is naming the disruption in the
// same breath, from the same evidence that classified it, never as boilerplate.
func TestClassifyReason_NamesWhyItIsNotSafe(t *testing.T) {
	podTemplate := types.Finding{
		ID: "f-probe", RuleID: "k8s.workload.no-probes",
		Title:             "Deployment reviews-v1 has no readinessProbe",
		AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "bookinfo", Name: "reviews-v1"}},
		RemediationYAML: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: reviews-v1
  namespace: bookinfo
spec:
  template:
    spec:
      containers:
        - name: reviews
          readinessProbe:
            httpGet: {path: /healthz, port: 9080}
`,
	}
	class, reason := ClassifyReason(podTemplate)
	if class != NeedsReview {
		t.Fatalf("class = %q, want needs-review", class)
	}
	if reason == "" {
		t.Fatal("a reviewed change with no stated reason is a change nobody can review")
	}
	low := strings.ToLower(reason)
	if !strings.Contains(low, "restart") && !strings.Contains(low, "roll") {
		t.Errorf("the reason for a pod-template edit does not mention that pods restart: %q", reason)
	}

	// SafeNow must NOT invent a disruption it does not have.
	safe := nsFinding(cleanQuota)
	if class, reason := ClassifyReason(safe); class != SafeNow || reason != "" {
		t.Errorf("a safe-now finding reported class=%q reason=%q; it disturbs nothing and should say nothing",
			class, reason)
	}
}

// The handoff carries the disruption, prominently, and refuses Manual as before.
func TestBuildHandoff_AReviewedChangeLeadsWithWhatItDoes(t *testing.T) {
	f := types.Finding{
		ID: "f-probe", RuleID: "k8s.workload.no-probes",
		Title:             "Deployment reviews-v1 has no readinessProbe",
		AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "bookinfo", Name: "reviews-v1"}},
		RemediationYAML:   "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: reviews\n",
	}
	h, err := BuildHandoff(f, NeedsReview, "kind-assay-mesh")
	if err != nil {
		t.Fatalf("BuildHandoff on a reviewed change: %v", err)
	}
	if h.Class != NeedsReview {
		t.Errorf("Class = %q; the tier has to travel with the handoff or a UI cannot tell the two apart", h.Class)
	}
	if h.Disruption == "" {
		t.Fatal("a reviewed handoff carries no disruption text")
	}
	if !strings.Contains(strings.ToLower(h.Summary), "restart") &&
		!strings.Contains(strings.ToLower(h.Summary), "roll") {
		t.Errorf("the summary does not lead with what applying this does: %q", h.Summary)
	}

	// A safe change says so, and says nothing about restarts.
	sh, err := BuildHandoff(nsFinding(cleanQuota), SafeNow, "ctx")
	if err != nil {
		t.Fatalf("BuildHandoff on an additive change: %v", err)
	}
	if sh.Disruption != "" {
		t.Errorf("an additive handoff claims a disruption: %q", sh.Disruption)
	}
	if strings.Contains(strings.ToLower(sh.Summary), "restart") {
		t.Errorf("an additive handoff mentions restarts: %q", sh.Summary)
	}

	// Manual is still refused: there is nothing mechanical to hand over.
	hedged := nsFinding(strings.Replace(cleanQuota, "spec:", "# verify these against usage first\nspec:", 1))
	if _, err := BuildHandoff(hedged, Manual, "ctx"); err == nil {
		t.Error("a manual finding produced a handoff; there is no mechanical change to hand over")
	}
}

// A remediation that only LOOKS is not a change, and must never be offered as one.
//
// Found on the live testbed: k8s.workload.privileged-host-access ships
// `kubectl -n monitoring get daemonset … -o yaml | grep -nE 'privileged|hostNetwork|…'` — an
// investigation. It fell through every mutating-verb check into "unrecognised", which the loop then
// offered as a reviewed change with the disruption "what applying this does was not established".
// Applying a grep does nothing, and a loop that offers one is describing a read as a fix.
func TestClassify_AReadOnlyCommandIsNotAFix(t *testing.T) {
	for _, cmd := range []string{
		"kubectl -n monitoring get daemonset node-exporter -o yaml | grep -nE 'privileged|hostNetwork'",
		"kubectl describe pod -n bookinfo reviews-v1",
		"kubectl logs -n bookinfo deploy/reviews-v1 --tail=50",
		"kubectl get ns bookinfo -o jsonpath='{.metadata.labels}'",
	} {
		f := types.Finding{ID: "f-r", RuleID: "k8s.workload.privileged-host-access",
			Title:              "DaemonSet node-exporter runs with hostNetwork",
			AffectedResources:  []types.ResourceRef{{Kind: "DaemonSet", Namespace: "monitoring", Name: "node-exporter"}},
			RemediationCommand: cmd}
		if got := Classify(f); got != Manual {
			t.Errorf("Classify(%q) = %q, want manual — this command reads, it does not change anything", cmd, got)
		}
		if _, err := BuildHandoff(f, Classify(f), "ctx"); err == nil {
			t.Errorf("a read-only command produced a handoff: %q", cmd)
		}
	}
}

// A namespace label change is characterised, not shrugged at.
//
// k8s.namespace.pss-admission-not-enforced ships `kubectl label --overwrite namespace X
// pod-security.kubernetes.io/warn=baseline pod-security.kubernetes.io/audit=baseline`. warn and
// audit never reject a pod, so nothing running is disturbed — but --overwrite replaces whatever was
// there, and a reviewer is owed that sentence rather than "what applying this does was not
// established".
func TestClassify_ALabelChangeSaysWhatItDoes(t *testing.T) {
	f := types.Finding{ID: "f-pss", RuleID: "k8s.namespace.pss-admission-not-enforced",
		Title:              "Namespace bookinfo does not enforce Pod Security admission",
		AffectedResources:  []types.ResourceRef{{Kind: "Namespace", Name: "bookinfo"}},
		RemediationCommand: "kubectl label --overwrite namespace bookinfo pod-security.kubernetes.io/warn=baseline pod-security.kubernetes.io/audit=baseline"}

	class, reason := ClassifyReason(f)
	if class == Manual {
		t.Fatalf("a label change is a real, mechanical change; got %q", class)
	}
	low := strings.ToLower(reason)
	if strings.Contains(low, "not established") {
		t.Errorf("the reason shrugs where it could be specific: %q", reason)
	}
	if !strings.Contains(low, "label") {
		t.Errorf("the reason does not say this changes labels: %q", reason)
	}
	// "replac" and not "replace": the sentence says "replacing", and a literal check for the
	// infinitive fails on correct copy. This assertion was wrong before the code was.
	if !strings.Contains(low, "overwrite") && !strings.Contains(low, "replac") {
		t.Errorf("the reason does not mention that --overwrite replaces an existing value: %q", reason)
	}
}
