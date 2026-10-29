package verdict

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// --- fixtures modelled on what the kind testbed actually produced -----------------------
//
// The shapes here are not invented: they mirror the findings observed on the mesh testbed on
// 2026-08-17, where the visible cards were led by three variants of one hedged
// "namespace has no NetworkPolicy" observation while the only finding carrying dollars sat
// among them undistinguished. See docs/qa/peak-review-2026-08.md.

func idleHog() types.Finding {
	return types.Finding{
		ID:                  "f-idlehog",
		RuleID:              "k8s.cost.overprovisioned-requests",
		Title:               "Right-size over-provisioned requests on waste/idle-hog",
		WhyItMatters:        "The workload requests far more CPU and memory than it has ever used. The unused reservation is billed and blocks scheduling.",
		Severity:            types.SeverityMedium,
		Category:            types.CategoryCost,
		DollarImpactMonthly: 48.34,
		EstimatedEffort:     types.EffortLow,
		Confidence:          0.9,
		RemediationYAML:     "resources:\n  requests:\n    cpu: 50m\n    memory: 64Mi\n",
		AffectedResources: []types.ResourceRef{
			{Kind: "Deployment", Namespace: "waste", Name: "idle-hog"},
		},
	}
}

// netpol builds one of the blanket, hedged NetworkPolicy findings — same rule, one per
// namespace, no dollars, and its own text admits it may not apply.
func netpol(ns string) types.Finding {
	return types.Finding{
		ID:              "f-netpol-" + ns,
		RuleID:          "k8s.security.namespace-no-networkpolicy",
		Title:           "Namespace " + ns + " has no NetworkPolicy",
		Description:     "Add a default-deny NetworkPolicy if its CNI enforces policy.",
		WhyItMatters:    "Without a policy every pod in the namespace can reach every other pod, if the CNI enforces policy at all.",
		Severity:        types.SeverityMedium,
		Category:        types.CategorySecurity,
		EstimatedEffort: types.EffortMedium,
		Confidence:      0.7,
		RemediationYAML: "kind: NetworkPolicy\nmetadata:\n  name: default-deny\n",
		AffectedResources: []types.ResourceRef{
			{Kind: "Namespace", Namespace: ns, Name: ns},
		},
	}
}

// limitRange is the shape that survives as genuinely SafeNow: a namespace-scoped object that
// constrains future pods without touching any running one.
func limitRange() types.Finding {
	return types.Finding{
		ID:              "f-limitrange",
		RuleID:          "k8s.config.namespace-no-limitrange",
		Title:           "Add a LimitRange to namespace waste",
		WhyItMatters:    "Without defaults, containers with no request land in BestEffort QoS and are evicted first.",
		Severity:        types.SeverityLow,
		Category:        types.CategoryConfig,
		EstimatedEffort: types.EffortLow,
		Confidence:      0.9,
		RemediationYAML: "apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: defaults\n  namespace: waste\n",
		AffectedResources: []types.ResourceRef{
			{Kind: "Namespace", Namespace: "waste", Name: "waste"},
		},
	}
}

func criticalNoMoney() types.Finding {
	return types.Finding{
		ID:              "f-crit",
		RuleID:          "k8s.security.cluster-admin-binding",
		Title:           "ServiceAccount bound to cluster-admin",
		WhyItMatters:    "Any pod using this ServiceAccount can do anything in the cluster.",
		Severity:        types.SeverityCritical,
		Category:        types.CategorySecurity,
		EstimatedEffort: types.EffortMedium,
		Confidence:      1,
		AffectedResources: []types.ResourceRef{
			{Kind: "ClusterRoleBinding", Name: "deployer-admin"},
		},
	}
}

// --- §6 the acceptance target ------------------------------------------------------------

// TestPriority_IdleHogOutranksBlanketNetworkPolicyFindings pins the one outcome that is not
// negotiable, whatever weighting priority.go ends up carrying: on the testbed's finding set,
// the thing to do first is the over-provisioning that carries every dollar on the page — not a
// conditional observation repeated once per namespace.
func TestPriority_IdleHogOutranksBlanketNetworkPolicyFindings(t *testing.T) {
	findings := []types.Finding{
		netpol("bookinfo"), netpol("istio-system"), netpol("monitoring"),
		idleHog(),
	}
	sel := Select(findings, 3)
	if len(sel.Top) == 0 {
		t.Fatal("Select returned no leaders")
	}
	if got := sel.Top[0].Finding.RuleID; got != "k8s.cost.overprovisioned-requests" {
		t.Errorf("leader = %q (%s), want the over-provisioning finding — a hedged blanket "+
			"observation must never be what the client is told to do first",
			got, sel.Top[0].Finding.Title)
	}
}

// --- §3.1 the invariant -------------------------------------------------------------------

func TestVerdict_HeadlineUnchangedByLens(t *testing.T) {
	findings := []types.Finding{idleHog(), netpol("a"), netpol("b"), criticalNoMoney()}
	var want float64
	for _, f := range findings {
		want += f.DollarImpactMonthly
	}

	for _, n := range []int{1, 3, 99} {
		sel := Select(findings, n)
		if sel.TotalDollars != want {
			t.Errorf("n=%d: TotalDollars = %.2f, want %.2f — the lens must not move the headline",
				n, sel.TotalDollars, want)
		}
		var shown float64
		for _, r := range sel.Top {
			shown += r.Finding.DollarImpactMonthly
		}
		if sum := shown + sel.RestDollars; sum != want {
			t.Errorf("n=%d: shown %.2f + rest %.2f = %.2f, want %.2f — every dollar must be accounted for",
				n, shown, sel.RestDollars, sum, want)
		}
	}
}

// --- §3.2 determinism ---------------------------------------------------------------------

func TestSelect_Deterministic(t *testing.T) {
	// Deliberately identical scores, so only the tie-break can order them.
	twins := []types.Finding{}
	for _, id := range []string{"c", "a", "b"} {
		f := idleHog()
		f.ID = "f-" + id
		f.RuleID = "rule." + id
		twins = append(twins, f)
	}
	first := Select(twins, 3)
	for i := 0; i < 5; i++ {
		again := Select(twins, 3)
		for j := range first.Top {
			if first.Top[j].Finding.ID != again.Top[j].Finding.ID {
				t.Fatalf("run %d position %d: %q then %q — the same report must always yield the same podium",
					i, j, first.Top[j].Finding.ID, again.Top[j].Finding.ID)
			}
		}
	}
	// And the tie-break must be the documented one: RuleID ascending.
	if first.Top[0].Finding.RuleID != "rule.a" {
		t.Errorf("tie-break leader = %q, want rule.a (RuleID ascending)", first.Top[0].Finding.RuleID)
	}
}

// --- §3.3 confidence is never safety ------------------------------------------------------

func TestSafety_IgnoresConfidence(t *testing.T) {
	// A certain problem with a disruptive fix, and an uncertain problem with a harmless one.
	certainDisruptive := idleHog()
	certainDisruptive.Confidence = 1
	certainDisruptive.RemediationYAML = "kind: NetworkPolicy\n"

	uncertainAdditive := limitRange()
	uncertainAdditive.Confidence = 0.2

	if got := Classify(certainDisruptive); got != NeedsReview {
		t.Errorf("certain + disruptive = %q, want needs-review — certainty is not safety", got)
	}
	if got := Classify(uncertainAdditive); got != SafeNow {
		t.Errorf("uncertain + additive = %q, want safe-now — doubt about the problem says nothing about the fix", got)
	}
}

// --- §3.4 no fabrication ------------------------------------------------------------------

func TestRationale_EveryClaimTracesToASourceField(t *testing.T) {
	f := idleHog()
	r := Ranked{Finding: f, Safety: Classify(f), CollapsedFrom: 1}
	got := Rationale(r)

	// No formatted currency may appear: this package cannot see the report's single
	// money format, so a baked-in string here would be a second implementation of it. The
	// report's TestRender_NoUngroupedDollars caught exactly that on the first render.
	if strings.Contains(got, "$") {
		t.Errorf("rationale embeds a formatted currency — each surface formats money itself: %q", got)
	}
	// The verbatim clause must be the finding's own leading sentence, not a paraphrase.
	lead := firstSentence(f.WhyItMatters)
	if !strings.Contains(got, lead) {
		t.Errorf("rationale does not carry WhyItMatters verbatim.\n got: %q\nwant substring: %q", got, lead)
	}
	// Nothing may appear that the finding does not support. "namespaces" plural is only legal
	// when more than one namespace is affected — here exactly one is.
	if strings.Contains(got, "namespaces") {
		t.Errorf("rationale claims multiple namespaces for a single-namespace finding: %q", got)
	}
}

// --- §3.5 hedged findings may not lead ----------------------------------------------------

func TestSelect_HedgedFindingCannotLead(t *testing.T) {
	// The hedged finding is the ONLY high-severity one, and still must not lead.
	hedged := netpol("bookinfo")
	hedged.Severity = types.SeverityHigh
	sel := Select([]types.Finding{hedged, idleHog()}, 2)
	if sel.Top[0].Finding.RuleID == hedged.RuleID {
		t.Errorf("a finding whose own text says it may not apply led the podium: %q", sel.Top[0].Finding.Title)
	}
	// It must still be present — honest to report, dishonest to put first.
	found := false
	for _, r := range sel.Top {
		if r.Finding.RuleID == hedged.RuleID {
			found = true
		}
	}
	if !found && sel.RestCount == 0 {
		t.Error("the hedged finding vanished entirely — this is a lens, not a filter")
	}
}

// --- §3.6 edge cases ----------------------------------------------------------------------

func TestSelect_EmptyAndSingleFinding(t *testing.T) {
	empty := Select(nil, 3)
	if len(empty.Top) != 0 || empty.TotalDollars != 0 || empty.RestCount != 0 {
		t.Errorf("empty input produced %+v, want a zero Selection", empty)
	}

	one := Select([]types.Finding{idleHog()}, 3)
	if len(one.Top) != 1 {
		t.Fatalf("single finding produced %d leaders, want 1", len(one.Top))
	}
	if one.RestCount != 0 || one.RestDollars != 0 {
		t.Errorf("single finding left a remainder: count=%d dollars=%.2f", one.RestCount, one.RestDollars)
	}
}

func TestSelect_AllZeroDollarsStillRanks(t *testing.T) {
	// The AKS shape: thousands of findings, most of them with no cost model at all. Ranking
	// must not collapse to "whatever order they arrived in".
	a, b := criticalNoMoney(), netpol("x")
	sel := Select([]types.Finding{b, a}, 2)
	if sel.Top[0].Finding.ID != a.ID {
		t.Errorf("leader = %q, want the critical finding — severity must still order when nothing has a price",
			sel.Top[0].Finding.ID)
	}
}

// --- §4 collapse --------------------------------------------------------------------------

func TestSelect_CollapsesSameRuleAcrossNamespaces(t *testing.T) {
	findings := []types.Finding{
		netpol("bookinfo"), netpol("istio-system"), netpol("monitoring"), idleHog(),
	}
	sel := Select(findings, 10)

	seen := map[string]int{}
	for _, r := range sel.Top {
		seen[r.Finding.RuleID]++
	}
	if seen["k8s.security.namespace-no-networkpolicy"] != 1 {
		t.Errorf("the NetworkPolicy rule appears %d times, want 1 — three namespaces is one observation",
			seen["k8s.security.namespace-no-networkpolicy"])
	}
	for _, r := range sel.Top {
		if r.Finding.RuleID != "k8s.security.namespace-no-networkpolicy" {
			continue
		}
		if r.CollapsedFrom != 3 {
			t.Errorf("CollapsedFrom = %d, want 3", r.CollapsedFrom)
		}
		// A collapsed card must not understate its reach.
		if len(r.Finding.AffectedResources) != 3 {
			t.Errorf("collapsed card lists %d resources, want the union of 3",
				len(r.Finding.AffectedResources))
		}
	}
}

func TestSelect_CollapsedDollarsAreSummedNotDropped(t *testing.T) {
	a, b := idleHog(), idleHog()
	b.ID, b.DollarImpactMonthly = "f-idlehog-2", 10
	sel := Select([]types.Finding{a, b}, 1)
	if len(sel.Top) != 1 {
		t.Fatalf("want 1 collapsed leader, got %d", len(sel.Top))
	}
	if got, want := sel.Top[0].Finding.DollarImpactMonthly, 58.34; got != want {
		t.Errorf("collapsed dollars = %.2f, want %.2f (summed, not the representative's own)", got, want)
	}
	if sel.TotalDollars != want58() {
		t.Errorf("TotalDollars = %.2f, want %.2f", sel.TotalDollars, want58())
	}
}

func want58() float64 { return 58.34 }

// --- safety polarity: SafeNow must be earned, not inferred from silence -------------------

// TestSafety_ScaleCommandIsNotSafeNow comes from the first real-data run of this package.
// On the AKS dev cluster the top-ranked finding was "Single replica without PDB", whose
// remediation is `kubectl -n batch scale deployment/metrics-agent --replicas=2`, and the
// first version of Classify called that safe-now — printing "remediation is additive and does
// not restart workloads" about a command that changes a live workload's replica count.
//
// The marker list had "replicas:" in its YAML form and missed the command form, but the real
// defect was the POLARITY: safety was inferred from the absence of a danger signal. That is
// the same mistake the project's denial-guard already forbids elsewhere — never assert absence
// from not having seen something. SafeNow is now granted only on positive evidence of an
// additive change.
func TestSafety_ScaleCommandIsNotSafeNow(t *testing.T) {
	f := types.Finding{
		ID:     "f-pdb",
		RuleID: "k8s.workload.single-replica-no-pdb",
		Title:  "Single replica without PDB: batch/metrics-agent",
		RemediationCommand: "kubectl -n batch scale deployment/metrics-agent --replicas=2\n" +
			"# only AFTER ≥2 replicas, add a PodDisruptionBudget (e.g. maxUnavailable: 1)",
	}
	if got := Classify(f); got == SafeNow {
		t.Errorf("Classify = %q for a kubectl scale command — changing a live workload's replica "+
			"count is not additive", got)
	}
}

func TestSafety_UnrecognisedRemediationDefaultsToReview(t *testing.T) {
	// A remediation shape nobody has thought about yet must land in the cautious class, not
	// the reassuring one.
	f := types.Finding{
		ID:              "f-novel",
		RuleID:          "some.future.rule",
		RemediationYAML: "someFutureKey:\n  doSomething: true\n",
	}
	if got := Classify(f); got == SafeNow {
		t.Errorf("Classify = %q for an unrecognised remediation — SafeNow must be earned", got)
	}
}

// TestSafety_ResourcesChangeIsReviewNotSafe replaces an earlier test that asserted the
// opposite. It claimed a "pure resources/requests change" was SafeNow, which is how B-008
// reached the screen: the belief was wrong, not the code, and a test encoding a wrong belief is
// worse than no test.
func TestSafety_ResourcesChangeIsReviewNotSafe(t *testing.T) {
	if got := Classify(idleHog()); got != NeedsReview {
		t.Errorf("Classify = %q for a resources/requests change, want needs-review — it edits the pod template", got)
	}
}

// --- StartHere: separate from the podium, and always actually safe -------------------------

// TestSelect_StartHereIsSafeAndMayDifferFromTheLeader encodes what the first real-data run
// taught: on the AKS dev cluster the two most important findings have no mechanical fix at
// all, so "what matters most" and "where to start safely" are different answers and the
// product must be able to give both without either borrowing the other's authority.
func TestSelect_StartHereIsSafeAndMayDifferFromTheLeader(t *testing.T) {
	// A critical finding with no remediation outranks a modest but mechanically safe one.
	sel := Select([]types.Finding{criticalNoMoney(), limitRange()}, 2)

	if sel.Top[0].Finding.ID != "f-crit" {
		t.Fatalf("leader = %q, want the critical finding", sel.Top[0].Finding.ID)
	}
	if sel.StartHere == nil {
		t.Fatal("StartHere is nil although a safe-now finding exists")
	}
	if sel.StartHere.Finding.ID != "f-limitrange" {
		t.Errorf("StartHere = %q, want the safe-now finding", sel.StartHere.Finding.ID)
	}
	if sel.StartHere.Safety != SafeNow {
		t.Errorf("StartHere.Safety = %q — this field may only ever point at a safe-now finding", sel.StartHere.Safety)
	}
}

func TestSelect_StartHereIsNilWhenNothingIsSafe(t *testing.T) {
	// The honest empty answer: a cluster where every fix needs a human gets no "start here"
	// rather than a promoted unsafe one.
	sel := Select([]types.Finding{criticalNoMoney(), netpol("a")}, 2)
	if sel.StartHere != nil {
		t.Errorf("StartHere = %q (%s), want nil — nothing here is safe to apply mechanically",
			sel.StartHere.Finding.ID, sel.StartHere.Safety)
	}
}

// TestSelect_StartHereSearchesBeyondThePodium — the safe option is worth surfacing even when
// it did not rank in the top n.
func TestSelect_StartHereSearchesBeyondThePodium(t *testing.T) {
	sel := Select([]types.Finding{criticalNoMoney(), netpol("a"), netpol("b"), limitRange()}, 1)
	if len(sel.Top) != 1 {
		t.Fatalf("want a podium of 1, got %d", len(sel.Top))
	}
	if sel.StartHere == nil || sel.StartHere.Finding.ID != "f-limitrange" {
		t.Errorf("StartHere = %v, want the safe-now finding found outside the podium", sel.StartHere)
	}
}

// TestSafety_PodTemplateChangeIsNotRestartFree is B-008, found by reading the podium the
// theater rendered on the live testbed: "Safest place to begin: Set resource requests on
// bookinfo/details-v1 — additive, no workload restart."
//
// That is false. Editing container resources edits the Deployment's pod template, which
// creates a new ReplicaSet and rolls every pod. The additive allowlist had "resources:" and
// "requests:" in it, so the same optimistic-direction error as B-002's polarity bug reappeared
// one layer up: a shape that looks harmless in YAML is disruptive in effect.
//
// The wider consequence is a product one, not a code one. Almost no Kubernetes remediation is
// restart-free — resources, probes, security contexts and images all touch the pod template;
// scaling adds pods; NetworkPolicy changes reachability; a PDB changes drain behaviour. So
// "does not restart anything" is very nearly an empty class, and SafeNow keeps only the changes
// that genuinely do not touch running pods.
func TestSafety_PodTemplateChangeIsNotRestartFree(t *testing.T) {
	f := types.Finding{
		ID:              "f-req",
		RuleID:          "k8s.workload.missing-requests",
		Title:           "Set resource requests on bookinfo/details-v1",
		RemediationYAML: "spec:\n  template:\n    spec:\n      containers:\n        - name: details\n          resources:\n            requests:\n              cpu: 50m\n",
	}
	if got := Classify(f); got == SafeNow {
		t.Errorf("Classify = %q — editing container resources rolls the workload's pods", got)
	}
}

func TestSafety_NamespaceScopedAdditiveObjectsStaySafeNow(t *testing.T) {
	// What remains genuinely restart-free: a namespace-scoped object that does not touch any
	// running pod.
	for _, yaml := range []string{
		"apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: defaults\n",
		"apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: quota\n",
	} {
		f := types.Finding{ID: "f-x", RuleID: "r.x", RemediationYAML: yaml}
		if got := Classify(f); got != SafeNow {
			t.Errorf("Classify = %q for %.30q…, want safe-now", got, yaml)
		}
	}
}

// TestFirstSentence_DoesNotSplitInsideANumber is B-009, read straight off the rendered report:
// the podium showed "but the burst peaks at 1" where the finding says "peaks at 1.4 vCPU per
// pod". firstSentence cut at the first '.', and that '.' was a decimal point.
//
// Truncating prose is a cosmetic loss; truncating a NUMBER changes a value the client will
// quote. 1.4 vCPU reading as 1 vCPU is the same class of defect as any other wrong figure, and
// it arrived through the one clause of the rationale that is supposed to be verbatim.
func TestFirstSentence_DoesNotSplitInsideANumber(t *testing.T) {
	cases := []struct{ in, want string }{
		{"but the burst peaks at 1.4 vCPU per pod. The current sizing was set in 2023",
			"but the burst peaks at 1.4 vCPU per pod"},
		{"p99 is 12.5ms today. Yesterday it was worse.", "p99 is 12.5ms today"},
		{"Two sentences here. And another.", "Two sentences here"},
		{"No terminator at all", "No terminator at all"},
		{"Version 1.2.3 is affected. Upgrade.", "Version 1.2.3 is affected"},
		{"Ends with a decimal 0.5", "Ends with a decimal 0.5"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := firstSentence(tc.in); got != tc.want {
			t.Errorf("firstSentence(%q)\n got:  %q\n want: %q", tc.in, got, tc.want)
		}
	}
}

// --- T1.6 remaining coverage ---------------------------------------------------------------

// TestCollapse_RepresentativeIsTheMostSevereThenTheMostExpensive — the card that speaks for a
// group must be its worst member, not whichever happened to be collected first. A group led by
// its mildest instance understates itself.
func TestCollapse_RepresentativeIsTheMostSevereThenTheMostExpensive(t *testing.T) {
	mk := func(id string, sev types.Severity, usd float64) types.Finding {
		f := base()
		f.ID, f.RuleID, f.Severity, f.DollarImpactMonthly = id, "same.rule", sev, usd
		return f
	}
	// Deliberately collected worst-last.
	sel := Select([]types.Finding{
		mk("f-low", types.SeverityLow, 5),
		mk("f-med-cheap", types.SeverityMedium, 1),
		mk("f-med-dear", types.SeverityMedium, 900),
		mk("f-high", types.SeverityHigh, 0),
	}, 1)

	if len(sel.Top) != 1 {
		t.Fatalf("want one collapsed group, got %d", len(sel.Top))
	}
	got := sel.Top[0]
	if got.Finding.ID != "f-high" {
		t.Errorf("representative = %q, want f-high (severity decides first)", got.Finding.ID)
	}
	if got.CollapsedFrom != 4 {
		t.Errorf("CollapsedFrom = %d, want 4", got.CollapsedFrom)
	}
	// The representative carries the GROUP's money, not its own.
	if want := 906.0; got.Finding.DollarImpactMonthly != want {
		t.Errorf("group dollars = %.2f, want %.2f", got.Finding.DollarImpactMonthly, want)
	}
	// Same severity → the dearer one represents.
	sel2 := Select([]types.Finding{
		mk("f-med-cheap", types.SeverityMedium, 1),
		mk("f-med-dear", types.SeverityMedium, 900),
	}, 1)
	if sel2.Top[0].Finding.ID != "f-med-dear" {
		t.Errorf("representative = %q, want f-med-dear (money breaks a severity tie)", sel2.Top[0].Finding.ID)
	}
}

// TestSafety_VerbMatchingDoesNotFireOnSubstrings — the mutating-verb check is padded so an object
// whose NAME contains a verb is not mistaken for the verb. Over-triggering here would push
// genuinely safe remediations into needs-review and make "start here" disappear for no reason.
func TestSafety_VerbMatchingDoesNotFireOnSubstrings(t *testing.T) {
	safe := []string{
		"kubectl get deployment/scaler -o yaml",    // "scaler" is not `scale`
		"kubectl get deploy/patcher -n ops",        // "patcher" is not `patch`
		"kubectl describe deployment/settings-api", // "settings" is not `set`
		"kubectl get statefulset/creator",          // "creator" is not `create`
	}
	for _, cmd := range safe {
		f := types.Finding{ID: "f", RuleID: "r", RemediationYAML: "kind: LimitRange\n", RemediationCommand: cmd}
		if got := Classify(f); got != SafeNow {
			t.Errorf("Classify = %q for %q — a name containing a verb is not the verb", got, cmd)
		}
	}

	mutating := []string{
		"kubectl scale deploy/x --replicas=2",
		"kubectl delete pdb/x -n ops",
		"kubectl rollout restart deploy/x",
		"kubectl patch deploy/x -p '{}'",
	}
	for _, cmd := range mutating {
		f := types.Finding{ID: "f", RuleID: "r", RemediationYAML: "kind: LimitRange\n", RemediationCommand: cmd}
		if got := Classify(f); got == SafeNow {
			t.Errorf("Classify = %q for %q — this changes a live object", got, cmd)
		}
	}
}

// TestSafety_DisruptiveHalfDecidesAMixedRemediation — a remediation that both adds a LimitRange
// and edits a pod template is judged by the half that restarts things.
func TestSafety_DisruptiveHalfDecidesAMixedRemediation(t *testing.T) {
	f := types.Finding{
		ID: "f-mixed", RuleID: "r.mixed",
		RemediationYAML: "kind: LimitRange\nmetadata:\n  name: defaults\n---\n" +
			"spec:\n  template:\n    spec:\n      containers:\n        - name: app\n          resources: {}\n",
	}
	if got := Classify(f); got == SafeNow {
		t.Errorf("Classify = %q — a mixed remediation is only as safe as its riskiest half", got)
	}
}

// --- the safety axis, corrected: scaling UP is additive -------------------------------------
//
// Found by reading the podium the theater rendered on the real AKS cluster: the leading finding is
// "Single replica without PDB" across 102 workloads, its remediation is
// `kubectl scale deploy/x --replicas=2`, and the classifier called it needs-review because the
// command contained a mutating verb. But scaling UP creates a new pod and leaves the running one
// untouched, is reversible with one command, and is bounded to a single workload — that is exactly
// what SafeNow is supposed to mean.
//
// The direction is not visible in the command text; it is only visible against the CURRENT replica
// count, which lives in Architecture.WorkloadNodes. So safety is a property of the pair
// (remediation × target workload), never of the remediation string alone. Where the current count
// is unknown — the Architecture is trimmed per namespace — the answer stays conservative.

func replicaLookup(m map[string]int) ReplicaLookup {
	return func(ref types.ResourceRef) (int, bool) {
		n, ok := m[ref.Kind+"/"+ref.Namespace+"/"+ref.Name]
		return n, ok
	}
}

func singleReplicaNoPDB() types.Finding {
	return types.Finding{
		ID:       "f-pdb",
		RuleID:   "k8s.workload.single-replica-no-pdb",
		Title:    "Single replica without PDB: batch/metrics-agent",
		Severity: types.SeverityHigh,
		WhyItMatters: "This replica is behind a Service on a serving port, so a node event can " +
			"cause a user-visible outage window until the pod reschedules",
		Confidence:         0.9,
		RemediationCommand: "kubectl -n batch scale deployment/metrics-agent --replicas=2",
		AffectedResources: []types.ResourceRef{
			{Kind: "Deployment", Namespace: "batch", Name: "metrics-agent"},
		},
	}
}

func TestSafety_ScalingUpIsAdditive(t *testing.T) {
	f := singleReplicaNoPDB()
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got != SafeNow {
		t.Errorf("ClassifyWith = %q for a 1→2 scale — a new pod is created and the running one is "+
			"untouched, reversible in one command", got)
	}
}

func TestSafety_ScalingDownIsNot(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n batch scale deployment/metrics-agent --replicas=2"
	// The workload already has 5 replicas, so "--replicas=2" removes capacity.
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 5})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q for a 5→2 scale — removing capacity is not additive", got)
	}
}

func TestSafety_UnknownCurrentReplicasStaysConservative(t *testing.T) {
	f := singleReplicaNoPDB()
	// Architecture is trimmed per namespace, so a workload may simply be absent.
	for name, lookup := range map[string]ReplicaLookup{
		"nil lookup":   nil,
		"empty lookup": replicaLookup(map[string]int{}),
	} {
		if got := ClassifyWith(f, lookup); got == SafeNow {
			t.Errorf("%s: ClassifyWith = %q — an unknown current count cannot license a safety claim", name, got)
		}
	}
}

func TestSafety_ScaleUpWithAnyOtherMutatingVerbIsNotSafe(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n batch scale deployment/metrics-agent --replicas=2 && " +
		"kubectl -n batch delete pdb/metrics-agent"
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — a scale-up bundled with a delete is only as safe as the delete", got)
	}
}

func TestSafety_ScaleUpAcrossManyTargetsNeedsAllOfThemKnown(t *testing.T) {
	// A collapsed finding covers several workloads. If any target's current count is unknown, or
	// any would be a scale-down, the group is not safe.
	f := singleReplicaNoPDB()
	f.AffectedResources = append(f.AffectedResources,
		types.ResourceRef{Kind: "Deployment", Namespace: "batch", Name: "web-frontend"})

	partial := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})
	if got := ClassifyWith(f, partial); got == SafeNow {
		t.Errorf("ClassifyWith = %q with one of two targets unknown", got)
	}

	both := replicaLookup(map[string]int{
		"Deployment/batch/metrics-agent": 1,
		"Deployment/batch/web-frontend":  1,
	})
	if got := ClassifyWith(f, both); got != SafeNow {
		t.Errorf("ClassifyWith = %q with every target a known scale-up, want safe-now", got)
	}
}

// TestSelect_StartHereIsAnIndividualFindingNotACollapsedGroup — found on the real AKS report,
// where 14 findings classified safe-now and StartHere was still nil.
//
// The cause was that StartHere was picked from the collapsed groups. Collapsing unions every
// member's AffectedResources, so the representative of the single-replica rule carried 102 targets
// and the safety check correctly refused: applying one change to 102 workloads at once is not
// additive. True, and useless — "where do I start" is by definition ONE action on ONE target.
//
// So collapsing stays a presentation device for the podium, and StartHere is chosen from the
// individual findings.
func TestSelect_StartHereIsAnIndividualFindingNotACollapsedGroup(t *testing.T) {
	// Twelve instances of one rule, each a provable 1→2 scale-up on its own workload.
	var findings []types.Finding
	replicas := map[string]int{}
	for i := 0; i < 12; i++ {
		f := singleReplicaNoPDB()
		name := fmt.Sprintf("wl-%02d", i)
		f.ID = "f-" + name
		f.RemediationCommand = "kubectl -n batch scale deployment/" + name + " --replicas=2"
		f.AffectedResources = []types.ResourceRef{{Kind: "Deployment", Namespace: "batch", Name: name}}
		findings = append(findings, f)
		replicas["Deployment/batch/"+name] = 1
	}
	// One unrelated, more severe finding with no remediation, so it leads the podium.
	findings = append(findings, criticalNoMoney())

	sel := SelectWith(findings, 2, replicaLookup(replicas))

	// The podium collapses the twelve into one group, which is NOT safe as a group.
	var group *Ranked
	for i := range sel.Top {
		if sel.Top[i].Finding.RuleID == "k8s.workload.single-replica-no-pdb" {
			group = &sel.Top[i]
		}
	}
	if group == nil {
		t.Fatal("the collapsed single-replica group is missing from the podium")
	}
	if group.CollapsedFrom != 12 {
		t.Errorf("CollapsedFrom = %d, want 12", group.CollapsedFrom)
	}

	// But there IS a concrete safe action, and it must be offered.
	if sel.StartHere == nil {
		t.Fatal("StartHere is nil although twelve individually-safe scale-ups exist")
	}
	if sel.StartHere.Safety != SafeNow {
		t.Errorf("StartHere.Safety = %q, want safe-now", sel.StartHere.Safety)
	}
	if got := sel.StartHere.CollapsedFrom; got != 1 {
		t.Errorf("StartHere.CollapsedFrom = %d, want 1 — a starting point is one action on one target", got)
	}
	if n := len(sel.StartHere.Finding.AffectedResources); n != 1 {
		t.Errorf("StartHere targets %d resources, want 1", n)
	}
}

// --- B-012: two more ways a safety claim outran its evidence ---------------------------------
//
// Both found by reading what StartHere actually pointed at on the real AKS report: a 1→2 scale of
// a StatefulSet, offered as "additive and does not restart workloads", whose own remediation text
// began "# verify the app supports >1 replica (replication/quorum) before scaling a StatefulSet".
//
// This is the third time in one sitting that a safety claim was more confident than its evidence,
// and the third time real output caught it rather than a test. The pattern is worth naming: any
// classifier that says something reassuring must be tested against the thing it describes, not
// against a fixture written from the same assumption.

func TestSafety_RemediationTextCanHedgeToo(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "# verify the app supports >1 replica (replication/quorum) before scaling\n" +
		"kubectl -n batch scale deployment/metrics-agent --replicas=2"
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — a remediation that says \"verify X before\" is a conditional "+
			"instruction, not a mechanical fix", got)
	}
}

func TestSafety_ScalingAStatefulSetIsNotAdditive(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n obs scale statefulset/alertmanager --replicas=2"
	f.AffectedResources = []types.ResourceRef{
		{Kind: "StatefulSet", Namespace: "obs", Name: "alertmanager"},
	}
	lookup := replicaLookup(map[string]int{"StatefulSet/obs/alertmanager": 1})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — a second StatefulSet replica may need quorum or peer "+
			"configuration to be correct, so adding one is not merely additive", got)
	}
}

func TestSafety_ScalingADeploymentUpStaysAdditive(t *testing.T) {
	// The distinction must not swallow the case it was built for.
	f := singleReplicaNoPDB()
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})
	if got := ClassifyWith(f, lookup); got != SafeNow {
		t.Errorf("ClassifyWith = %q for a 1→2 Deployment scale, want safe-now", got)
	}
}

func TestSafety_DaemonSetHasNoScaleToBeSafeAbout(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n kube-system scale daemonset/agent --replicas=2"
	f.AffectedResources = []types.ResourceRef{
		{Kind: "DaemonSet", Namespace: "kube-system", Name: "agent"},
	}
	lookup := replicaLookup(map[string]int{"DaemonSet/kube-system/agent": 1})
	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — a DaemonSet's replica count is not a thing to raise", got)
	}
}

// TestSafety_CommentProseIsNotAnOperation is B-013, and it is the mirror image of B-008.
//
// The single-replica rule's Deployment remediation is:
//
//	kubectl -n batch scale deployment/metrics-agent --replicas=2
//	# only AFTER ≥2 replicas, add a PodDisruptionBudget (…); a minAvailable equal to the
//	# replica count deadlocks every node drain
//
// The verb scanner matched " drain " — inside the explanatory comment — and demoted a provable
// 1→2 scale-up to needs-review. On the real AKS report that took safe-now from 14 to 0, so the
// product said "no mechanically safe starting point" about a cluster with 56 provable ones.
//
// The lesson is that one text region means opposite things to the two checks: operation verbs are
// only meaningful in the EXECUTABLE part, while preconditions ("verify X before") live precisely in
// the comments. Scanning both the same way is wrong by construction.
func TestSafety_CommentProseIsNotAnOperation(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n batch scale deployment/metrics-agent --replicas=2\n" +
		"# only AFTER ≥2 replicas, add a PodDisruptionBudget (e.g. maxUnavailable: 1); " +
		"a minAvailable equal to the replica count deadlocks every node drain"
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got != SafeNow {
		t.Errorf("ClassifyWith = %q — the words in a trailing explanatory comment are prose, not "+
			"operations; the executable line is a plain 1→2 scale", got)
	}
}

// TestSafety_RealMutatingVerbInTheExecutableLineStillCounts — the fix must not blind the scanner.
func TestSafety_RealMutatingVerbInTheExecutableLineStillCounts(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "kubectl -n batch drain node/aks-worker-1\n# harmless comment"
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — an actual drain is not safe", got)
	}
}

// TestSafety_PreconditionInACommentStillDisqualifies — the other direction: a hedge in a comment
// must keep working, because that is where rule authors put them.
func TestSafety_PreconditionInACommentStillDisqualifies(t *testing.T) {
	f := singleReplicaNoPDB()
	f.RemediationCommand = "# verify the app supports >1 replica before scaling\n" +
		"kubectl -n batch scale deployment/metrics-agent --replicas=2"
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got == SafeNow {
		t.Errorf("ClassifyWith = %q — a precondition in a comment is still a precondition", got)
	}
}

// TestSafety_OrdinaryProseIsNotAHedge — "ensure" and friends are how rules phrase a
// recommendation. They may only disqualify when they appear as a precondition in a remediation,
// never when they appear in a finding's own description.
func TestSafety_OrdinaryProseIsNotAHedge(t *testing.T) {
	f := singleReplicaNoPDB()
	f.Description = "Ensure the workload has more than one replica so a node event cannot take it offline."
	f.WhyItMatters = "Verify coverage across zones; confirm the Service still routes."
	lookup := replicaLookup(map[string]int{"Deployment/batch/metrics-agent": 1})

	if got := ClassifyWith(f, lookup); got != SafeNow {
		t.Errorf("ClassifyWith = %q — imperative prose in a description is not a conditional fix", got)
	}
}

// TestStartHere_NeverOffersAPlaceholderRemediation locks something that is currently true by luck.
//
// Several rules deliberately hand over a PLACEHOLDER remediation — the missing-resource-requests
// rule emits a manifest whose values are commented "PLACEHOLDER — DO NOT apply blind: these are not
// measured values", because the honesty policy forbids printing numbers the audit did not measure.
// Offering one of those as "the safest place to begin" would invite an operator to apply exactly the
// change the rule warned them not to.
//
// On the live testbed no placeholder is currently SafeNow, but only because every placeholder
// remediation happens to be a pod-template edit, which NeedsReview catches for an unrelated reason.
// A future rule with an additive placeholder would slip straight through, so the property is asserted
// directly rather than left to that coincidence.
func TestStartHere_NeverOffersAPlaceholderRemediation(t *testing.T) {
	f := limitRange() // additive shape → would otherwise be SafeNow
	// A ResourceQuota is on the additive allowlist and contains no pod-template key, so nothing
	// ELSE would stop it being SafeNow. That is the point: the guard has to be the placeholder
	// itself, not a marker that happens to also be present.
	f.RemediationYAML = "apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: quota\nspec:\n" +
		"  hard:\n    # PLACEHOLDER — DO NOT apply blind: not measured\n    pods: \"10\"\n"

	if got := Classify(f); got == SafeNow {
		t.Errorf("Classify = %q for a remediation the rule itself marks PLACEHOLDER / DO NOT apply — "+
			"it may not be offered as the safest place to begin", got)
	}

	sel := Select([]types.Finding{f, criticalNoMoney()}, 2)
	if sel.StartHere != nil {
		t.Errorf("StartHere points at %q, whose remediation is a placeholder", sel.StartHere.Finding.Title)
	}
}
