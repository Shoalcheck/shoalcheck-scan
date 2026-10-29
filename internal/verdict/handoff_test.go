package verdict

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func limitRangeFinding() types.Finding {
	return types.Finding{
		ID:     "f-lr-1",
		RuleID: "k8s.namespace.no-limitrange",
		Title:  "Namespace payments has no LimitRange",
		AffectedResources: []types.ResourceRef{
			{Kind: "Namespace", Name: "payments"},
		},
		RemediationYAML: "apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: defaults\n  namespace: payments\nspec:\n  limits:\n    - type: Container\n      defaultRequest:\n        cpu: 100m\n",
	}
}

// A handoff is the text an operator runs. It is not an action this tool takes, and the shape of the
// type has to make that impossible to blur.
func TestBuildHandoff_IsTextForTheOperatorAndNeverAnAction(t *testing.T) {
	h, err := BuildHandoff(limitRangeFinding(), SafeNow, "aks-shop-dev-westus3-01")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}

	if len(h.Steps) < 3 {
		t.Fatalf("a handoff with %d step(s) cannot cover check, apply and confirm", len(h.Steps))
	}
	// The dry run comes FIRST. A handoff that leads with apply is a handoff that changes a cluster
	// before anyone has seen whether the manifest even parses against it.
	if !strings.Contains(h.Steps[0].Command, "--dry-run") {
		t.Errorf("the first step is %q; it must be the dry run", h.Steps[0].Command)
	}
	if idx := stepIndexContaining(h, "--dry-run"); idx != 0 {
		t.Errorf("the dry run is step %d, not the first", idx)
	}
	// Every step is a command the operator runs. None of them may be something this process runs.
	for _, s := range h.Steps {
		if s.Command == "" {
			t.Errorf("step %q carries no command", s.Label)
		}
		if s.Why == "" {
			t.Errorf("step %q says what to run and not why", s.Label)
		}
	}
}

// The manifest is the rule's, verbatim. Regenerating it here would mean the text the operator applies
// is not the text the rule was written and tested against.
func TestBuildHandoff_ManifestIsVerbatim(t *testing.T) {
	f := limitRangeFinding()
	h, err := BuildHandoff(f, SafeNow, "ctx")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	if h.YAML != f.RemediationYAML {
		t.Errorf("the handoff's manifest differs from the rule's.\n  rule:    %q\n  handoff: %q",
			f.RemediationYAML, h.YAML)
	}
}

// Manual is refused; a reviewed change is not.
//
// This test used to assert that NeedsReview was refused too, on the reasoning that a loop offering
// disruptive changes had stopped being a closed loop. Measurement overruled it: SafeNow occurs on no
// real cluster — the only rule emitting an additive kind ships a manifest that honestly calls itself
// a starting point — so the strict version was a feature that could not happen. A reviewed change is
// admitted and pays for it by naming its disruption; Manual stays refused, because there is nothing
// mechanical to hand over.
func TestBuildHandoff_RefusesManualAndNamesTheRest(t *testing.T) {
	if _, err := BuildHandoff(limitRangeFinding(), Manual, "ctx"); !errors.Is(err, ErrNotSafeNow) {
		t.Errorf("Manual produced err=%v; want ErrNotSafeNow", err)
	}
	h, err := BuildHandoff(limitRangeFinding(), NeedsReview, "ctx")
	if err != nil {
		t.Fatalf("a reviewed change was refused: %v", err)
	}
	if h.Disruption == "" {
		t.Error("a reviewed handoff carries no disruption, which is the only thing that earns it a place here")
	}
	if h.Class != NeedsReview {
		t.Errorf("Class = %q, want needs-review", h.Class)
	}
}

// A refusal has to name its reason, because "no handoff" and "no handoff BECAUSE the rule ships no
// manifest" send the reader to different places.
func TestBuildHandoff_RefusalsAreSpecific(t *testing.T) {
	noYAML := limitRangeFinding()
	noYAML.RemediationYAML = ""
	if _, err := BuildHandoff(noYAML, SafeNow, "ctx"); !errors.Is(err, ErrNoRemediation) {
		t.Errorf("a finding with no manifest gave err=%v; want ErrNoRemediation", err)
	}

	noTarget := limitRangeFinding()
	noTarget.AffectedResources = nil
	if _, err := BuildHandoff(noTarget, SafeNow, "ctx"); !errors.Is(err, ErrNoTarget) {
		t.Errorf("a finding naming no resource gave err=%v; want ErrNoTarget — a manifest with nowhere\n"+
			"    to go is how somebody applies it to the wrong namespace", err)
	}
}

// The copy may not promise an outcome. Applying a manifest is not the same as a finding going away:
// the next audit is a fresh reading, and what it reports is its own business.
func TestBuildHandoff_PromisesNothing(t *testing.T) {
	h, err := BuildHandoff(limitRangeFinding(), SafeNow, "aks-shop-dev-westus3-01")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	hay := strings.ToLower(h.Summary + " " + h.Caveat)
	for _, s := range h.Steps {
		hay += " " + strings.ToLower(s.Label+" "+s.Why)
	}
	for _, banned := range []string{"will fix", "fixes", "resolves", "will resolve", "guarantee",
		"saves you", "will clear", "eliminates"} {
		if strings.Contains(hay, banned) {
			t.Errorf("the handoff copy contains %q — applying a manifest is not an outcome this tool can\n"+
				"    promise, and the next audit is a fresh reading. Copy: %s", banned, hay)
		}
	}
	if h.Caveat == "" {
		t.Error("the handoff carries no caveat; the operator is being handed a cluster change with no limits stated")
	}
}

// The target is explicit, so nobody applies a namespaced manifest to whatever context happens to be
// current.
func TestBuildHandoff_NamesItsTarget(t *testing.T) {
	h, err := BuildHandoff(limitRangeFinding(), SafeNow, "aks-shop-dev-westus3-01")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	if len(h.Targets) == 0 {
		t.Fatal("the handoff names no target")
	}
	joined := strings.Join([]string{h.Summary, h.Steps[0].Command}, " ")
	if !strings.Contains(joined, "payments") {
		t.Errorf("neither the summary nor the dry run names the namespace: %q", joined)
	}
	if !strings.Contains(h.Steps[0].Command, "--context aks-shop-dev-westus3-01") {
		t.Errorf("the dry run does not pin a context (%q); the manifest would land wherever the operator's\n"+
			"    current context points, which is the mistake this field exists to prevent", h.Steps[0].Command)
	}
}

func stepIndexContaining(h Handoff, s string) int {
	for i, st := range h.Steps {
		if strings.Contains(st.Command, s) {
			return i
		}
	}
	return -1
}

// THE HONEST SIZE OF THE CLOSED LOOP — and whether it can happen at all.
//
// The first version of this test counted SafeNow findings in the golden fixture, found one, and went
// green. That was false assurance. The fixture is hand-authored persona data, and its one eligible
// finding carries the rule id k8s.namespace.no-quota — WHICH IS NOT IN THE RULE REGISTRY. No live
// cluster can produce it. A green test guarding a capability that cannot occur is worse than no test:
// it reports the feature as reachable.
//
// So eligibility is measured against the rules that actually ship. Every SafeNow finding's rule must
// exist, and the count is logged so the number stays in front of whoever reads this.
//
// As it stands the count is ZERO on the live testbed, and that is the classifier being right rather
// than broken. SafeNow needs an additive kind with no hedge; the only rule emitting an additive kind
// is k8s.namespace.no-resource-governance; and its remediation honestly calls itself
// "# starting point — right-size from usage before applying", which is a precondition, not a
// mechanical fix. Making the loop demonstrable therefore needs a product decision — a rule that
// ships a genuinely mechanical additive fix, or a loop that admits reviewed changes and states the
// disruption — and not a looser safety classifier.
func TestHandoff_EveryEligibleFindingComesFromARuleThatExists(t *testing.T) {
	shipped := map[string]bool{}
	for _, r := range rules.All() {
		shipped[r.ID()] = true
	}
	if len(shipped) == 0 {
		t.Fatal("the rule registry is empty, so this test would pass on anything")
	}

	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "sample-audit.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	counts := map[SafetyClass]int{}
	reachable, phantom := 0, 0
	for _, f := range ar.Findings {
		c := Classify(f)
		counts[c]++
		if c != SafeNow {
			continue
		}
		if !shipped[f.RuleID] {
			phantom++
			t.Logf("fixture-only: %s classifies as safe-now but no shipped rule emits that id", f.RuleID)
			continue
		}
		reachable++
		h, err := BuildHandoff(f, c, "kind-assay-mesh")
		if err != nil {
			t.Errorf("%s is safe-now and produces no handoff: %v", f.RuleID, err)
			continue
		}
		if h.YAML == "" && h.Command == "" {
			t.Errorf("%s produced a handoff with nothing to run", f.RuleID)
		}
	}
	t.Logf("golden fixture: %d findings — safe-now=%d (reachable from a shipped rule: %d, fixture-only: %d), "+
		"needs-review=%d manual=%d",
		len(ar.Findings), counts[SafeNow], reachable, phantom, counts[NeedsReview], counts[Manual])
	if reachable == 0 {
		t.Log("NOTE: no shipped rule currently produces a finding the closed loop can act on. This is " +
			"recorded rather than asserted, because the fix is a product decision and not a code change: " +
			"loosening the safety classifier to make a demo work is the one option that is off the table.")
	}
}

// The command path, checked against what a real rule actually ships.
//
// Every defect below was invisible in a unit fixture and obvious the moment the product's own output
// for a live finding was read on screen. The rule ships:
//
//	kubectl label --overwrite namespace bookinfo pod-security.kubernetes.io/warn=baseline …   # surface breakage first, then set enforce=baseline; …
//
// A trailing shell comment, which is good documentation and a trap for anything that appends flags.
func TestBuildHandoff_ACommandWithATrailingCommentIsStillACommand(t *testing.T) {
	f := types.Finding{
		ID: "f-pss", RuleID: "k8s.namespace.pss-admission-not-enforced",
		Title:             "Enforce a PodSecurity admission profile on namespace bookinfo",
		AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: "bookinfo"}},
		RemediationCommand: "kubectl label --overwrite namespace bookinfo " +
			"pod-security.kubernetes.io/warn=baseline pod-security.kubernetes.io/audit=baseline   " +
			"# surface breakage first, then set enforce=baseline",
	}
	h, err := BuildHandoff(f, NeedsReview, "kind-assay-mesh")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}

	dry := h.Steps[0].Command
	// THE DRY RUN MUST BE A DRY RUN. Appending the flag after a "#" puts it inside a shell comment,
	// where it does nothing — so the step labelled "check it parses" would apply the change instead.
	if !strings.Contains(dry, "--dry-run=server") {
		t.Fatalf("the first step carries no dry-run flag: %q", dry)
	}
	if i, j := strings.Index(dry, "#"), strings.Index(dry, "--dry-run=server"); i >= 0 && j > i {
		t.Errorf("the dry-run flag sits AFTER a shell comment, so it is commented out and the step applies\n"+
			"    the change it claims to check:\n    %s", dry)
	}

	// EVERY command pins the context. Without it the change lands wherever the operator's current
	// context points, which in a fleet is rarely the cluster they were just reading about.
	for i, st := range h.Steps {
		if !strings.Contains(st.Command, "--context kind-assay-mesh") {
			t.Errorf("step %d does not pin the audited context: %q", i+1, st.Command)
		}
	}

	// The read-back must read what the change TOUCHED. A label change confirmed by listing
	// LimitRanges tells the operator nothing about whether the labels landed.
	last := h.Steps[len(h.Steps)-1].Command
	if strings.Contains(last, "limitrange") || strings.Contains(last, "resourcequota") {
		t.Errorf("the read-back for a label change lists quota objects: %q", last)
	}
	if !strings.Contains(last, "label") && !strings.Contains(last, "-o yaml") && !strings.Contains(last, "jsonpath") {
		t.Errorf("the read-back does not show the labels the change set: %q", last)
	}
}

// A staged remediation says it is staged.
//
// Proven on the live testbed. The PSA rule's command sets warn and audit and documents itself
// "# surface breakage first, then set enforce=baseline". Applied exactly as handed over, the finding
// did NOT leave the next reading — correctly, because admission still enforced nothing — and the
// evidence updated to say so: "enforce=<unset>, warn=baseline, audit=baseline — admission does not
// block any pod".
//
// The tool was right at every step and the operator was still owed a sentence. Handing over the
// first half of a two-part change without saying which half it is invites the reasonable conclusion
// that the re-audit failed.
func TestBuildHandoff_SaysWhenItIsOnlyTheFirstStep(t *testing.T) {
	staged := types.Finding{
		ID: "f-pss", RuleID: "k8s.namespace.pss-admission-not-enforced",
		Title:             "Enforce a PodSecurity admission profile on namespace bookinfo",
		AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: "bookinfo"}},
		RemediationCommand: "kubectl label --overwrite namespace bookinfo " +
			"pod-security.kubernetes.io/warn=baseline   # surface breakage first, then set enforce=baseline",
	}
	h, err := BuildHandoff(staged, NeedsReview, "kind-assay-mesh")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	if !h.Staged {
		t.Error("a remediation documenting a later step is not marked staged")
	}
	hay := strings.ToLower(h.Summary + " " + h.Caveat + " " + h.StagedNote)
	if !strings.Contains(hay, "still") && !strings.Contains(hay, "first") {
		t.Errorf("nothing tells the operator this is one step of more: %q / %q", h.Summary, h.StagedNote)
	}

	// And the general clause: applying anything is not a promise about the next reading.
	if !strings.Contains(strings.ToLower(h.Caveat), "independent") {
		t.Errorf("the caveat does not say the next reading is independent: %q", h.Caveat)
	}

	// A single-step remediation is NOT marked staged — the flag has to mean something.
	single := nsFinding(cleanQuota)
	sh, err := BuildHandoff(single, SafeNow, "ctx")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	if sh.Staged || sh.StagedNote != "" {
		t.Errorf("a one-step remediation is marked staged: %v / %q", sh.Staged, sh.StagedNote)
	}
}

// The manifest goes into a heredoc, and a heredoc is a place where text becomes shell.
//
// Two things have to hold. The delimiter is QUOTED — <<'EOF' — so nothing inside is expanded: a
// manifest carrying $(...) or backticks is a manifest, not a command, and an unquoted delimiter
// would execute it on the operator's machine with their credentials. And the delimiter must not
// appear in the body, or the heredoc ends early and the operator pastes a truncated manifest
// followed by loose YAML the shell tries to run.
func TestBuildHandoff_TheHeredocCannotExecuteTheManifest(t *testing.T) {
	nasty := `apiVersion: v1
kind: ResourceQuota
metadata:
  name: caps
  namespace: payments
  annotations:
    note: "$(id) and ` + "`whoami`" + ` and ${HOME}"
spec:
  hard:
    requests.cpu: "8"
`
	f := nsFinding(nasty)
	f.AffectedResources = []types.ResourceRef{{Kind: "Namespace", Name: "payments"}}
	h, err := BuildHandoff(f, SafeNow, "ctx")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	for i, st := range h.Steps {
		if !strings.Contains(st.Command, "<<") {
			continue
		}
		// A quoted delimiter is the whole defence. Without it the shell substitutes $(id) before
		// kubectl ever sees the manifest.
		if !strings.Contains(st.Command, "<<'") && !strings.Contains(st.Command, `<<"`) {
			t.Errorf("step %d opens an UNQUOTED heredoc, so the shell would expand the manifest before "+
				"kubectl reads it: %q", i+1, firstLine(st.Command))
		}
		// And the manifest must survive byte for byte.
		if !strings.Contains(st.Command, "$(id)") || !strings.Contains(st.Command, "${HOME}") {
			t.Errorf("step %d altered the manifest on the way into the heredoc", i+1)
		}
	}
}

// A manifest containing the delimiter must not truncate the heredoc.
func TestBuildHandoff_ADelimiterInTheBodyDoesNotTruncate(t *testing.T) {
	body := `apiVersion: v1
kind: ResourceQuota
metadata:
  name: caps
  namespace: payments
  annotations:
    script: |
      EOF
      echo pwned
spec:
  hard:
    requests.cpu: "8"
`
	f := nsFinding(body)
	f.AffectedResources = []types.ResourceRef{{Kind: "Namespace", Name: "payments"}}
	h, err := BuildHandoff(f, SafeNow, "ctx")
	if err != nil {
		t.Fatalf("BuildHandoff: %v", err)
	}
	for i, st := range h.Steps {
		if !strings.Contains(st.Command, "<<") {
			continue
		}
		delim := heredocDelimiter(st.Command)
		if delim == "" {
			t.Errorf("step %d has a heredoc with no readable delimiter: %q", i+1, firstLine(st.Command))
			continue
		}
		// The delimiter must appear exactly twice: opening it, and closing it. A third occurrence —
		// a line inside the manifest — is where the operator's paste stops being a manifest.
		lines := strings.Split(st.Command, "\n")
		closers := 0
		for _, l := range lines {
			if strings.TrimSpace(l) == delim {
				closers++
			}
		}
		if closers != 1 {
			t.Errorf("step %d: the delimiter %q appears as a standalone line %d times; the manifest "+
				"contains it, so the heredoc ends early and everything after it is handed to the shell",
				i+1, delim, closers)
		}
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func heredocDelimiter(cmd string) string {
	i := strings.Index(cmd, "<<")
	if i < 0 {
		return ""
	}
	rest := cmd[i+2:]
	rest = strings.TrimLeft(rest, "'\"")
	end := strings.IndexAny(rest, "'\"\n ")
	if end < 0 {
		return ""
	}
	return rest[:end]
}
