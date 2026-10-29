package pipeline

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A BOUNDARY THAT NAMES A DENOMINATOR THE FINDING DOES NOT HAVE IS FALSE.
//
// Found by reading a Markdown export of a real 839-finding production reading. Under the heading
// `k8s.workload.single-replica-no-pdb` sat the line "The count is per container and states its
// denominator" — a rule that reads `spec.replicas` and a PodDisruptionBudget selector, and whose evidence
// is "Deployment mailtoaster/maintenance-web: spec.replicas = 1". One boundary family held fifteen rules
// and five of them had no container in them at all.
//
// Measured on that reading: allow-privilege-escalation 64/64 findings named a container,
// writable-root-filesystem 74/74, no-probes 52/52 — and default-sa-token-automount 0/43,
// no-anti-affinity 0/46, single-replica-no-pdb 0/33, risky-rollout-strategy 0/13,
// privileged-host-access 0/3. **138 findings in one reading carried a sentence about a denominator they
// do not have.**
//
// A wrong boundary is worse than a missing one. ClaimBoundaries is the one place this product states what
// it does NOT know; a false sentence there is a claim about a claim, and it is printed on every surface —
// the card, the terminal, the Markdown export, SARIF, the MCP corpus and the ticket somebody opens days
// later.
//
// THE GATE IS THE FALSIFIER, not the classification: if a finding says its count is per container, its
// evidence must name one. That property is checkable on any reading, needs no list to maintain, and fails
// the moment a rule joins the wrong family.
func TestGolden_APerContainerBoundaryNeedsAContainerInTheEvidence(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	const perContainer = "The count is per container"
	checked, offenders := 0, map[string]int{}
	for _, f := range ar.Findings {
		carries := false
		for _, l := range f.ClaimBoundaries {
			if strings.Contains(l, perContainer) {
				carries = true
				break
			}
		}
		if !carries {
			continue
		}
		checked++
		if !strings.Contains(strings.ToLower(strings.Join(f.Evidence, " ")), "container") {
			offenders[f.RuleID]++
		}
	}
	if checked == 0 {
		t.Fatal("no finding in the golden carries the per-container boundary, so this assertion is vacuous — " +
			"either the sentence was reworded or the fixture no longer covers those rules")
	}
	for rule, n := range offenders {
		t.Errorf("%s: %d finding(s) carry %q and name no container in their evidence — the boundary states a "+
			"denominator the finding does not have", rule, n, perContainer)
	}
	t.Logf("%d finding(s) carry the per-container boundary; every one names a container", checked)
}

// AND THE OTHER DIRECTION, because a split can go wrong the other way: a rule whose evidence is per
// container and whose boundaries do not say so tells a reader less than the reading knows. This is a
// weaker property — a container can be named incidentally — so it names the rules rather than every
// finding, and it fires only when a rule's findings ALL name a container and NONE carries the sentence.
func TestGolden_APerContainerRuleSaysSo(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	const perContainer = "The count is per container"
	type tally struct{ n, withContainer, withLine int }
	by := map[string]*tally{}
	for _, f := range ar.Findings {
		// Only the workload posture rules: a "container" in a node or RBAC finding's evidence is a different
		// word, and this property is about a rule whose SUBJECT is a container.
		if !strings.HasPrefix(f.RuleID, "k8s.workload.") {
			continue
		}
		t0 := by[f.RuleID]
		if t0 == nil {
			t0 = &tally{}
			by[f.RuleID] = t0
		}
		t0.n++
		if strings.Contains(strings.ToLower(strings.Join(f.Evidence, " ")), "container ") {
			t0.withContainer++
		}
		for _, l := range f.ClaimBoundaries {
			if strings.Contains(l, perContainer) {
				t0.withLine++
				break
			}
		}
	}
	for rule, t0 := range by {
		if t0.n >= 2 && t0.withContainer == t0.n && t0.withLine == 0 {
			t.Errorf("%s: all %d finding(s) name a container in their evidence and none says its count is "+
				"per container — the reading knows more than it states", rule, t0.n)
		}
	}
}
