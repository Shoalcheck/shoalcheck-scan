package pipeline

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/analyzers"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// pillar_observability_test.go — the third pillar, and the two tables that fill it.

// Every analyzer that emits a finding declares a pillar, PillarNone included: a missing entry and a deliberate
// abstention are different statements, and only one of them is an answer.
func TestAnalyzerPillars_EveryEmittedRuleDeclares(t *testing.T) {
	table := analyzers.PillarByRule()
	emitted := analyzerRuleIDs(t)
	var missing []string
	for _, id := range emitted {
		if _, ok := table[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d analyzer rule(s) declare no pillar (PillarNone is a valid answer and has to be written):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	live := map[string]bool{}
	for _, id := range emitted {
		live[id] = true
	}
	for id := range table {
		if !live[id] {
			t.Errorf("the analyzer pillar table declares %q, which no analyzer emits", id)
		}
	}
}

// The monitoring four are the pillar, and nothing else is: assigning a GitOps or mesh finding would claim it is
// one of the three things the document leads with.
func TestAnalyzerPillars_OnlyMonitoringIsObservability(t *testing.T) {
	table := analyzers.PillarByRule()
	want := map[string]bool{
		"stack.monitoring.servicemonitor-selects-nothing": true,
		"stack.monitoring.podmonitor-selects-nothing":     true,
		"stack.monitoring.alert-route-receiver-missing":   true,
		"stack.monitoring.prometheus-storage-ephemeral":   true,
	}
	for id, p := range table {
		if p == types.PillarObservability && !want[id] {
			t.Errorf("%s is in the monitoring pillar and is not a monitoring finding", id)
		}
		if want[id] && p != types.PillarObservability {
			t.Errorf("%s is a monitoring finding and is not in the pillar: %q", id, p)
		}
	}
	if len(want) != 4 {
		t.Fatal("the fixture list changed; check the pillar's membership against the analyzer")
	}
}

// The two tables are disjoint. A rule id in both would let one of them silently win, and which one would depend
// on map iteration order in the merge.
func TestPillarTables_DoNotOverlap(t *testing.T) {
	a, r := analyzers.PillarByRule(), rules.PillarByRule()
	for id := range a {
		if _, both := r[id]; both {
			t.Errorf("%q is declared in both pillar tables", id)
		}
	}
	if len(a) == 0 || len(r) == 0 {
		t.Fatal("a table is empty, so this assertion checked nothing")
	}
}

// The merge reaches findings: an analyzer finding gets the pillar its own package declared, and a rule finding
// keeps the one the registry declared.
func TestAttachPillar_MergesBothTables(t *testing.T) {
	fs := []types.Finding{
		{ID: "f-1", RuleID: "stack.monitoring.alert-route-receiver-missing"},
		{ID: "f-2", RuleID: "stack.argocd.outofsync"},
		{ID: "f-3", RuleID: "k8s.reliability.node-drain-budget"},
		{ID: "f-4", RuleID: "some.rule.this.build.never.heard.of"},
	}
	attachPillar(fs)
	if fs[0].Pillar != types.PillarObservability {
		t.Errorf("the alert-route finding is in %q, want the monitoring pillar", fs[0].Pillar)
	}
	if fs[1].Pillar != types.PillarNone {
		t.Errorf("an Argo finding was assigned to %q", fs[1].Pillar)
	}
	if fs[2].Pillar != types.PillarChangePreflight {
		t.Errorf("the drain rule lost its pillar: %q", fs[2].Pillar)
	}
	if fs[3].Pillar != types.PillarNone {
		t.Errorf("an unknown rule was assigned to %q", fs[3].Pillar)
	}
}

// The pillar's own words: a label, a question, and no claim that an alert failed to fire.
func TestObservabilityPillar_SaysWhatItChecks(t *testing.T) {
	p := types.PillarObservability
	if p.Label() != "Monitoring Coverage" {
		t.Errorf("label = %q", p.Label())
	}
	q := p.Question()
	if !strings.Contains(q, "monitoring") || !strings.HasSuffix(q, "?") {
		t.Errorf("question = %q", q)
	}
	for _, banned := range []string{"alerts do not work", "you are not monitoring", "failed to fire"} {
		if strings.Contains(strings.ToLower(q), banned) {
			t.Errorf("the question claims %q, which a snapshot cannot see", banned)
		}
	}
}

// analyzerRuleIDs is every RuleID the analyzer package stamps on a finding, read from its source.
//
// TWO NAMESPACES SHARE THE stack.* PREFIX and only one of them is a rule id: an analyzer's own ID
// (stack.monitoring.servicemonitor — the unit the registry and the collection step are named by) and the
// RuleID it stamps on a finding (stack.monitoring.servicemonitor-selects-nothing). The pillar table is keyed
// on the second. So the sweep takes every stack.* literal in the sources — which catches ids declared as a
// const, the way Istio's is, and which a regex anchored on `RuleID:` missed — and subtracts the analyzers'
// own IDs, read from the registry rather than from the text.
func analyzerRuleIDs(t *testing.T) []string {
	t.Helper()
	own := map[string]bool{}
	for _, a := range analyzers.All() {
		own[a.ID()] = true
	}
	ids := map[string]bool{}
	for _, f := range analyzerSources(t) {
		for _, m := range ruleIDLiteral.FindAllStringSubmatch(f, -1) {
			if !own[m[1]] {
				ids[m[1]] = true
			}
		}
	}
	var out []string
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) < 8 {
		t.Fatalf("only %d analyzer rule ids found; the sweep is blind: %v", len(out), out)
	}
	if len(own) < 10 {
		t.Fatalf("the analyzer registry holds %d entries; the subtraction above is not doing its job", len(own))
	}
	return out
}

// EVERY stack.* LITERAL, not only the ones written at a RuleID field. Istio's id is declared as a const and
// used through it, so a regex anchored on `RuleID:` missed it and the orphan check reported the pillar table
// as declaring a rule nothing emits — the sweep was blind, not the table wrong. Matching the literal wherever
// it appears errs toward finding too many, which makes the "every emitted rule declares" half stricter and
// the orphan half looser; that is the safe direction for both.
var ruleIDLiteral = regexp.MustCompile(`"(stack\.[a-z0-9.-]+)"`)

func analyzerSources(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "analyzers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}
