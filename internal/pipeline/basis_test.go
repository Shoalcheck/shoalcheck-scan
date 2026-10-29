package pipeline

import (
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Every finding states what its claim RESTS ON. The label is "basis", not a citation, and the distinction is the
// whole design: knowing a list was read establishes that the rule had its inputs, not that those inputs support
// the conclusion. Saying the weaker thing accurately is the point.
func TestAttachFindingBasis_StatesWhatEachFindingRestsOn(t *testing.T) {
	ar := &types.AuditReport{
		Findings: []types.Finding{
			{ID: "f-1", RuleID: "k8s.workload.mutable-image-tags"},
			{ID: "f-2", RuleID: "k8s.workload.single-replica-no-pdb"},
			{ID: "f-3", RuleID: "k8s.cost.overprovisioned-resources"},
			{ID: "f-4", RuleID: "some.rule.this.build.never.heard.of"},
		},
		Methodology: types.Methodology{
			// the workload, job and pod lists read; poddisruptionbudgets and services NOT.
			CollectedKinds: []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets", "nodes", "pods"},
			DeniedKinds:    []string{"poddisruptionbudgets", "services"},
			RunBasis:       &types.RunBasis{UsageSource: "prometheus"},
		},
	}
	attachFindingBasis(ar, true)

	for _, f := range ar.Findings {
		if f.Basis == nil {
			t.Fatalf("%s has no basis at all", f.ID)
		}
	}

	// A rule whose inputs were all read says so, and says nothing more.
	full := ar.Findings[0].Basis
	if len(full.Refused) != 0 {
		t.Errorf("f-1's inputs were all read; basis reports %v refused", full.Refused)
	}
	// mutable-image-tags reads every pod spec the cluster runs: the three workload lists, CronJobs, Jobs and Pods.
	if got := full.Summary(); got != "basis · 6 kinds, all read" {
		t.Errorf("f-1 summary = %q", got)
	}

	// A rule that fired on partial coverage must NAME what was missing. This is the case the card most needs:
	// the finding exists, so nothing else on it says the picture is incomplete.
	partial := ar.Findings[1].Basis
	if len(partial.Refused) != 2 {
		t.Errorf("f-2 depends on poddisruptionbudgets and services, both refused; basis reports %v", partial.Refused)
	}
	s := partial.Summary()
	for _, want := range []string{"2 refused", "poddisruptionbudgets", "services"} {
		if !strings.Contains(s, want) {
			t.Errorf("f-2 summary %q does not mention %q", s, want)
		}
	}

	// A usage-dependent finding says where the usage came from, because without a source it would not exist.
	if !ar.Findings[2].Basis.UsageRequired {
		t.Error("f-3 is the rightsizing rule and does not declare a usage dependency")
	}
	if !strings.Contains(ar.Findings[2].Basis.Summary(), "usage from prometheus") {
		t.Errorf("f-3 summary = %q", ar.Findings[2].Basis.Summary())
	}

	// An unknown producer says "not recorded", never a basis of zero kinds: "rests on nothing" and "we cannot
	// say" are different statements and only one of them is true.
	unk := ar.Findings[3].Basis
	if !unk.Unknown {
		t.Error("f-4's rule is unknown to this build and was given a basis anyway")
	}
	if got := unk.Summary(); !strings.Contains(got, "not recorded") {
		t.Errorf("f-4 summary = %q — an unknown producer must not read as resting on nothing", got)
	}
}

// The basis must never claim support. A citation implies it; this line does not, and the wording is load-bearing.
func TestAttachFindingBasis_NeverClaimsSupport(t *testing.T) {
	b := &types.FindingBasis{Kinds: []string{"pods", "services"}}
	s := strings.ToLower(b.Summary())
	for _, banned := range []string{"support", "prove", "confirm", "verified", "evidence"} {
		if strings.Contains(s, banned) {
			t.Errorf("the basis line says %q — knowing a list was read establishes that the rule had its "+
				"inputs, not that they support the conclusion: %q", banned, s)
		}
	}
	if !strings.HasPrefix(s, "basis ") {
		t.Errorf("the line does not label itself a basis: %q", s)
	}
}
