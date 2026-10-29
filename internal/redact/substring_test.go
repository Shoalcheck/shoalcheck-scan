package redact

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// REDACTION REPLACED SUBSTRINGS, AND A REDACTED READING SAID `spec.replicas = res-7cf452`.
//
// Measured on a live 188-finding reading before the fix: the token that stood for the identifier "1"
// appeared 391 times and the one for "15" twenty more, across 61 evidence lines. The headline summary read
// "res-7cf45287 more in the document" — the count 187 with its leading "1" swapped for a resource token.
//
// TWO CAUSES, AND THEY ARE DIFFERENT MISTAKES.
//
//	Highlight.Value WAS REGISTERED AS A RESOURCE NAME. It is built by highlight(section, label, count int)
//	and is always a COUNT — "1", "15" — never a name. Registering it made every digit-1 in the document a
//	candidate for replacement.
//
//	AND THE REPLACER HAD NO WORD BOUNDARY. strings.NewReplacer swaps any occurrence anywhere, so a
//	namespace called "waste" rewrites "wasteful" and an API group called "apps" rewrites the English word
//	in "most apps never use" — which is a sentence this product prints.
func TestRedact_ACountIsNotAnIdentifier(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "acme-prod"},
		Highlights: []types.Highlight{
			{Section: "security", Label: "Privileged workloads", Value: "1", Detail: "one workload"},
			{Section: "reliability", Label: "Single points of failure", Value: "15", Detail: "fifteen"},
		},
		// Highlights are harvested inside the Architecture block, so the fixture needs one for this test to
		// reach the code it is about — which is itself worth knowing: without an Architecture the values
		// were never registered at all, and the defect appeared only on real readings.
		Architecture: &types.Architecture{},
		Headline: &types.Headline{
			Remainder: "187 more in the document — every finding, with what each rests on",
		},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.workload.no-probes", RuleVersion: "1.0.0", Title: "t",
			Severity: types.SeverityLow, Category: types.CategoryReliability, Confidence: 1,
			Evidence:          []string{"Deployment app/api: spec.replicas = 1"},
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "app", Name: "api"}},
		}},
	}

	out := Report(ar)
	if got := out.Headline.Remainder; !strings.HasPrefix(got, "187 more") {
		t.Errorf("the headline count was rewritten: %q\n\nA highlight's Value is a COUNT, not a name; "+
			"registering it as an identifier makes every occurrence of that digit in the document a "+
			"candidate for replacement", got)
	}
	if got := out.Findings[0].Evidence[0]; !strings.HasSuffix(got, "= 1") {
		t.Errorf("evidence reads %q: a replica count is arithmetic the reader needs, and a token in its "+
			"place is not a redaction of anything", got)
	}
}

// A SHORT IDENTIFIER MUST NOT REWRITE A LONGER WORD.
func TestRedact_ReplacesWholeIdentifiersOnly(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "acme-prod"},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.namespace.no-quota", RuleVersion: "1.0.0",
			Title:    "Namespace waste has no ResourceQuota",
			Severity: types.SeverityLow, Category: types.CategoryConfig, Confidence: 1,
			// The namespace's own name, and an English word that merely starts with it.
			Evidence:          []string{"namespace waste holds wasteful workloads", "the waste namespace"},
			AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: "waste", Namespace: "waste"}},
		}},
	}

	out := Report(ar)
	ev := strings.Join(out.Findings[0].Evidence, " | ")
	// "waste" AS A WORD, not as a substring: "wasteful" contains it and is not a leak.
	if regexp.MustCompile(`\bwaste\b`).MatchString(ev) {
		t.Errorf("the namespace name survived as a word: %s", ev)
	}
	if !strings.Contains(ev, "wasteful") {
		t.Errorf("the word \"wasteful\" was rewritten: %s\n\nA replacement without a boundary turns every "+
			"longer word that begins with an identifier into a token, and the sentence stops being English",
			ev)
	}
}

// KUBERNETES' OWN API GROUPS ARE NOT CUSTOMER DATA, and two of them are ordinary English words.
//
// PolicyPosture.Operators registers every operator group deliberately: a customer's own group is
// indistinguishable from a vendor's without an allowlist that fails open on exactly the ones that matter.
// That argument is about VENDORS. The groups the Kubernetes project itself ships are a closed set present on
// every cluster in the world, they identify nobody, and `apps` and `batch` are English words: registering
// them rewrote "most apps never use" and made `apps/v1` unreadable in every place it appeared.
func TestRedact_KubernetesOwnGroupsAreNotIdentifiers(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "acme-prod"},
		PolicyPosture: &types.PolicyPosture{
			Operators: []string{"apps", "batch", "cert-manager.io", "acmebank.internal"},
		},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.workload.privileged-host-access", RuleVersion: "1.0.0", Title: "t",
			Severity: types.SeverityHigh, Category: types.CategorySecurity, Confidence: 1,
			Evidence: []string{
				"a wide kernel surface most apps never use",
				"Deployment apps/v1 in namespace app",
			},
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "app", Name: "api"}},
		}},
	}

	out := Report(ar)
	ev := strings.Join(out.Findings[0].Evidence, " | ")
	if !strings.Contains(ev, "most apps never use") {
		t.Errorf("an English sentence was rewritten by an API-group token: %s", ev)
	}
	if !strings.Contains(ev, "apps/v1") {
		t.Errorf("the API version was rewritten: %s — a redacted document that cannot say which API version "+
			"an object uses has lost a fact that identifies nobody", ev)
	}
	// The customer's own group is still a customer identifier and must not survive.
	for _, op := range out.PolicyPosture.Operators {
		if op == "acmebank.internal" {
			t.Error("a customer-authored operator group survived redaction, which is the leak the harvest " +
				"exists to prevent")
		}
	}
}
