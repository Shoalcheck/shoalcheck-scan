package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func sampleReport() *types.AuditReport {
	return &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "acme-pay-prod", Region: "eu-central-1", Provider: "eks"},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.workload.single-replica-no-pdb", RuleVersion: "1.0.0",
			Title:       "Single replica without PDB: payments/payments-gateway",
			Description: "Deployment payments/payments-gateway runs one replica.",
			Evidence:    []string{"Deployment payments/payments-gateway: spec.replicas = 1", "node ip-10-0-1-94 hosts it"},
			Severity:    types.SeverityHigh, Category: types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: "payments", Name: "payments-gateway"}},
			EstimatedEffort:   types.EffortMedium, Confidence: 1.0,
			Provenance: types.Provenance{Collector: "kubernetes", Version: "dev"},
		}},
		Architecture: &types.Architecture{
			AZs:        []types.AZ{{Name: "eu-central-1a", Nodes: []types.NodeRef{{Name: "ip-10-0-1-94", Type: "m6i.large", Namespace: "payments"}}}},
			Namespaces: []types.NamespaceSummary{{Name: "payments", Description: "PCI workloads"}},
			RBAC:       []types.RBACEntry{{Subject: "cicd/acme-deployer", Binding: "acme-deployer-admin", Role: "cluster-admin", Risk: "critical", Description: "x"}},
		},
		Methodology: types.Methodology{CollectorsRun: []string{"kubernetes"}, DataSources: []string{"Kubernetes API"}},
	}
	// Summary intentionally left for the caller to derive if needed.
}

func TestReport_NoOriginalIdentifierSurvives(t *testing.T) {
	ar := sampleReport()
	ar.Summary = types.DeriveSummary(ar.Findings)
	red := Report(ar)

	data, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted: %v", err)
	}
	out := string(data)

	for _, secret := range []string{
		"acme-pay-prod", "payments-gateway", "ip-10-0-1-94",
		"acme-deployer", "cicd/acme-deployer",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("redacted report still leaks %q", secret)
		}
	}
	// "payments" (the namespace) must be gone too — check as a whole token,
	// not as a substring of an unrelated word.
	if strings.Contains(out, `"payments"`) || strings.Contains(out, "payments/") {
		t.Errorf("namespace 'payments' leaked: %s", out)
	}
}

// A FINDING THAT LEFT CAN NAME WHAT THIS READING NEVER SAW. The replacer is built from the identifiers this reading
// holds; a finding the earlier reading reported about an object that has since been deleted names that object, and
// nothing here knows the name to replace it (found by an automated security review of c9ce89a). So under --redact
// the titles of findings that left the set are withheld — the id, rule and severity are this product's own and
// travel — rather than passed through a replacer that cannot vouch for them.
func TestRedact_AFindingThatLeftDoesNotNameWhatThisReadingNeverSaw(t *testing.T) {
	ar := sampleReport()
	ar.Trend = &types.TrendDelta{NoLongerInSetCount: 1, NoLongerInSet: []types.TrendFinding{{
		ID: "f-gone", RuleID: "k8s.workload.privileged-host-access", Severity: types.SeverityHigh,
		Title: "Deployment payroll/secret-export requests privileged or host-level access"}}}
	red := Report(ar)

	data, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted: %v", err)
	}
	for _, name := range []string{"secret-export", "payroll"} {
		if strings.Contains(string(data), name) {
			t.Errorf("a redacted reading names %q, an object only the earlier reading held", name)
		}
	}
	if red.Trend == nil || len(red.Trend.NoLongerInSet) != 1 {
		t.Fatalf("trend = %+v, want the one finding that left, still counted and listed", red.Trend)
	}
	if g := red.Trend.NoLongerInSet[0]; g.ID != "f-gone" || g.RuleID != "k8s.workload.privileged-host-access" || g.Severity != types.SeverityHigh {
		t.Errorf("left = %+v, want its id, rule and severity kept", g)
	}
	if ar.Trend.NoLongerInSet[0].Title == "" {
		t.Error("redaction emptied the original reading's title: it must not mutate its input")
	}
}

func TestReport_PreservesStructure(t *testing.T) {
	ar := sampleReport()
	ar.Summary = types.DeriveSummary(ar.Findings)
	red := Report(ar)

	if len(red.Findings) != 1 || red.Findings[0].Severity != types.SeverityHigh {
		t.Fatalf("finding structure not preserved: %+v", red.Findings)
	}
	if red.Findings[0].ID != "f-1" || red.Findings[0].RuleID != "k8s.workload.single-replica-no-pdb" {
		t.Error("rule identity must survive redaction (IDs/ruleIDs are not secrets)")
	}
	// A TOKEN, NOT THE CONSTANT — see TestRedact_FleetClustersStayDistinct. The literal "cluster" made every
	// redacted report in a fleet share one name, and FleetReport.Validate rejects the duplicate: the fleet
	// document did not exist at all once a second cluster was audited. What this assertion is actually about
	// is that the ORIGINAL name is gone and something stable stands in its place.
	if red.Cluster.Name == "acme-prod" || red.Cluster.Name == "" {
		t.Errorf("cluster name = %q: the original must not survive and the field must not be blanked",
			red.Cluster.Name)
	}
	if !strings.HasPrefix(red.Cluster.Name, "cluster-") {
		t.Errorf("cluster name = %q, want a cluster- token", red.Cluster.Name)
	}
	if red.Cluster.Provider != "eks" {
		t.Error("provider is not sensitive and must survive")
	}
	// The structured ns/name in AffectedResources must be tokenized consistently
	// with the same token used in the evidence free-text.
	tok := red.Findings[0].AffectedResources[0].Name
	if tok == "payments-gateway" || tok == "" {
		t.Fatalf("workload name not tokenized: %q", tok)
	}
	if !strings.Contains(strings.Join(red.Findings[0].Evidence, " "), tok) {
		t.Errorf("evidence does not use the same token %q as the structured field", tok)
	}
}

func TestReport_Deterministic(t *testing.T) {
	a1 := sampleReport()
	a1.Summary = types.DeriveSummary(a1.Findings)
	a2 := sampleReport()
	a2.Summary = types.DeriveSummary(a2.Findings)
	d1, _ := json.Marshal(Report(a1))
	d2, _ := json.Marshal(Report(a2))
	if string(d1) != string(d2) {
		t.Error("redaction must be deterministic across runs")
	}
}

func TestReport_NilSafe(t *testing.T) {
	if Report(nil) != nil {
		t.Error("Report(nil) must return nil")
	}
}

// TestReport_RedactsComplianceAssessmentTitle ensures the new
// ComplianceAssessment.Controls[].Title is tokenized like ComplianceRow.Title.
// A control Title can echo a workload/namespace name; without redaction it leaks
// through --redact. Control numbers, EvidenceRuleIDs, and FindingIDs are not PII
// and must pass through unchanged.
func TestReport_RedactsComplianceAssessmentTitle(t *testing.T) {
	ar := sampleReport()
	ar.Summary = types.DeriveSummary(ar.Findings)
	ar.ComplianceAssessment = &types.ComplianceAssessment{
		Framework: "CIS-K8s",
		Version:   "CIS Kubernetes Benchmark v1.9 (Section 5 subset)",
		Controls: []types.ComplianceControl{{
			Control:         "5.3.2",
			Title:           "NetworkPolicy missing in payments namespace (payments-gateway)",
			Status:          types.ControlStatusFail,
			FindingIDs:      []string{"f-1"},
			EvidenceRuleIDs: []string{"k8s.namespace.no-network-policy"},
		}},
		Score: types.ComplianceScore{Total: 1, Failed: 1, Scored: 1,
			Totals: map[types.ControlStatus]int{types.ControlStatusFail: 1}},
	}

	red := Report(ar)
	data, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted: %v", err)
	}
	out := string(data)

	if strings.Contains(out, "payments-gateway") || strings.Contains(out, "payments namespace") {
		t.Errorf("compliance assessment title leaked PII: %s", out)
	}
	// Non-PII identifiers must survive.
	if !strings.Contains(out, "5.3.2") {
		t.Error("control number 5.3.2 must pass through redaction")
	}
	if !strings.Contains(out, "k8s.namespace.no-network-policy") {
		t.Error("evidenceRuleIds must pass through redaction")
	}
	// Input must not be mutated.
	if ar.ComplianceAssessment.Controls[0].Title != "NetworkPolicy missing in payments namespace (payments-gateway)" {
		t.Error("Report must not mutate the input assessment")
	}
}

func TestReport_DoesNotMutateInput(t *testing.T) {
	ar := sampleReport()
	ar.Summary = types.DeriveSummary(ar.Findings)
	_ = Report(ar)
	if ar.Cluster.Name != "acme-pay-prod" {
		t.Error("Report must not mutate its input")
	}
}

func TestRedact_ObservedEdgesTokenized(t *testing.T) {
	ar := &types.AuditReport{
		Cluster: types.ClusterInfo{Name: "prod-eks"},
		Architecture: &types.Architecture{
			Tier: types.TierObserved,
			Topologies: []types.NamespaceTopology{{
				Name:      "shop",
				Workloads: []types.WorkloadNode{{ID: "Deployment/api", Kind: "Deployment", Name: "api"}},
			}},
			ObservedEdges: []types.ObservedEdge{
				{From: "Deployment/web", To: "Deployment/api", RequestsPerSec: 5},
				{From: "Deployment/api", To: "external/payments-saas", RequestsPerSec: 2},
			},
		},
		Findings: []types.Finding{},
	}
	red := Report(ar)
	for _, e := range red.Architecture.ObservedEdges {
		if strings.Contains(e.From, "api") || strings.Contains(e.To, "api") {
			t.Errorf("ObservedEdge endpoint not tokenized: %s→%s", e.From, e.To)
		}
		if strings.Contains(e.From, "payments-saas") || strings.Contains(e.To, "payments-saas") {
			t.Errorf("external endpoint not tokenized: %s→%s", e.From, e.To)
		}
	}
}

// TestRedact_StackFindingEvidenceTokenized verifies that a Phase-3 stack finding
// (cert-manager Certificate) has its CR-derived identifiers tokenized in both
// Evidence and AffectedResources — the same path rule findings use.
func TestRedact_StackFindingEvidenceTokenized(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod-cluster"},
		Findings: []types.Finding{{
			ID: "f-stack01", RuleID: "stack.certmanager.expiring", RuleVersion: "1.0.0",
			Title:             "Certificate prod/api-tls expires soon",
			Evidence:          []string{"prod/api-tls: status.notAfter=2026-07-01T00:00:00Z"},
			Severity:          types.SeverityHigh,
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: "prod", Name: "api-tls"}},
			Confidence:        0.9,
			Provenance:        types.Provenance{Collector: "kubernetes", Version: "0.1.0"},
		}},
	}
	out := Report(ar)
	ev := out.Findings[0].Evidence[0]
	if strings.Contains(ev, "prod/api-tls") {
		t.Errorf("stack finding Evidence must be tokenized, still contains raw identifier: %q", ev)
	}
	if out.Findings[0].AffectedResources[0].Namespace == "prod" {
		t.Errorf("AffectedResources namespace must be tokenized: %+v", out.Findings[0].AffectedResources[0])
	}
}

// TestRedact_IssuerNameDoesNotSurvive is the redaction-safety guard for the
// cert-manager issuer fix: a cert-manager issuerRef NAME (which can embed
// company/CA/domain identifiers) is NOT a structured field gatherIdentifiers
// harvests, so if it were written into Evidence as free text it would survive
// --redact. The analyzer now drops the name (keeping only the kind), so a
// company-revealing issuer name must NEVER appear in a redacted report.
func TestRedact_IssuerNameDoesNotSurvive(t *testing.T) {
	const issuerName = "acmecorp-internal-ca"
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod-cluster"},
		Findings: []types.Finding{{
			ID: "f-cert01", RuleID: "stack.certmanager.expiring", RuleVersion: "1.0.0",
			Title: "Certificate prod/api-tls expires soon",
			// Evidence as the analyzer now emits it: issuer KIND, not NAME.
			Evidence: []string{
				"prod/api-tls: status.notAfter=2026-07-01T00:00:00Z",
				"spec.issuerRef.kind=ClusterIssuer (issuer name omitted — may carry CA/domain identifiers)",
				"read from CR status only — the backing Secret was never read",
			},
			Severity:          types.SeverityHigh,
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: "Certificate", Namespace: "prod", Name: "api-tls"}},
			Confidence:        0.9,
			Provenance:        types.Provenance{Collector: "kubernetes", Version: "0.1.0"},
		}},
	}
	out := Report(ar)
	for _, f := range out.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e, issuerName) {
				t.Errorf("issuer name %q survived --redact in Evidence: %q", issuerName, e)
			}
		}
	}
}

// A GROUP NAME IS IDENTITY, AND IT SURVIVED --redact IN THE SENTENCE BESIDE ITS OWN TOKEN.
//
// Measured by redacting a live kind reading and reading the RBAC chains back:
//
//	plain : {"subject":"Group/system:masters","binding":"cluster-admin","description":"Group system:masters bound to cluster-admin"}
//	redact: {"subject":"subj-56abd1","binding":"res-adca44","description":"Group system:masters bound to res-adca44"}
//
// The subject field is a token and the DESCRIPTION still names the group. The harvest adds the subject as it
// appears in the field — "Group/system:masters" — and the description carries the bare name, so the
// replacement never matches. On that cluster it is harmless: system:masters is a group the Kubernetes
// project ships and identifies nobody. On a real cluster the same sentence reads "Group
// acme-payments-admins bound to res-…", and a customer's directory group is exactly the kind of name
// --redact exists to remove — it names the company, and often the team and the product line with it.
//
// Same shape as the binding that survived in F-1/M-91's evidence text: a name structured in one field and
// free-text in another, harvested in the form it has in the field and not in the form it has in the
// sentence.
func TestRedact_AnRBACGroupNameDoesNotSurviveInTheChainsSentence(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod"},
		Architecture: &types.Architecture{
			RBAC: []types.RBACEntry{
				{
					Subject:     "Group/acme-payments-admins",
					Binding:     "payments-admin-binding",
					Role:        "cluster-admin",
					Risk:        "critical",
					Description: "Group acme-payments-admins bound to cluster-admin",
				},
				{
					Subject:     "User/deploy@acme.example",
					Binding:     "deploy-binding",
					Role:        "edit",
					Risk:        "high",
					Description: "User deploy@acme.example bound to edit",
				},
			},
		},
	}
	out := Report(ar)
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, name := range []string{"acme-payments-admins", "deploy@acme.example"} {
		if strings.Contains(s, name) {
			i := strings.Index(s, name)
			t.Errorf("%q survives --redact:\n  …%s…", name, s[max(0, i-90):i+40])
		}
	}
	// AND THE SAME NAME IN A FINDING'S EVIDENCE, which is where the live reading still carried it: the rule
	// writes "ClusterRoleBinding X names User jane.doe@acme.example, and reaches cluster-wide", and that
	// sentence is owned by a different producer from the chain above.
	ar.Findings = []types.Finding{{
		ID: "f-1", RuleID: "k8s.rbac.dangerous-grant", Title: "a wide grant",
		Evidence:          []string{"ClusterRoleBinding payments-admin-binding names User deploy@acme.example, and reaches cluster-wide."},
		AffectedResources: []types.ResourceRef{{Kind: "ClusterRoleBinding", Name: "payments-admin-binding"}},
	}}
	out = Report(ar)
	body, err = json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s = string(body)
	if strings.Contains(s, "deploy@acme.example") {
		i := strings.Index(s, "deploy@acme.example")
		t.Errorf("a subject named in a finding's evidence survives --redact:\n  …%s…", s[max(0, i-90):i+40])
	}

	// AND THE TOKENS ARE THERE, so the sentence still says who was bound to what.
	if !strings.Contains(s, "subj-") {
		t.Errorf("no subject token in the redacted chains, so the sentence lost its subject entirely: %s", s)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// A REDACTED PACK SAID "the built-in ClusterRole res-adca44".
//
// `shoalcheck explain` over a redacted reading:
//
//	Review res-adca44 grant on ServiceAccount subj-a1de55
//	· scope note: matches the built-in ClusterRole "res-adca44" by name only — custom wildcard (*,*,*) …
//
// The role is `cluster-admin`: an upstream ClusterRole that ships with every Kubernetes cluster in the
// world. Tokenising it protects nobody and costs the auditor the sentence's meaning — "built-in" and a
// token in the same clause contradict each other, because a built-in has a public name by definition.
//
// The product already argues this for API groups, in redact.go's own words: a group the Kubernetes project
// ships "identifies nobody", and registering `apps` rewrote ordinary English. THE SAME CLOSED-SET ARGUMENT
// REACHES THE RBAC NAMES Kubernetes ships, and no further: a customer's own ClusterRole is tokenised as
// before, and the skip is keyed on the KIND as well as the name, so a Deployment somebody called
// "cluster-admin" is still a customer object and still a token.
func TestRedact_TheRolesKubernetesShipsStayReadable(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod"},
		// The chain is where the live reading tokenised it: add("subj", e.Role) harvests every role name in
		// Architecture.RBAC, so the built-in became a token everywhere the document mentions it.
		Architecture: &types.Architecture{
			RBAC: []types.RBACEntry{
				{Subject: "ServiceAccount/payments/deployer", Binding: "acme-deployer-admin",
					Role: "cluster-admin", Risk: "critical", Description: "ServiceAccount payments/deployer bound to cluster-admin"},
				{Subject: "ServiceAccount/payments/reader", Binding: "acme-reader",
					Role: "acme-superuser", Risk: "high", Description: "ServiceAccount payments/reader bound to acme-superuser"},
			},
		},
		Findings: []types.Finding{
			{
				ID: "f-1", RuleID: "k8s.rbac.cluster-admin-serviceaccount", Title: "wide grant",
				Evidence: []string{`matches the built-in ClusterRole "cluster-admin" by name only`},
				AffectedResources: []types.ResourceRef{
					{Kind: "ClusterRole", Name: "cluster-admin"},
					{Kind: "ClusterRole", Name: "acme-superuser"},
				},
			},
		},
	}
	out := Report(ar)
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)

	// THE ASSERTION IS ON THE FIELD, NOT ON THE DOCUMENT. A first version checked whether the whole JSON
	// still contained "cluster-admin" and passed on the RULE ID — k8s.rbac.cluster-admin-serviceaccount —
	// which carries the substring and is never redacted. An assertion that can pass for the wrong reason
	// measures nothing.
	builtIn := false
	for _, f := range out.Findings {
		for _, r := range f.AffectedResources {
			if r.Kind == "ClusterRole" && r.Name == "cluster-admin" {
				builtIn = true
			}
		}
	}
	for _, e := range out.Architecture.RBAC {
		if e.Role == "cluster-admin" {
			builtIn = true
		}
	}
	if !builtIn {
		t.Errorf("the built-in ClusterRole was tokenised in every field that names it, so the redacted "+
			"reading says \"the built-in ClusterRole <token>\" — a contradiction that tells an auditor "+
			"nothing:\n%s", s)
	}
	for _, ev := range out.Findings[0].Evidence {
		if strings.Contains(ev, "built-in ClusterRole \"res-") {
			t.Errorf("the evidence sentence still calls a token a built-in: %s", ev)
		}
	}
	if strings.Contains(s, "acme-superuser") {
		i := strings.Index(s, "acme-superuser")
		t.Errorf("a customer's own ClusterRole survives --redact:\n  …%s…", s[max(0, i-80):i+40])
	}
	// AND THE COLLISION, WHICH GOES THE SAFE WAY. A customer object that happens to share a name with an
	// upstream RBAC object registers that string as an identifier, and a token is per-VALUE — so the name is
	// replaced everywhere in that reading, including where it meant the built-in. The customer object wins:
	// losing a sentence's clarity is the cost, and it is the cheaper of the two mistakes.
	clash := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod"},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.rbac.cluster-admin-serviceaccount", Title: "wide grant",
			AffectedResources: []types.ResourceRef{
				{Kind: "ClusterRole", Name: "cluster-admin"},
				{Kind: "Deployment", Namespace: "payments", Name: "cluster-admin"},
			},
		}},
	}
	for _, f := range Report(clash).Findings {
		for _, r := range f.AffectedResources {
			if r.Kind == "Deployment" && r.Name == "cluster-admin" {
				t.Error("a Deployment named cluster-admin kept its name: the skip is for the RBAC names " +
					"Kubernetes ships, not for the word")
			}
		}
	}
}

// A SERVICEACCOUNT KUBERNETES SHIPS IS NOT AN IDENTIFIER, AND ITS NAME IS A SUBSTRING OF ONE.
//
// M-120 registered the bare half of every RBAC subject so a customer's directory group could not survive in
// free text. Measured afterwards on a live reading: the chain `kube-system/clusterrole-aggregation-controller`
// registered `clusterrole-aggregation-controller`, and replacing that string also rewrote the TAIL of the
// upstream ClusterRole `system:controller:clusterrole-aggregation-controller` — so a name Kubernetes ships
// came out of the redacted reading as `system:controller:res-…`.
//
// The subject is an upstream control-plane ServiceAccount: it exists identically on every cluster and
// identifies nobody. Its namespace says so, and the namespaces Kubernetes reserves are a closed set —
// the same argument KubernetesOwnGroup and KubernetesOwnRBACName already make.
//
// A ServiceAccount in a CUSTOMER namespace is an identifier as before, which is the half this must not lose.
func TestRedact_ASubjectInAKubernetesNamespaceIsNotAnIdentifier(t *testing.T) {
	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "prod"},
		Architecture: &types.Architecture{
			RBAC: []types.RBACEntry{
				{Subject: "kube-system/clusterrole-aggregation-controller",
					Binding: "system:controller:clusterrole-aggregation-controller",
					Role:    "system:controller:clusterrole-aggregation-controller", Risk: "low"},
				{Subject: "payments/deployer", Binding: "acme-deployer", Role: "acme-superuser", Risk: "high"},
			},
		},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.rbac.dangerous-grant", Title: "grant",
			Evidence: []string{
				"ClusterRoleBinding system:controller:clusterrole-aggregation-controller names ServiceAccount kube-system/clusterrole-aggregation-controller",
				"ClusterRoleBinding acme-deployer names ServiceAccount payments/deployer",
			},
			AffectedResources: []types.ResourceRef{
				{Kind: "ClusterRole", Name: "system:controller:clusterrole-aggregation-controller"},
			},
		}},
	}
	body, err := json.Marshal(Report(ar))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)

	if !strings.Contains(s, "system:controller:clusterrole-aggregation-controller") {
		i := strings.Index(s, "system:controller:")
		t.Errorf("an upstream ClusterRole name was partly rewritten, so the reading names a role that does "+
			"not exist:\n  …%s…", s[max(0, i-40):min(len(s), i+90)])
	}
	if strings.Contains(s, "payments/deployer") || strings.Contains(s, "acme-deployer") {
		t.Errorf("a customer ServiceAccount or binding survives --redact:\n%s", s)
	}
}
