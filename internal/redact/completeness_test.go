package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A SENTINEL test rather than a checklist.
//
// redact.Report works by shallow-copying the report and rebuilding the fields it NAMES — its own comment says
// so. That design means every field added to the schema afterwards passes through untouched, silently, and the
// only thing standing between that and a leak is somebody remembering. Three fields had already slipped
// through: Architecture.NodePools (pool names are customer-chosen), Architecture.Flows (namespaces, and on any
// cluster with an Ingress the client's public hostname), and Architecture.UnpricedStorageClasses.
//
// A 165-entry list of every string field in the schema was the obvious alternative and would have been
// rubber-stamped within two releases. This instead states the PROPERTY: a redacted report does not contain the
// customer's names. Put the same identifiers in every field, redact, and assert none survives anywhere in the
// serialized output. A new field carrying a name it should not fails immediately, with no list to maintain.
func buildSentinelReport() *types.AuditReport {
	const (
		ns   = "payments-prod"
		wl   = "stripe-webhook"
		pool = "acme-payments-workers"
		sc   = "acmebank-fast-ssd"
		host = "pay.acmebank.com"
		// A PolicyRule.ResourceNames value: customer-chosen, and the single most identifying string a
		// dangerous-grant finding prints. On the kind testbed these read `kubelet-config`; on a real
		// cluster they read like this one.
		grant = "acme-prod-db-credentials"
		uid   = "5f2c9e18-aaaa-4bbb-8ccc-1d2e3f4a5b6c"
		nodeN = "ip-10-4-7-31.eu-central-1.compute.internal"
	)

	ar := &types.AuditReport{
		SchemaVersion: "v1",
		Cluster:       types.ClusterInfo{Name: "acme-prod-eks", Region: "sa-east-1"},
		// THE POLICY-SHAPE PROJECTION, populated so this sentinel can see it. It shipped 2026-08-30 and
		// passed straight through Report untouched — namespace names intact in a --redact document — because
		// this builder did not set it, and a sentinel only guards the fields it plants. That is the standing
		// weakness of this test and the reason to extend it in the same change as any schema addition.
		PolicyPosture: &types.PolicyPosture{
			OperatorsRead: true,
			// A vendor group, which is public and must SURVIVE, beside a customer group built on their own
			// domain, which must not. Asserting both directions is what stops a fix that simply drops the
			// list from passing.
			Operators: []string{"cert-manager.io", "acmebank.internal"},
			Namespaces: []types.NamespacePosture{{
				Name: ns, PodSecurity: types.PodSecurityLabels{Enforce: "restricted"},
				PodSecurityRead: true, NetworkPolicies: 2, NetworkPoliciesRead: true,
			}},
		},
		Findings: []types.Finding{{
			ID: "f-1", RuleID: "k8s.workload.mutable-image-tags", RuleVersion: "1.0.0",
			Title:       "Mutable image tag on " + ns + "/" + wl,
			Description: "The Deployment " + wl + " in " + ns + " uses a floating tag.",
			Evidence:    []string{"pod " + wl + "-7d4f in " + ns},
			AffectedResources: []types.ResourceRef{{
				Kind: "Deployment", Namespace: ns, Name: wl,
				OwnerChain: []types.OwnerLink{{Kind: "Deployment", Name: wl}},
			}},
			Confidence: 0.9,
		}, {
			// A DANGEROUS-GRANT FINDING, which is what B-1 Option C adds. Its ScopedTo names an object the
			// customer chose, and the SAME NAME appears in the evidence sentence — which is where a leak
			// would actually be read, and where a registry-based replacer can only reach it if the name was
			// registered from somewhere structured. Planted before gatherIdentifiers harvested ScopedTo, so
			// this test caught it first; that is the order the brief asked for.
			ID: "f-2", RuleID: "k8s.rbac.dangerous-grant", RuleVersion: "1.0.0",
			Title:       "ClusterRole grants read access to named Secrets",
			Description: "ClusterRole " + wl + "-reader grants get on secrets cluster-wide.",
			Evidence: []string{
				"ClusterRole " + wl + "-reader: get, list on secrets, scoped to " + grant,
			},
			AffectedResources: []types.ResourceRef{{Kind: "ClusterRole", Name: wl + "-reader"}},
			ScopedTo:          []string{grant},
			Severity:          types.SeverityHigh, Category: types.CategorySecurity,
			Confidence: 1.0,
		}},
		Architecture: &types.Architecture{
			Namespaces: []types.NamespaceSummary{{Name: ns, Workloads: wl, Description: wl + " and friends"}},
			NodePools:  []types.NodePoolSummary{{Type: pool, Spec: "4 vCPU / 16 GiB", Count: 3}},
			AZs: []types.AZ{{Name: "sa-east-1a",
				Nodes: []types.NodeRef{{Name: nodeN, Namespace: ns, Type: "m6i.xlarge"}}}},
			Flows: []types.FlowDiagram{{
				ID: "flow-" + ns, Title: "Checkout path through " + ns,
				Steps: []types.FlowStep{
					{Label: host, Namespace: ns, Kind: "external"},
					{Label: wl, Namespace: ns, Kind: "service", Note: "reached from " + host},
				},
			}},
			// THE RBAC CHAIN. add("subj", …) mints three tokens — the ServiceAccount, the binding and the
			// role — and until this block existed the sentinel document contained no "subj" token at all,
			// so deleting any of those three harvests would have failed nothing. Measured by
			// TestRedact_EveryHarvestKindIsExercisedByTheSentinel: 9 of 10 kinds covered, subj the tenth.
			//
			// All three names are customer-chosen on a real cluster and all three identify: a
			// ServiceAccount named for the team, a binding named for the ticket that created it, a Role
			// named for the system it was cut for.
			RBAC: []types.RBACEntry{{
				Subject: "acmebank-payments-sa", Binding: "acmebank-payments-crb",
				Role: "acmebank-payments-reader", Risk: "read-only", RiskBasis: "rules",
				Description: "reads Secrets in " + ns,
			}},
			UnpricedStorageClasses: []string{sc},
			ObservedEdges:          []types.ObservedEdge{{From: ns + "/" + wl, To: ns + "/db"}},
		},
		Highlights: []types.Highlight{{Section: "cost", Label: "Largest namespace", Value: ns, Detail: wl + " dominates"}},
		Methodology: types.Methodology{
			CollectorsRun:  []string{"kubernetes"},
			CollectedKinds: []string{"pods"},
			DataSources:    []string{"Kubernetes API (server v1.31.0)"},
			RunBasis:       &types.RunBasis{ClusterUID: uid, UsageSource: "prometheus", EngineVersion: "0.1.0"},
			// A SIMULATED READING (gate --with) names what it laid over: a manifest path from the customer's own
			// repository, and an object the change CREATES — whose name no finding carries, so only the
			// simulation block's own harvest can register it.
			Simulation: &types.Simulation{
				Base: "live", Files: []string{simFile},
				Objects: []types.SimulatedObject{{Kind: "Deployment", Namespace: ns, Name: simCreated, File: simFile, Doc: 1, Action: "created"}},
				NotEvaluated: []types.SimulatedObject{{Kind: "Secret", Namespace: ns, Name: wl, File: simFile, Doc: 2,
					Reason: "Secret and ConfigMap contents are never read"}},
				NotSimulated: []string{"deletions"},
			},
		},
	}
	ar.Summary = types.DeriveSummary(ar.Findings)
	return ar
}

// The simulation block's two strings no other field carries.
const (
	simFile    = "deploy/acmebank-ledger/overlays/prod/change.yaml"
	simCreated = "ledger-reconciler-v2"
)

func TestReport_NoCustomerIdentifierSurvivesAnywhere(t *testing.T) {
	const (
		ns   = "payments-prod"
		wl   = "stripe-webhook"
		pool = "acme-payments-workers"
		sc   = "acmebank-fast-ssd"
		host = "pay.acmebank.com"
		// A PolicyRule.ResourceNames value: customer-chosen, and the single most identifying string a
		// dangerous-grant finding prints. On the kind testbed these read `kubelet-config`; on a real
		// cluster they read like this one.
		grant = "acme-prod-db-credentials"
		uid   = "5f2c9e18-aaaa-4bbb-8ccc-1d2e3f4a5b6c"
		nodeN = "ip-10-4-7-31.eu-central-1.compute.internal"
		// Distinctive on purpose, and NOT a substring of the node name above: the node name contains
		// "eu-central-1", so asserting that string would have been satisfied by the node-name replacement
		// and proved nothing about the region field.
		region = "sa-east-1"
		zone   = "sa-east-1a"
		// The RBAC chain: a ServiceAccount, the binding that grants it and the role it points at. Three
		// distinct strings, because the harvest mints a token for each and one string would have left two
		// of the three unguarded.
		rbacSubject = "acmebank-payments-sa"
		rbacBinding = "acmebank-payments-crb"
		rbacRole    = "acmebank-payments-reader"
	)
	ar := buildSentinelReport()
	out := Report(ar)
	if out == nil {
		t.Fatal("Report returned nil")
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(blob)

	for name, what := range map[string]string{
		ns:    "a namespace",
		wl:    "a workload name",
		pool:  "a node-pool name",
		sc:    "a StorageClass name",
		host:  "the client's public hostname",
		uid:   "the cluster UID, which anyone with cluster access can match in one command",
		nodeN: "a node name",
		grant: "an object name a PolicyRule scoped a grant to — the field internal/redact did not cover",
		// THE SENTINEL PLANTED THESE AND NEVER ASSERTED THEM, for as long as it has existed. Measured on a
		// live redacted reading of the testbed: cluster.region was still "eu-central-1" and all three
		// architecture.azs[].name were still "eu-central-1a/b/c" — while redact.go line 93 reads
		// `out.Cluster.Region = rep(ar.Cluster.Region)` and the AZ loop's own comment says the zone name
		// "had not been" replaced and now is. Both calls run; `rep` only replaces what gatherIdentifiers
		// HARVESTED, and neither the region nor a zone was ever harvested, so both were no-ops that read
		// as fixes. A region is a locating fact — Frankfurt narrows the customer — and on a private cloud
		// a "region" is a site name, which is exactly the argument this project used to keep the region out
		// of the support bundle.
		region: "the cloud region, which is a locating fact",
		zone:   "an availability zone — the same locating fact, one level down",
		// THE RBAC CHAIN, WHICH NOTHING EXERCISED. add("subj", …) mints a token for the ServiceAccount,
		// the binding and the role, and the sentinel document contained no subj token at all — so all three
		// harvests were unfalsifiable. Each is customer-chosen and each identifies on its own.
		simFile:     "a manifest path from the customer's repository, named by a simulated reading",
		simCreated:  "an object a simulated change creates, named by nothing but the simulation block",
		rbacSubject: "the ServiceAccount a grant is held by",
		rbacBinding: "the binding that grants it",
		rbacRole:    "the role it points at",
	} {
		if strings.Contains(text, name) {
			t.Errorf("a redacted report still contains %s (%q)", what, name)
		}
	}
	if strings.Contains(text, "acme") || strings.Contains(text, "acmebank") {
		t.Error("a redacted report still contains the customer's own name somewhere")
	}
	// And redaction must not empty the report: a document with nothing in it is safe and useless.
	if len(out.Findings) != 2 || out.Findings[0].ID != "f-1" || out.Findings[1].ID != "f-2" {
		t.Error("redaction dropped the findings instead of tokenizing them")
	}
	if out.Architecture == nil || len(out.Architecture.NodePools) != 1 || len(out.Architecture.Flows) != 1 {
		t.Error("redaction dropped architecture sections instead of tokenizing them")
	}
}

// A diagnostic helper for the sentinel test: print WHERE a surviving identifier lives, so a failure names the
// field instead of leaving the next reader to grep a JSON blob.
// A diagnostic that names the FIELD a surviving identifier lives in, so a failure does not leave the next
// reader grepping a JSON blob.
func TestReport_LocateSurvivors(t *testing.T) {
	out := Report(buildSentinelReport())
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				walk(vv, path+"."+k)
			}
		case []any:
			for i, vv := range x {
				walk(vv, fmt.Sprintf("%s[%d]", path, i))
			}
		case string:
			for _, sentinel := range []string{"stripe-webhook", "payments-prod", "acme", "pay.acmebank.com",
				"acme-prod-db-credentials"} {
				if strings.Contains(x, sentinel) {
					t.Errorf("%s = %q  (contains %q)", path, x, sentinel)
				}
			}
		}
	}
	walk(tree, "report")
}
