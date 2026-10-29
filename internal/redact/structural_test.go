package redact

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// structural_test.go — THE GATE THE SENTINEL PROMISED AND DID NOT DELIVER.
//
// F-1 of `docs/qa/2026-08-31-phase2-adversarial-review.md`, and it is right.
//
// completeness_test.go is a property test over a HAND-BUILT fixture. Its header promises that "a new field
// carrying a name it should not fails immediately, with no list to maintain" — and that promise holds only
// for fields `buildSentinelReport` happens to plant. Four fields have now reached the schema and needed
// hand-rebuilding in redact.Report without the sentinel noticing: Architecture.NodePools,
// Architecture.Flows, Architecture.UnpricedStorageClasses, and PolicyPosture (B-156).
//
// The ledger's remedy for B-156 was "extend the sentinel in the same change as any schema addition". That is
// a discipline, and this project's own rule answers it: A GATE YOU MUST REMEMBER IS NOT A GATE.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS DOES INSTEAD
//
// It walks types.AuditReport BY REFLECTION, plants a value unique to each string field's PATH, redacts, and
// asserts that every planted value either disappears or is listed below with a reason. There is no fixture
// to keep representative, because the fixture is generated from the type.
//
// A new string field on the schema therefore fails THIS BUILD until somebody classifies it — which is the
// difference between a gate and a habit.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY AN EXEMPTION LIST IS NOT THE SAME PROBLEM AGAIN
//
// The list below is not a list of fields to redact — it is a list of fields that must SURVIVE, and it fails
// closed: a field nobody has classified is treated as a leak, not as an exemption. The four fields that
// slipped past the sentinel would each have failed here on the day they were added.

// survivesRedaction names every string field whose value is NOT customer data and must reach a redacted
// document intact, with the reason. A path absent from this map must not survive.
//
// Paths are dotted field names from the AuditReport root; a slice or map element is named by its field path
// without an index, because every element of a slice shares one classification.
var survivesRedaction = map[string]string{
	// ── this product's own vocabulary: identifiers we mint and closed enums ──────────────────
	"SchemaVersion":                              "the literal \"v1\", this product's contract version",
	"Findings.RuleID":                            "a rule identifier this product mints",
	"Findings.RuleVersion":                       "a rule's own version",
	"Findings.ID":                                "a sha256-derived finding id — already a token",
	"Findings.Severity":                          "closed enum: critical|high|medium|low|info",
	"Findings.Category":                          "closed enum: cost|reliability|security|config|compliance",
	"Findings.EstimatedEffort":                   "closed enum",
	"Findings.Pillar":                            "closed enum: ground-truth|change-preflight|observability",
	"Findings.CommandSafety":                     "closed enum describing our own remediation command",
	"Findings.PriceBasis":                        "closed enum naming which price basis produced a figure",
	"Findings.SpendKind":                         "closed enum: compute|storage|network|control-plane",
	"Findings.Provenance.Collector":              "the literal \"kubernetes\"",
	"Findings.Provenance.Version":                "the engine version",
	"Findings.Basis.Kinds":                       "collector step names this product mints",
	"Findings.Basis.Refused":                     "same",
	"Findings.Basis.Requests":                    "session-trace refs — \"T-04\" — positions in this document",
	"Findings.Basis.UsageSource":                 "closed enum: prometheus|metrics-api|vpa|none",
	"Findings.Basis.Summary":                     "prose this product generates about its own basis",
	"Findings.AffectedResources.Kind":            "a Kubernetes KIND — public API vocabulary",
	"Findings.AffectedResources.OwnerChain.Kind": "same",
	"Findings.IDBasis.Kind":                      "a Kubernetes kind, from a closed set — Deployment, Node, Namespace and the rest",
	"Findings.IDBasis.OwnerChain.Kind":           "same; the basis carries no owner chain, but the shape does",
	"Findings.IDBasis.OwnerChain.UID":            "an RFC 4122 UID the API server assigned",
	"Summary.HighestPriorityID":                  "a finding id — already a token",
	"Summary.BySeverity.KEY":                     "closed severity enum as a map key",
	"Summary.ByCategory.KEY":                     "closed category enum as a map key",
	"Highlights.Section":                         "closed enum: security|reliability|cost",
	"Highlights.Tone":                            "closed enum: critical|warn|ok|info",
	"Narratives.Section":                         "a section identifier this product mints",
	"SectionLedes.KEY":                           "a section identifier this product mints; the VALUE is redacted",
	"Peers.Provider":                             "closed enum: aws|azure|gcp|…",
	"Peers.Role":                                 "closed enum: primary|staging|dr|ephemeral",
	"Peers.Status":                               "closed enum: active|standby|decommissioned",
	"Relationships.Kind":                         "closed enum: replication|image-promotion|…",
	"Relationships.Direction":                    "closed enum: one-way|bidirectional",

	// ── a UID is random, not descriptive ─────────────────────────────────────────────────────
	"Findings.AffectedResources.OwnerChain.UID": "an RFC 4122 UID the API server assigned — carries no name, " +
		"and it is the join key a reader uses to match an owner across two readings",

	// ── the cluster's own facts that are public vocabulary, not identity ─────────────────────
	"Cluster.Provider":          "closed enum: aws|azure|gcp|kind|onprem|unknown",
	"Cluster.SpendSource":       "closed enum naming how spend was derived",
	"Cluster.KubernetesVersion": "an upstream version string; a vendor build suffix is not customer identity",

	// ── Kubernetes' and the cloud vendors' closed vocabularies ───────────────────────────────
	"PolicyPosture.Namespaces.PodSecurity.Enforce": "a PSA level: privileged|baseline|restricted",
	"PolicyPosture.Namespaces.PodSecurity.Audit":   "same",
	"PolicyPosture.Namespaces.PodSecurity.Warn":    "same",
	"Architecture.AZs.Nodes.Type":                  "a cloud instance type — a public SKU",
	"Architecture.AZs.Nodes.Capacity":              "a capacity shape, e.g. \"4 vCPU / 16 GiB\"",
	"Architecture.NodePools.Capacity":              "same",
	"Architecture.NodePools.CostSource":            "closed enum naming where a price came from",
	"Architecture.UnpricedNodeTypes":               "cloud instance types — public SKUs",
	"Architecture.Tier":                            "closed enum: declared|observed",
	"Architecture.Topologies.Tier":                 "same",
	"Architecture.Stack.Layer":                     "closed enum naming a stack layer",
	"Architecture.Stack.Name":                      "a VENDOR name — cert-manager, Istio. Deliberately not redacted: it is the field that carries vendor identity for a human reader",
	"Architecture.RBAC.Risk":                       "closed enum",
	"Architecture.RBAC.RiskBasis":                  "closed enum: rules|name|unresolved — says where the band came from, not what the role is called",
	"Architecture.RBAC.FindingIDs":                 "finding ids — already tokens",
	"Architecture.Flows.Steps.Kind":                "a Kubernetes kind",
	"Architecture.Flows.Steps.FindingID":           "a finding id",
	"Architecture.ObservedSource":                  "closed enum: istio|linkerd|cilium|…",
	"Architecture.ObservedWindow":                  "a duration, e.g. \"5m\"",
	"Architecture.ObservedEdges.Source":            "closed telemetry-source enum",
	"Architecture.ObservedEdges.Protocol":          "closed enum: http|grpc|tcp",
	"Architecture.ObservedEdges.MTLS":              "closed enum",
	"Architecture.ObservedEdges.Confidence":        "closed enum",
	"Architecture.ObservedEdges.Window":            "a duration",
	"Architecture.Topologies.Edges.Kind":           "closed edge-kind enum",
	"Architecture.Topologies.Services.Kind":        "a Kubernetes kind",
	"Architecture.Topologies.Services.Type":        "a Service type: ClusterIP|NodePort|LoadBalancer",
	"Architecture.Topologies.Workloads.Kind":       "a Kubernetes kind",
	"Architecture.Topologies.Workloads.Severity":   "closed severity enum",
	"Architecture.Topologies.Workloads.FindingID":  "a finding id",

	// ── compliance: control numbers and framework names are PUBLIC standards ─────────────────
	"Compliance.Framework":                          "a public framework name: CIS-K8s|SOC2|PCI-DSS",
	"Compliance.Control":                            "a public control number",
	"Compliance.Status":                             "closed enum",
	"Compliance.FindingIDs":                         "finding ids",
	"ComplianceAssessment.Framework":                "a public framework name",
	"ComplianceAssessment.Version":                  "a public benchmark version string",
	"ComplianceAssessment.Controls.Control":         "a public control number",
	"ComplianceAssessment.Controls.Status":          "closed enum: pass|fail|manual|na",
	"ComplianceAssessment.Controls.Rationale":       "prose THIS PRODUCT authors explaining a non-PASS; it names no cluster object",
	"ComplianceAssessment.Controls.EvidenceRuleIDs": "rule identifiers this product mints",
	"ComplianceAssessment.Controls.FindingIDs":      "finding ids",
	"ComplianceAssessment.Score.Totals.KEY":         "a status enum as a map key",

	// ── the domain assessments: ids and enums; Title/Detail/Recommended ARE redacted ─────────
	"Assessments.Observability.ID":         "a check identifier this product mints",
	"Assessments.Observability.Status":     "closed enum",
	"Assessments.Observability.FindingRef": "a finding id",
	"Assessments.GitOps.ID":                "same",
	"Assessments.GitOps.Status":            "same",
	"Assessments.GitOps.FindingRef":        "same",
	"Assessments.Deployments.ID":           "same",
	"Assessments.Deployments.Status":       "same",
	"Assessments.Deployments.FindingRef":   "same",
	"Assessments.Alerts.ID":                "same",
	"Assessments.Alerts.Status":            "same",
	"Assessments.Alerts.FindingRef":        "same",

	// ── methodology: what the RUN did, which is this product's own account of itself ─────────
	"Methodology.CollectorsRun":  "the literal \"kubernetes\"",
	"Methodology.CollectedKinds": "collector step names",
	"Methodology.DeniedKinds":    "collector step names — the KIND is named, never the object",
	// One entry per kind read, from the fixed list in collect/volume.go: a resource kind name and two counts.
	// No object is named, and a count is never an identifier.
	"Methodology.Volume.ByKind.Kind": "a resource kind name from collect/volume.go's fixed list",
	// The same two facts DeniedKinds carries, paired: a collector step name and one of six causes this
	// project defines. Neither is customer data, and the cause is checked against the closed set on the
	// way out of Methodology.UnreadKinds, so a value from a hand-edited file cannot travel as a cause.
	//
	// It is worth saying what would change that: a kind is `cr:<plural>.<group>` for a custom resource,
	// and a CRD group can be the customer's own domain. That string is already in DeniedKinds and is
	// already classified here, so this field inherits the same exposure rather than adding one — and the
	// support bundle, the only artifact this project asks a customer to send, refuses to NAME a
	// non-builtin kind for exactly that reason (internal/support.builtinKinds).
	"Methodology.Unread.Kind":                    "a collector step name, the same string DeniedKinds carries",
	"Methodology.Simulation.Base":                "closed enum: live|capture|empty",
	"Methodology.Simulation.Objects.Kind":        "a Kubernetes kind — public API vocabulary",
	"Methodology.Simulation.Objects.Action":      "closed enum: created|replaced",
	"Methodology.Simulation.NotEvaluated.Kind":   "a Kubernetes kind — public API vocabulary",
	"Methodology.Simulation.NotEvaluated.Action": "closed enum, empty for an object not evaluated",
	"Methodology.Simulation.NotSimulated":        "a fixed list this product writes about its own method (overlay.NotSimulated)",
	"Methodology.Unread.Cause":                   "one of six causes internal/collect measures — a closed set, validated on read",
	"Methodology.LLMModel":                       "a model identifier, this product's own configuration",
	"Methodology.RunBasis.EngineVersion":         "our engine version",
	"Trend.EngineNote":                           "our sentence naming two engine versions",
	"Trend.NewIDs":                               "finding ids — the same tokens Findings carries, a subset of them",
	"Trend.NoLongerInSet.ID":                     "a finding id from the earlier reading — the same kind of token Findings carries",
	"Trend.NoLongerInSet.RuleID":                 "a rule identifier this product mints",
	"Trend.NoLongerInSet.Severity":               "closed enum: critical|high|medium|low|info",
	"Trend.NotCompared.Reason":                   "a comparison gate's own sentence; it names no customer object",
	"Methodology.RunBasis.RuleSet.ID":            "a rule or analyzer ID from our registry",
	"Methodology.RunBasis.RuleSet.Version":       "a rule version from our registry",
	"Methodology.RunBasis.UsageSource":           "closed enum",
	"Methodology.RunBasis.UsageTier":             "closed enum: none|unproven|proven",
	"Methodology.RunBasis.UsageProvenance":       "prose this product generates about its own proof",
	"Methodology.RunBasis.DataVersions.KEY":      "a dataset name from our registry: pricing|api-removals",
	"Methodology.RunBasis.DataVersions.Version":  "a dataset stamp",
	"Methodology.RunBasis.DataVersions.Source":   "closed enum: embedded|cache|bundle|live",
	"Methodology.UsageMethodology.Source":        "closed enum",
	"Methodology.UsageMethodology.Backend":       "closed enum",
	"Methodology.UsageMethodology.Window":        "a duration",
	"Methodology.UsageMethodology.Confidence":    "closed enum",
	"Methodology.UsageMethodology.Caveats":       "prose this product generates about its own data",
	"Methodology.SessionTrace.Rows.Verbs":        "HTTP/Kubernetes verbs — get, list",
	"Methodology.SessionTrace.Rows.Resource":     "an apiGroup/resource path — public API vocabulary",
	"Methodology.SessionTrace.Rows.Outcome":      "a tally: \"12 ok, 1 forbidden\"",
	"Methodology.SessionTrace.Rows.Class":        "closed enum: read|stream|write|external",
	"Methodology.SessionTrace.Rows.Paths":        "whitelisted DISCOVERY routes — /apis, /version",
	"Methodology.SessionTrace.Rows.Ref":          "a position in this document — \"T-04\"",
	"Methodology.SessionTrace.Rows.ConsumedBy":   "rule identifiers this product mints",
	"Trend.ReferenceDataChanged":                 "dataset names from our own registry",

	// ── never serialized at all ──────────────────────────────────────────────────────────────
	// ── the calendar: dates, closed enums, dataset stamps and prose about our own coverage ────
	"Headline.Lines.Kind":       "a claim kind from internal/headline's own table",
	"Headline.Lines.FindingIDs": "finding ids — already tokens",

	"Calendar.Rows.Date":                   "a date, YYYY-MM-DD",
	"Calendar.Rows.Kind":                   "closed enum: object|dataset",
	"Calendar.Rows.Field":                  "a Kubernetes field path — public API vocabulary (status.notAfter)",
	"Calendar.Rows.Dataset":                "a dataset name from our registry",
	"Calendar.Rows.DatasetVersion":         "a dataset stamp",
	"Calendar.Rows.DatasetSource":          "closed enum: embedded|cache|bundle|live",
	"Calendar.Rows.FindingIDs":             "finding ids — already tokens",
	"Calendar.Rows.Object.Kind":            "a Kubernetes KIND — public API vocabulary",
	"Calendar.Rows.Object.OwnerChain.Kind": "same",
	"Calendar.Rows.Object.OwnerChain.UID":  "an RFC 4122 UID the API server assigned — carries no name",
	"Calendar.NotAssessed.Clock":           "prose this product authors about its own coverage; names no cluster object",
	"Calendar.NotAssessed.Reason":          "same — the reason a clock was not assessed, with at most a dataset stamp in it",
	"Findings.Deadline.Date":               "a date, YYYY-MM-DD",
	"Findings.Deadline.Field":              "a Kubernetes field path — public API vocabulary",

	"FleetLinkage.PrivateImageDigests": "FleetLinkage is `json:\"-\"` — it is a transient fleet-assembly " +
		"fingerprint that never reaches any document. It carries the most identifying strings in the " +
		"schema (private registries, served hostnames), and the reason that is safe is the tag, not a " +
		"replacer — which is why it is classified rather than rebuilt.",
	"FleetLinkage.PrivateRegistries": "same — never serialized",
	"FleetLinkage.ServedHosts":       "same — never serialized",
	"FleetLinkage.OutboundHosts":     "same — never serialized",
	"Identity.ClusterUID": "Identity is `json:\"-\"` — the cluster identity recorded BEFORE redaction so the licence " +
		"counts a redacted reading as the cluster it is. Never serialized; it exists precisely to survive redaction " +
		"in memory, so rebuilding it would defeat it.",
	"Identity.ClusterName": "same — never serialized",
}

// sentinelValue is planted into EVERY string field, and the same value everywhere is the point.
//
// The first version of this test planted a value unique to each path, and it was wrong in a way worth
// recording: redact.Report replaces strings through a REGISTRY built by gatherIdentifiers from a handful of
// structured fields. A per-path value is in no registry, so it survives a field that IS correctly rebuilt —
// the test could not tell "passed through untouched" from "rebuilt, but this string was not an identifier".
//
// One value, planted everywhere including into the fields gatherIdentifiers harvests, makes the question
// exact: after redaction, this string survives only where nothing replaced it.
const sentinelValue = "acmebank-payments-prod"

// plantStrings walks v and sets every reachable string to sentinelValue, recording each path it planted.
//
// It ALLOCATES what it walks: a nil pointer or empty slice carries no string, so a field that exists only as
// a nil pointer would be invisible. That is the exact shape of B-156 — PolicyPosture was a nil pointer in
// the hand-built fixture and the walk sailed past it.
func plantStrings(v reflect.Value, path string, out map[string]bool, depth int) {
	if depth > 12 {
		return // the schema is not this deep; a runaway guard, not a policy
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		plantStrings(v.Elem(), path, out, depth+1)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not serialized, not reachable by a consumer
			}
			sub := f.Name
			if path != "" {
				sub = path + "." + f.Name
			}
			plantStrings(v.Field(i), sub, out, depth+1)
		}
	case reflect.Slice:
		if v.IsNil() || v.Len() == 0 {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		plantStrings(v.Index(0), path, out, depth+1)
	case reflect.Map:
		kt := v.Type().Key()
		if kt.Kind() != reflect.String {
			return
		}
		if v.IsNil() {
			if !v.CanSet() {
				return
			}
			v.Set(reflect.MakeMap(v.Type()))
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		plantStrings(elem, path, out, depth+1)
		// CONVERT to the map's key type, which is not always `string`: BySeverityDelta is
		// map[types.Severity]int. A bare reflect.ValueOf(string) panics on a named key type, and the panic
		// is in the walker rather than in the schema — so fixing it by skipping maps would have read as
		// "the schema is fine".
		v.SetMapIndex(reflect.ValueOf(sentinelValue).Convert(kt), elem)
		out[path+".KEY"] = true
	case reflect.String:
		if !v.CanSet() {
			return
		}
		v.SetString(sentinelValue)
		out[path] = true
	}
}

// survivors walks a redacted report and returns every path still holding sentinelValue.
func survivors(v reflect.Value, path string, out map[string]bool, depth int) {
	if depth > 12 {
		return
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			survivors(v.Elem(), path, out, depth+1)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			sub := t.Field(i).Name
			if path != "" {
				sub = path + "." + t.Field(i).Name
			}
			survivors(v.Field(i), sub, out, depth+1)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			survivors(v.Index(i), path, out, depth+1)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if k.Kind() == reflect.String && k.String() == sentinelValue {
				out[path+".KEY"] = true
			}
			survivors(v.MapIndex(k), path, out, depth+1)
		}
	case reflect.String:
		if v.String() == sentinelValue {
			out[path] = true
		}
	}
}

// F-1's gate. A string field on types.AuditReport is either redacted or classified — never neither.
func TestRedact_EveryStringFieldOnTheSchemaIsClassified(t *testing.T) {
	ar := &types.AuditReport{}
	planted := map[string]bool{}
	plantStrings(reflect.ValueOf(ar).Elem(), "", planted, 0)

	if len(planted) < 100 {
		t.Fatalf("the walk planted only %d string field(s) on AuditReport — it is not reaching the schema, "+
			"so this test would pass by checking nothing", len(planted))
	}

	out := Report(ar)
	if out == nil {
		t.Fatal("Report returned nil")
	}
	left := map[string]bool{}
	survivors(reflect.ValueOf(out).Elem(), "", left, 0)

	var leaked, misclassified []string
	for path := range planted {
		// The full path, INCLUDING a ".KEY" suffix: a map's key and its value are classified separately,
		// because they routinely differ — SectionLedes has a section id for a key and a sentence about the
		// customer's cluster for a value.
		_, exempt := survivesRedaction[path]
		if left[path] && !exempt {
			leaked = append(leaked, path)
		}
		if !left[path] && exempt {
			misclassified = append(misclassified, path)
		}
	}

	if len(leaked) > 0 {
		t.Errorf("%d string field(s) carry a customer identifier into a REDACTED document and are not "+
			"classified as safe:\n  %s\n\n"+
			"--redact is the mode an operator uses to share a report OUTSIDE their organisation. Either\n"+
			"rebuild the field in redact.Report, or add it to survivesRedaction with the reason it is not\n"+
			"customer data. A field nobody classified is treated as a leak, which is the direction that\n"+
			"fails safely.", len(leaked), strings.Join(sorted(leaked), "\n  "))
	}

	// The other direction, so the exemption list cannot rot into a list of things that used to be true.
	if len(misclassified) > 0 {
		t.Errorf("%d field(s) are listed in survivesRedaction and are in fact redacted:\n  %s\n\n"+
			"Redaction got stricter and this list did not. Remove the entry — an exemption that exempts\n"+
			"nothing is the dead-guard shape this project has removed twice before.",
			len(misclassified), strings.Join(sorted(misclassified), "\n  "))
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
