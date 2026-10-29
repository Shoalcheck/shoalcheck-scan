package types

import "time"

// AuditReport is the top-level document — both the JSON fixture format on disk
// and the in-memory representation passed to the renderer.
//
// SchemaVersion "v1" is a forever commitment; bumping it means publishing a
// migration. Backward-compatible field additions stay on "v1".
//
// Architecture / Compliance / Assessments are optional v1 additions: in v0
// they're populated by hand in the fixture; in Phase 2 real collectors
// populate them from kubectl inspection + IaC parsing.
type AuditReport struct {
	SchemaVersion        string                `json:"schemaVersion"`
	GeneratedAt          time.Time             `json:"generatedAt"`
	Cluster              ClusterInfo           `json:"cluster"`
	Summary              Summary               `json:"summary"`
	Findings             []Finding             `json:"findings"`
	Methodology          Methodology           `json:"methodology"`
	Architecture         *Architecture         `json:"architecture,omitempty"`
	Compliance           []ComplianceRow       `json:"compliance,omitempty"`
	ComplianceAssessment *ComplianceAssessment `json:"complianceAssessment,omitempty"`
	Assessments          *DomainAssessments    `json:"assessments,omitempty"`
	Peers                []ClusterPeer         `json:"peers,omitempty"`
	Relationships        []ClusterRelationship `json:"relationships,omitempty"`
	Highlights           []Highlight           `json:"highlights,omitempty"`
	Narratives           []Narrative           `json:"narratives,omitempty"`
	SectionLedes         map[string]string     `json:"sectionLedes,omitempty"`

	// PolicyPosture is the machine-readable policy shape of this cluster — see policy_posture.go for what
	// it carries and, more importantly, what it structurally cannot. Optional and additive: a report written
	// before it shipped is still valid v1, and Validate never requires it.
	PolicyPosture *PolicyPosture `json:"policyPosture,omitempty"`

	// Trend carries the prev-vs-current summary delta when this report was
	// produced with audit history (`shoalcheck audit --save-history`) and a prior
	// snapshot for the same cluster existed. Optional, v1-compatible: omitted
	// (omitempty) when there's no prior audit to diff against, so existing
	// fixtures and tests are unaffected and Validate never requires it. The
	// renderer (a later ticket) reads it to show "since last audit" badges.
	Trend *TrendDelta `json:"trend,omitempty"`

	// Calendar is the "things with a clock" block: dated obligations this run could read, each with its source, and
	// the clocks it could not assess. Nil on readings written before the block existed, which the renderer says
	// in its own sentence rather than reading as "no deadlines". See calendar.go.
	Calendar *Calendar `json:"calendar,omitempty"`

	// Headline is at most five sentences a stranger reads first, each with its basis, plus the remainder and
	// the reading's own cost. Selected by internal/headline from this report and rendered identically by the
	// terminal, the document and the app — one selection, so the three surfaces cannot open with different
	// arguments. Nil on a reading written before the block existed.
	Headline *Headline `json:"headline,omitempty"`

	// FleetLinkage is a transient, read-only "fingerprint" (private image
	// digests/registries, served + outbound hostnames) used ONLY during fleet
	// assembly to detect GENUINE cross-cluster links. Never serialized
	// (json:"-"), so it has zero impact on the v1 JSON contract.
	FleetLinkage *FleetLinkage `json:"-"`

	// Identity is the cluster this reading is OF, as it was before redaction: the kube-system UID and the display
	// name. Transient and never serialized (json:"-"), for the same reason FleetLinkage is safe — the tag, not a
	// replacer. It exists for one consumer, the licence count, which must count a redacted reading as the cluster
	// it is: charged from the document, `audit --redact` cost a second slot for a cluster already read, and a key
	// bound to the cluster's fingerprint refused it, because a token's fingerprint matches nothing a shop issued.
	// Nil on a reading loaded from disk; ChargeIdentity falls back to what the document carries.
	Identity *ReadingIdentity `json:"-"`
}

// ReadingIdentity is the un-redacted identity of the cluster a reading is of. See AuditReport.Identity.
type ReadingIdentity struct {
	ClusterUID  string
	ClusterName string
	// Context is the kubeconfig context the reading was taken through. It is usually named after the cluster, so
	// it is customer data: redact.Report clears it. The instrument's empty "Since the last reading" prints the
	// command that keeps a reading of THIS cluster with it, rather than an invented one. Empty on a reading loaded
	// from disk and on a redacted one.
	Context string
}

// ChargeIdentity is the cluster a licence counts this reading as: the identity recorded before redaction when the
// pipeline recorded one, and otherwise the UID and name the document carries.
func (ar *AuditReport) ChargeIdentity() (uid, name string) {
	if ar == nil {
		return "", ""
	}
	if ar.Identity != nil {
		return ar.Identity.ClusterUID, ar.Identity.ClusterName
	}
	if rb := ar.Methodology.RunBasis; rb != nil {
		uid = rb.ClusterUID
	}
	return uid, ar.Cluster.Name
}

// FleetLinkage is the org-scoped, collision-resistant evidence used to decide
// whether two clusters in a fleet are genuinely linked. Shared workload NAMES
// (argocd, cert-manager) are deliberately NOT here — every cluster has them, so
// they prove nothing. Only values an unrelated org could not coincidentally
// share: private-registry image digests, private registry hosts (ACR instance /
// ECR account), and the cluster's own served/outbound hostnames.
type FleetLinkage struct {
	PrivateImageDigests []string // host/repo@sha256:… from PRIVATE registries only
	PrivateRegistries   []string // private registry hosts this cluster pulls from
	ServedHosts         []string // Ingress hosts this cluster serves (others call these)
	OutboundHosts       []string // ExternalName targets (non-public) this cluster references
}

// TrendDelta is the compact prev-vs-current summary the report carries so the
// renderer can show "since last audit" badges without re-reading history. It's
// derived from a full history.Diff at audit time; the heavier New/Resolved
// finding slices stay in the history layer.
type TrendDelta struct {
	// PreviousAt is the timestamp of the prior snapshot this delta is against.
	PreviousAt time.Time `json:"previousAt"`
	// NewCount is the number of findings present now but not in the prior audit.
	NewCount int `json:"newCount"`
	// NewIDs are the ids of exactly those findings, sorted. A count a reader cannot open is half a
	// comparison: the instrument printed "13 new in this reading" over a real pair of readings and nothing
	// on the page said which thirteen. Optional, so a reading written before the field still parses and
	// shows its count without the way in.
	NewIDs []string `json:"newIds,omitempty"`
	// ResolvedCount is DEPRECATED and kept only because schema v1 is a forever commitment: a
	// consumer that reads it must keep working. It carries the same number as NoLongerInSetCount.
	// New readers use that field; this one will stop being emitted in a later schema.
	//
	// The name was wrong, not merely unfashionable. Shoalcheck does not watch a cluster — it reads two
	// states minutes apart and reports the difference — so it cannot know that a finding absent from
	// the second reading was RESOLVED. The object may have been deleted, an autoscaler may have
	// acted, a rule may not have run, or someone else may have applied something in the same minute.
	ResolvedCount int `json:"resolvedCount"`

	// NoLongerInSetCount is the number of findings present in the prior reading and absent from this
	// one. It is deliberately a statement about two sets and not about a cause.
	// Always emitted, deliberately without omitempty: a zero is a real answer ("nothing left the
	// set"), and omitting it would leave a no-change run showing only the deprecated resolvedCount —
	// pointing new readers at exactly the field they should stop using.
	NoLongerInSetCount int `json:"noLongerInSetCount"`
	// NoLongerInSet names exactly the findings NoLongerInSetCount counts, by what the EARLIER reading said about
	// each, sorted by id. A new finding can be opened from this reading by its id; one that left cannot — it is
	// only in the earlier reading — so "1 no longer in the set" named nothing (D50 product review). Optional, so
	// a reading written before the field still parses and shows its count alone. The title names the object it
	// was about — possibly one this reading never held — so --redact withholds it and keeps the id, rule and
	// severity.
	NoLongerInSet []TrendFinding `json:"noLongerInSet,omitempty"`
	// NotEvaluatedCount is the number of findings from either reading that could not be compared,
	// because the other reading did not confirm reading something they rest on. Always emitted: a strip
	// that prints "one no longer present" while three findings could not be evaluated is telling half a
	// truth, and a consumer needs the caveat even when it is zero to know the field was computed.
	NotEvaluatedCount int `json:"notEvaluatedCount"`
	// FindingsDelta is current total findings minus the prior total.
	FindingsDelta int `json:"findingsDelta"`
	// SavingsDelta is current EstimatedSavingsUSD minus the prior value.
	SavingsDelta float64 `json:"savingsDelta"`

	// PricingCoverageChanged marks that the two readings could price a different set of node types or
	// storage classes, so SavingsDelta mixes a changed cluster with a changed price table and the two
	// cannot be separated. The polarity is deliberate: the zero value is "coverage was the same", which
	// is what every hand-built TrendDelta and every consumer written before this field assumed, so
	// adding it cannot silently turn an existing report's dollar figure into a caveat.
	PricingCoverageChanged bool `json:"pricingCoverageChanged,omitempty"`

	// SavingsUnpriced says SavingsDelta is not a measurement at all, because NEITHER reading had a savings
	// figure to compare. A difference between two absences renders as "+$0.00/mo identified", which reads as
	// "the savings did not move"; nothing moved because nothing was ever priced, and those are opposite news.
	//
	// A SIBLING OF PricingCoverageChanged AND NOT THE SAME GATE. That one catches a sum moving because the
	// price table changed under two comparable readings. This one catches two readings that never had a
	// figure to compare: the coverage is identical, that gate stays silent, and the delta is arithmetic over
	// two absences.
	//
	// THE POLARITY IS THE SAME DELIBERATE CHOICE ITS SIBLING RECORDS, and for the same reason: the zero
	// value is "the readings were priced", which is what every TrendDelta written before this field assumed.
	// Named the other way round — SavingsPriced — every stored reading would re-render its measured dollar
	// delta as a caveat the moment this field existed.
	SavingsUnpriced bool `json:"savingsUnpriced,omitempty"`

	// ReferenceDataChanged names the reference datasets whose versions differed between the two readings, so
	// the dollar delta was withheld rather than compared. ReferenceDataReason is prose a surface prints
	// verbatim beside the withheld figure, naming both versions.
	//
	// FIELD POLARITY IS THE OPPOSITE DISCIPLINE FROM THE COMPUTATION, deliberately. The zero value here means
	// "no caveat", for the same reason PricingCoverageChanged's does: adding it must not silently turn an
	// existing report's dollar figure into a caveat for a hand-built delta or a consumer written before the
	// field existed. Inside Compute, which reads two real reports, ABSENCE IS TREATED AS DIFFERENCE. Permissive
	// field, restrictive computation — one protects consumers, the other protects claims.
	ReferenceDataChanged []string `json:"referenceDataChanged,omitempty"`
	ReferenceDataReason  string   `json:"referenceDataReason,omitempty"`

	// Label and PreviousLabel are the operators' own words for the two readings (Methodology.Label): "before
	// upgrade to 1.32" → "after". Copy, never a run fact: the comparison gates do not read them.
	Label         string `json:"label,omitempty"`
	PreviousLabel string `json:"previousLabel,omitempty"`
	// RegressedCount is the number of findings present in both readings whose severity grew more urgent;
	// ChangedCount the number present in both with anything load-bearing moved (a superset). Always emitted:
	// a zero is a real answer, as for NoLongerInSetCount.
	RegressedCount int `json:"regressedCount"`
	ChangedCount   int `json:"changedCount"`
	// EngineNote is Comparability.Note: printed beside a comparison that was made across two engine versions
	// with both rule-set stamps present. Empty when the engine did not move.
	EngineNote string `json:"engineNote,omitempty"`
	// ReadingsKept is how many snapshots of this cluster the history store holds, this one included. The cover
	// prints it as an ordinal ("the 5th reading kept"). Zero means the caller did not count.
	ReadingsKept int `json:"readingsKept,omitempty"`
	// NotCompared is set INSTEAD of every count above when a prior reading exists but Gate 0 refused the pair.
	// Until this field, that case rendered nothing, and a reader could not tell "no prior" from "prior,
	// refused" — silence about a refusal is the failure the gates exist to prevent.
	NotCompared *NotCompared `json:"notCompared,omitempty"`
}

// TrendFinding is a finding named in a comparison by the reading that held it: its id, its rule, its severity and
// its title, as that reading wrote them. Nothing else is carried — the earlier reading is in the history store.
type TrendFinding struct {
	ID       string   `json:"id"`
	RuleID   string   `json:"ruleId"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
}

// NotCompared records that a prior reading exists and why it was not compared. The Reason is Gate 0's
// sentence, verbatim.
type NotCompared struct {
	PreviousAt time.Time `json:"previousAt"`
	Reason     string    `json:"reason"`
}

// Architecture is a structured snapshot of cluster topology.
//
// Phase 2 populates it from `kubectl get nodes -o json` (AZs + node pools),
// `kubectl get ns` (namespaces), and a `Stack` discovery probe (CNI, autoscaler,
// GitOps, observability vendor). Topologies / Flows / RBAC are populated by
// per-namespace workload discovery + IaC parsing. The fixture hand-crafts
// everything for Acme Pay in v0.
type Architecture struct {
	AZs        []AZ                `json:"azs"`
	Namespaces []NamespaceSummary  `json:"namespaces"`
	NodePools  []NodePoolSummary   `json:"nodePools"`
	Stack      []StackEntry        `json:"stack"`
	Topologies []NamespaceTopology `json:"topologies,omitempty"`
	Flows      []FlowDiagram       `json:"flows,omitempty"`
	RBAC       []RBACEntry         `json:"rbac,omitempty"`

	// UnpricedNodeTypes lists instance types we could not price (unknown type
	// or region not in the pricing tables — e.g. AKS/GKE nodes against the
	// AWS-only tables). It exists so the report can say "N node types unpriced"
	// rather than silently undercounting EstimatedMonthlySpend. Optional, v1-
	// compatible: omitted when every node type priced.
	UnpricedNodeTypes []string `json:"unpricedNodeTypes,omitempty"`

	// UnpricedStorageClasses lists StorageClass→diskType mappings the pricing
	// tables could not price (unknown SKU, or a provider/region with no storage
	// table — e.g. GCP). Mirrors UnpricedNodeTypes: the report says "N classes
	// unpriced" rather than silently undercounting storage spend. Omitted when
	// every priced class resolved.
	UnpricedStorageClasses []string `json:"unpricedStorageClasses,omitempty"`

	// Observed-service-map fields (Phase 2). All omitempty + zero-value-safe so
	// every existing fixture serializes byte-identically. Tier defaults to
	// TierDeclared (empty reads as declared); the others are populated only when a
	// mesh/CNI telemetry source was reachable. Measured numbers live ONLY on
	// ObservedEdges — declared wiring stays on Topologies[].Edges.
	Tier          Tier           `json:"tier,omitempty"`
	ObservedEdges []ObservedEdge `json:"observedEdges,omitempty"`
	// ObservedAsOf is a *time.Time, not time.Time, because Go's encoding/json
	// never omits a zero time.Time under omitempty (a struct is never "empty");
	// a nil pointer is the only way to keep existing fixtures byte-identical.
	ObservedSource string     `json:"observedSource,omitempty"`
	ObservedWindow string     `json:"observedWindow,omitempty"`
	ObservedAsOf   *time.Time `json:"observedAsOf,omitempty"`
	ObservedNote   string     `json:"observedNote,omitempty"`
}

// NamespaceTopology is a workload-graph view of a single namespace —
// the kind of diagram KubeDiagrams renders from kubectl manifests, but
// minimalist and severity-aware.
//
// Phase 2 builds this from `kubectl get all -n <ns>` + Service selector
// matching against pod labels.
type NamespaceTopology struct {
	Name      string         `json:"name"`
	Workloads []WorkloadNode `json:"workloads"`
	Services  []ServiceNode  `json:"services"`
	Edges     []GraphEdge    `json:"edges"`

	// Tier labels a single namespace as observed/partial/declared for per-namespace
	// partial labeling; empty reads as TierDeclared. Optional, v1-additive.
	Tier Tier `json:"tier,omitempty"`
}

// WorkloadNode is one Deployment / StatefulSet / DaemonSet / CronJob.
type WorkloadNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Replicas  int    `json:"replicas"`
	Severity  string `json:"severity,omitempty"`  // tints the node when there's a finding
	FindingID string `json:"findingId,omitempty"` // deep-link to the finding card
}

// ServiceNode is a Service, Ingress, or external endpoint.
type ServiceNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // Service | Ingress | External
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // ClusterIP | LoadBalancer | NodePort
	Note string `json:"note,omitempty"`
}

// GraphEdge mirrors the four relationship kinds KubeDiagrams uses:
//
//	"selector"      — Service → workload (dashed)
//	"reference"     — direct ref (solid black)
//	"owner"         — ownership chain (dotted)
//	"communication" — declared connectivity (NetworkPolicy allow-rule), not observed traffic (brown)
type GraphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Label string `json:"label,omitempty"`
}

// FlowDiagram is a horizontal request-flow pipeline — it shows declared
// request wiring (Ingress→Service→workload), NOT observed traffic.
type FlowDiagram struct {
	ID    string     `json:"id"`
	Title string     `json:"title"`
	Steps []FlowStep `json:"steps"`
}

// FlowStep is one node in a flow pipeline.
type FlowStep struct {
	Label     string `json:"label"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind"` // service | gateway | datastore | external | cronjob
	Note      string `json:"note,omitempty"`
	FindingID string `json:"findingId,omitempty"`
}

// RBACEntry is one ServiceAccount → ClusterRoleBinding/RoleBinding → Role/ClusterRole
// chain, with risk classification.
type RBACEntry struct {
	Subject     string   `json:"subject"`
	Binding     string   `json:"binding"`
	Role        string   `json:"role"`
	Risk        string   `json:"risk"` // "low" | "medium" | "high" | "critical"
	FindingIDs  []string `json:"findingIds,omitempty"`
	Description string   `json:"description"`
	// RiskBasis says where Risk came from, because a band read from a role's rules and a band guessed from
	// its name are not the same claim and must not render as one:
	//
	//	"rules"      the role's own PolicyRules were in this reading and the band is arithmetic over them
	//	"name"       the role kind was refused, so the band is a guess from the role's name
	//	"unresolved" the role kind was read and this roleRef was not among it
	//
	// Empty on a reading written before the join existed, which a renderer must treat as "not stated"
	// rather than as "rules".
	RiskBasis string `json:"riskBasis,omitempty"`
}

// ClusterPeer is a sibling cluster (staging, DR, etc.) that the audited
// cluster talks to. Phase 2 discovers peers via labels in shared GitOps
// repos or explicit peer config.
type ClusterPeer struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Region      string `json:"region"`
	Role        string `json:"role"`   // primary | staging | dr | ephemeral
	Status      string `json:"status"` // active | standby | decommissioned
	Description string `json:"description"`
	NodeCount   int    `json:"nodeCount"`
	PodCount    int    `json:"podCount"`
	Audited     bool   `json:"audited"` // true if this report covers this cluster
}

// ClusterRelationship is one directed (or bidirectional) link between clusters.
type ClusterRelationship struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Kind      string `json:"kind"`      // replication | image-promotion | shared-secrets | drr-failover | gitops
	Direction string `json:"direction"` // one-way | bidirectional
	Note      string `json:"note"`
}

// Highlight is one hand-curated stat tile shown in a section's bento row
// (e.g. "PCI controls flagged: 3"). Optional — sections render their tiles
// only from data present in the report, never from renderer constants.
type Highlight struct {
	Section string `json:"section"` // security | reliability | cost
	Label   string `json:"label"`
	Value   string `json:"value"`
	Detail  string `json:"detail"`
	Tone    string `json:"tone,omitempty"` // critical | warn | ok | info
}

// Narrative is a hand-written prose panel attached to a section (e.g. the
// Karpenter-pressure analysis). Optional; hidden when absent.
type Narrative struct {
	Section string `json:"section"`
	Title   string `json:"title"`
	Body    string `json:"body"`
}

// AZ is one availability zone with its node assignments.
type AZ struct {
	Name  string    `json:"name"`
	Nodes []NodeRef `json:"nodes"`
}

// NodeRef is one node in a zone — Phase 2 fills Name from kubectl
// `metadata.name`, Type from instance-type label, Namespace from the
// dominant pod-tenant on that node (sum of pod requests).
// Stateful flags nodes whose primary workload manages persistent data
// (e.g. PostgreSQL, Redis). Phase 2 derives this from StatefulSet presence
// or storage-class mounts on the dominant tenant; v0 sets it explicitly in
// the fixture.
type NodeRef struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Namespace is the node's DOMINANT-TENANT namespace — the one running the most of its pods — and not
	// "the namespace this node is in", which is not a thing a node has. The topology diagram says so out
	// loud ("Each node is striped by its dominant-tenant namespace") and this field was the only one on the
	// struct with no comment, so the only place the name could be read straight was here. Renaming it is a
	// forever-contract migration; saying what it means costs nothing.
	Namespace string `json:"namespace"`
	Stateful  bool   `json:"stateful,omitempty"`

	// Capacity is how this node's capacity is purchased (spot / on-demand /
	// unknown), read from read-only node labels via the shared provider-aware
	// classifier. Optional, v1-additive: omitted (zero value) when no capacity
	// signal is present, which keeps old fixtures byte-identical. A missing
	// capacity label is CapacityUnknown, NEVER silently on-demand.
	Capacity CapacityType `json:"capacityType,omitempty"`
}

// NamespaceSummary is a one-line description of a namespace's purpose.
type NamespaceSummary struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Workloads    string `json:"workloads"`
	FindingCount int    `json:"findingCount"`
}

// NodePoolSummary aggregates nodes by instance type + capacity. A mixed
// on-demand/spot pool of the same instance type SPLITS into two summaries so
// each is labelled correctly.
type NodePoolSummary struct {
	Type   string  `json:"type"`
	Spec   string  `json:"spec"`
	Count  int     `json:"count"`
	CostMo float64 `json:"costPerNodeMonth"` // UNCHANGED: on-demand list price; for a spot pool this is an UPPER BOUND

	// REMOVED 2026-09-10: `CostFloorMo float64 json:"costFloorPerNodeMonth,omitempty"`, the LOWER bound of
	// a spot price band. Nothing ever computed one, and that is not an oversight — it is the decision the
	// spot work already took: ship the on-demand list as an honest CEILING and refuse a floor, because a
	// real spot price needs cloud auth this tool does not hold. The field's own last line was "NEVER a
	// fabricated multiplier of CostMo". A field reserved for a figure the product has decided not to
	// produce is a promise the schema makes on its behalf, so the decision lives in docs/DECISIONS.md M-62
	// where it can be read, rather than in a field name nothing writes.

	// Capacity / CostSource / the per-capacity counts are v1-additive Layer 1
	// fields. All omitempty with a Valid() zero value, so a pool with no
	// capacity signal serializes byte-identically to the pre-Layer-1 fixture.
	Capacity        CapacityType `json:"capacityType,omitempty"`
	SpotCount       int          `json:"spotCount,omitempty"`
	OnDemandCount   int          `json:"onDemandCount,omitempty"`
	UnknownCapCount int          `json:"unknownCapacityCount,omitempty"`
	// CostSource records the basis of CostMo: list-estimate for on-demand/unknown
	// pools, spot-ceiling for spot pools (the list price is an UPPER BOUND, real
	// spot spend is lower and variable). Never "billed" in Layer 0/1.
	CostSource CostSource `json:"costSource,omitempty"`
}

// StackEntry is one platform-stack component (CNI, autoscaler, GitOps, …).
type StackEntry struct {
	Layer string `json:"layer"`
	Name  string `json:"name"`
	Note  string `json:"note"`
}

// ComplianceRow maps an audit-framework control to one or more findings.
//
// Status: "gap" (the only value BuildCompliance emits today; renderer reframes
// to "Potential gap"). "partial"/"ok" reserved.
type ComplianceRow struct {
	Framework  string   `json:"framework"`
	Control    string   `json:"control"`
	Title      string   `json:"title"`
	Status     string   `json:"status"`
	FindingIDs []string `json:"findingIds"`
}

// DomainAssessments holds the per-domain check lists rendered in the
// dedicated sections (Observability, GitOps, Deployments, Alerts).
type DomainAssessments struct {
	Observability []DomainCheck `json:"observability"`
	GitOps        []DomainCheck `json:"gitops"`
	Deployments   []DomainCheck `json:"deployments"`
	Alerts        []DomainCheck `json:"alerts"`
}

// DomainCheck is a single yes/no/partial assessment within a domain.
//
// Status: "ok" | "warn" | "fail" | "info".
type DomainCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	FindingRef  string `json:"findingRef,omitempty"`
	Recommended string `json:"recommended"`
}

// Summary aggregates the report at a glance — feeds the Executive Summary
// section of the rendered HTML.
type Summary struct {
	TotalFindings       int              `json:"totalFindings"`
	BySeverity          map[Severity]int `json:"bySeverity"`
	ByCategory          map[Category]int `json:"byCategory"`
	EstimatedSavingsUSD float64          `json:"estimatedSavingsUsd"`
	HighestPriorityID   string           `json:"highestPriorityId"`
}

// ClusterInfo identifies the cluster being audited.
type ClusterInfo struct {
	Name                  string  `json:"name"`
	KubernetesVersion     string  `json:"kubernetesVersion"`
	Provider              string  `json:"provider"` // eks | gke | aks | onprem | kind | minikube
	Region                string  `json:"region"`
	NodeCount             int     `json:"nodeCount"`
	PodCount              int     `json:"podCount"`
	NamespaceCount        int     `json:"namespaceCount"`
	EstimatedMonthlySpend float64 `json:"estimatedMonthlySpend"`

	// SpendSource records the basis of EstimatedMonthlySpend: list-estimate when
	// every pool is on-demand/unknown, spot-ceiling when any spot pool is present
	// (the cluster total then includes at least one upper-bound pool). v1-additive,
	// omitempty with a Valid() zero value — old fixtures stay byte-identical. Never
	// "billed" in Layer 0/1; the estimate stays the canonical number.
	SpendSource CostSource `json:"spendSource,omitempty"`

	// StorageMonthlyUSD is the summed PV/PVC capacity priced at list per GB-month
	// (the storage component already folded into EstimatedMonthlySpend, surfaced
	// separately so the report can break it out). Omitted when no storage priced.
	StorageMonthlyUSD float64 `json:"storageMonthlyUsd,omitempty"`

	// REMOVED 2026-09-10: `EgressMonthlyUSD float64 json:"egressMonthlyUsd,omitempty"`, "reserved for
	// priced egress when traffic volume becomes observable". The per-GB rates exist
	// (internal/pricing/storage_egress_gen.go) and the VOLUME does not: a read-only reading of the
	// Kubernetes API sees no bytes transferred, and no collector this architecture permits would. The field
	// was reserved for a figure this product cannot compute.
}

// Methodology documents how the report was produced — surfaces in the
// Methodology section of the rendered HTML.
//
// AnonymizationApplied is intentionally absent: surfacing an always-false value invites a "so my data goes
// to an LLM provider?" question before either the anonymization feature or the LLM integration exists.
//
// THAT ARGUMENT USED TO CONTRADICT ITSELF, two fields below where it was written. `LLMModel string` and
// `LLMTokensUsed int` were declared here — "empty in v0; informative when populated" — and nothing ever set
// either. So the struct made exactly the claim its own comment refused: a reader of the JSON schema saw
// `llmModel` and `llmTokensUsed` and could reasonably infer a model is in the loop, on a product whose
// whole position is that it reads a cluster from a laptop and contacts nothing else.
//
// REMOVED 2026-09-10 (docs/DECISIONS.md M-62). Both were omitempty and appear in none of the 48 saved
// readings measured, so no consumer can be parsing them. If an LLM step ever exists they come back through
// a schema migration with a producer attached — which is what the sentence above always said.
type Methodology struct {
	CollectorsRun      []string `json:"collectorsRun"`
	RunDurationSeconds int      `json:"runDurationSeconds"`
	DataSources        []string `json:"dataSources"`

	// Illustrative marks a report built from a demo/sample fixture rather than a
	// real cluster scan. When true the renderer shows a banner at the top of the
	// report so the reader can never mistake the body for measured data. Omitted
	// (false) for real audits. Validate() ignores it — a real run never sets it.
	Illustrative bool `json:"illustrative,omitempty"`

	// UsageMethodology records where every usage number came from (source,
	// backend flavour, confidence grade, window, caveats). Nil for non-usage
	// runs ⇒ byte-identical to today (omitempty), no Validate change.
	UsageMethodology *UsageMethodology `json:"usageMethodology,omitempty"`

	// CollectedKinds and DeniedKinds are the machine-readable record of what this run could and
	// could not read, as kind NAMES only.
	//
	// DataSources above already says the same thing in prose, but a prose sentence that concatenates
	// raw API error strings cannot be parsed by anything, and comparing two audits is only honest if
	// a guard can establish that both runs looked for the same things. A finding that a run could not
	// look for is not a finding that went away.
	//
	// The error text deliberately stays out of DeniedKinds: it belongs in the human-readable sentence,
	// it differs between runs for the same denial, and repeating it here would duplicate whatever the
	// API server chose to say about the operator's own permissions.
	CollectedKinds []string `json:"collectedKinds,omitempty"`
	DeniedKinds    []string `json:"deniedKinds,omitempty"`

	// Unread is every kind in DeniedKinds paired with the cause internal/collect measured for it.
	//
	// IT WAS AN ENGLISH SENTENCE PARSED BY A REGEX, and the justification was wrong. On 2026-09-10 the
	// causes lived only inside the DataSources note — "Partial collection — 3 resource kind(s) could not
	// be read: pods (not reachable), …" — and UnreadKinds() recovered them with two regexes. The reason
	// given was that a new field here is a forever-contract addition. That reason does not survive its own
	// week: ClaimBoundaries, IDBasis and RunBasis.Redacted were all added as additive omitempty fields in
	// the same seven days. This is the same kind of field.
	//
	// The failure mode was silent and total: rephrase the sentence — a comma, a word, a translation — and
	// every saved reading loses its causes, each kind falling back to "cause not recorded", which is a
	// value every gate accepts. Prose is for readers; a field is for programs.
	//
	// The note stays, because the document renders it and a person reads it. This field is authoritative;
	// UnreadKinds() parses the note only for a reading written before the field existed.
	Unread []UnreadKind `json:"unread,omitempty"`

	// RunBasis identifies WHICH cluster this reading is of and under what settings, so two snapshots
	// are never compared across clusters or across incompatible options. Nil on older snapshots,
	// which is itself the signal that no comparison may be made against them.
	RunBasis *RunBasis `json:"runBasis,omitempty"`

	// Label is the operator's own words for why this reading was taken — "before upgrade to 1.32". Set by
	// `shoalcheck audit --label` and by a schedule's Spec.Label. Copy, never a run fact: no gate reads it, and
	// the redactor clears it (free text may name anything).
	Label string `json:"label,omitempty"`

	// SessionTrace records the HTTP requests this process issued while producing the report, grouped at the
	// RBAC unit. Optional and additive: absent on a report produced without a recorder.
	SessionTrace *SessionTrace `json:"sessionTrace,omitempty"`

	// Volume is what this reading read, in the units somebody reading the same cluster another way would need:
	// objects, the bytes they occupy as `kubectl get -o yaml` prints them (managedFields omitted, as kubectl
	// omits them by default), and the (rule, object) pairs the rules examined. Every "what it would take
	// another way" figure stands on it — an agent that reads these objects once takes in at least these bytes.
	// Optional and additive: nil when nothing was read, and on readings older than the field.
	Volume *ReadVolume `json:"volume,omitempty"`

	// Simulation marks a reading that is NOT of a cluster as it is: a reading with a change laid over it in
	// memory, by `shoalcheck gate --with`. Nothing was applied to any cluster. Nil on every reading of a cluster
	// as it is, which is every reading this product took before the field existed.
	//
	// A FIELD, NOT ONLY A SENTENCE. DataSources says the same thing to a person; this says it to a program, so a
	// simulated reading kept with --json cannot later be handed to `gate --baseline` or the history and compared
	// as if the cluster had ever been in that state.
	Simulation *Simulation `json:"simulation,omitempty"`
}

// Simulation is what a simulated reading was built from and what it does not account for.
type Simulation struct {
	// Base is what the change was laid over: "live", a reading of the cluster taken by the same run; "capture", an
	// inventory captured earlier by `shoalcheck audit --capture`; "empty", no cluster at all (--manifests-only).
	Base string `json:"base"`
	// BaseAt is when the base was read. For a capture it is the capture's own reading clock, not the run's.
	BaseAt time.Time `json:"baseAt"`
	// Files is every manifest file the change was read from, as given.
	Files []string `json:"files"`
	// Objects is every object laid over the base, in the order applied.
	Objects []SimulatedObject `json:"objects"`
	// NotEvaluated is every object the change carries that was not laid over, each with its reason. Never
	// dropped: a reader has to be able to tell "judged and fine" from "not looked at".
	NotEvaluated []SimulatedObject `json:"notEvaluated,omitempty"`
	// NotSimulated is what the method does not account for — admission, defaulting, controllers, hooks,
	// deletions — in the words every surface prints.
	NotSimulated []string `json:"notSimulated"`
}

// SimulatedObject is one object a change carries and where it came from.
type SimulatedObject struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	File      string `json:"file"`
	// Doc is the document in File, counted from 1; Item the item of a List, counted from 1, when it was one.
	Doc  int `json:"doc"`
	Item int `json:"item,omitempty"`
	// Action is "created" or "replaced" for an object laid over; empty for one not evaluated.
	Action string `json:"action,omitempty"`
	// Reason is why an object was not evaluated; empty for one laid over.
	Reason string `json:"reason,omitempty"`
}

// ReadVolume is the measured size of one reading's read.
type ReadVolume struct {
	Objects   int   `json:"objects"`
	YAMLBytes int64 `json:"yamlBytes"`
	// Pairs is Σ over the rules that ran of the objects in the kinds each one reads: the checks a person would
	// make by hand to cover the same ground. Zero means not counted, never "no checks".
	Pairs  int          `json:"pairs,omitempty"`
	ByKind []KindVolume `json:"byKind"`
}

// KindVolume is one kind's share of a reading's read.
type KindVolume struct {
	Kind    string `json:"kind"`
	Objects int    `json:"objects"`
	Bytes   int64  `json:"bytes"`
}

// RunBasis is the identity and settings of one audit run — the minimum needed to decide whether two
// readings are comparable at all.
type RunBasis struct {
	// ClusterUID is the kube-system Namespace UID. It is the only stable cluster identity available
	// from a read-only snapshot: a kube context can be renamed, reused for a rebuilt cluster, or point
	// somewhere else entirely, so keying history on a display name silently compares two clusters.
	// Empty when kube-system was not collected — in which case no comparison may claim identity.
	ClusterUID string `json:"clusterUid,omitempty"`

	// IncludeSystem records whether system namespaces were evaluated. Two runs that disagree are not
	// comparable: findings appear and vanish wholesale purely from the setting.
	IncludeSystem bool `json:"includeSystem,omitempty"`

	// UsageSource is denormalised from UsageMethodology so a guard reads one field. A run with usage
	// and a run without it produce different rule populations, so the difference is not a cluster
	// change.
	UsageSource string `json:"usageSource,omitempty"`

	// UsageTier records whether the usage source was PROVEN to be this cluster's, or merely reachable.
	//
	// B-145: the usage queries carry no cluster selector, so a Thanos or Mimir holding several clusters
	// answers them perfectly and attributes another cluster's consumption to this one. "Prometheus
	// resolved" is not the fact worth recording; "resolved and proven to be this cluster's, by this
	// check" is. Values are prom.Tier: "none", "unproven", "proven".
	//
	// It sits beside UsageSource rather than inside UsageMethodology because a COMPARISON needs it: two
	// readings whose usage tiers differ produce different rule populations for a reason that has nothing
	// to do with the cluster, which is the same argument UsageSource itself is here for.
	UsageTier string `json:"usageTier,omitempty"`

	// UsageProvenance is why. Carried so a withheld figure can be explained where it is withheld, rather
	// than leaving the reader to infer a gap from an absence.
	UsageProvenance string `json:"usageProvenance,omitempty"`

	// EngineVersion is the rule engine that produced the findings. A rule that changed between runs
	// can add or drop findings with nothing having happened in the cluster.
	EngineVersion string `json:"engineVersion,omitempty"`

	// RuleSet is every producer whose ID can appear in Finding.RuleID, with its version, as the build that
	// took this reading knew it. It lets a comparison ask the sharp question — "did the other reading's
	// build have this rule at all?" — and withhold only the findings it cannot speak to, instead of
	// refusing the whole reading whenever EngineVersion moved (see internal/history, Gate 0 and Gate 1).
	// Sorted by ID. About 1–2 KB per snapshot. Absent on snapshots written before 2026-09-02.
	RuleSet []RuleStamp `json:"ruleSet,omitempty"`

	// OwnerLabel is the namespace label key the operator named with --owner-label, and OwnerCoverage is how
	// many findings it resolved out of how many could have had one. Both are on the reading rather than
	// inferred from the findings, because "12 of 134 have an owner" is the honest form and a list of four
	// team names alone would let a reader assume the rest were covered.
	//
	// The KEY is customer text — an operator's own convention — so it is redacted with everything else.
	OwnerLabel    string `json:"ownerLabel,omitempty"`
	OwnerResolved int    `json:"ownerResolved,omitempty"`
	OwnerOwnable  int    `json:"ownerOwnable,omitempty"`

	// Redacted marks a reading written by `--redact`: its ClusterUID is a token, deterministic across redacted
	// readings of the same cluster and unmatchable against a plain one. Gate 0 reads it to say WHAT happened
	// when the UIDs differ, instead of asserting two clusters.
	Redacted bool `json:"redacted,omitempty"`

	// DataVersions maps a reference dataset's registry name to the version and source this run read.
	//
	// SAME REASON AS EngineVersion, one layer down. A rule that changed can add or drop findings with the
	// cluster untouched; a price TABLE that changed can move every dollar figure with the cluster untouched.
	// Without this field a comparison across a table refresh announces "+$1,200/mo identified" and attributes
	// it to the customer, which is the defect the whole comparison layer exists to prevent.
	//
	// Generalises pricing's AsOf() (date, source) rather than inventing a second convention.
	DataVersions map[string]DataVersion `json:"dataVersions,omitempty"`
}

// RuleStamp is one producer's identity in a RunBasis.RuleSet.
type RuleStamp struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// DataVersion is one reference dataset's stamp.
type DataVersion struct {
	// Version is the dataset's own stamp, e.g. "2026-08". THE COMPARISON GATE COMPARES THIS AND NOT Source:
	// the same table read from the embedded snapshot on Monday and from a bundle on Friday is the same table,
	// and refusing a comparison over its provenance would withhold one we are entitled to make.
	Version string `json:"version"`
	// Source is where the bytes came from: embedded | cache | bundle | live. Printed, never compared.
	Source string `json:"source"`
}

// DataSourceValid reports whether s is in the closed provenance set.
//
// The set lives here rather than being imported from internal/refdata because internal/types is a leaf: every
// package depends on it and it depends on nothing. The refdata constants are the authority and a test in that
// package asserts the two agree, which is the same shape Severity and Category already use.
func DataSourceValid(s string) bool {
	switch s {
	case "embedded", "cache", "bundle", "live":
		return true
	}
	return false
}

// CriticalCount returns the number of critical findings — convenience for templates,
// where map[Severity]int can't be indexed with a plain string literal.
func (s Summary) CriticalCount() int { return s.BySeverity[SeverityCritical] }

// HighCount returns the number of high-severity findings.
func (s Summary) HighCount() int { return s.BySeverity[SeverityHigh] }

// MediumCount returns the number of medium-severity findings.
func (s Summary) MediumCount() int { return s.BySeverity[SeverityMedium] }

// LowCount returns the number of low-severity findings.
func (s Summary) LowCount() int { return s.BySeverity[SeverityLow] }

// InfoCount returns the number of info-severity findings.
func (s Summary) InfoCount() int { return s.BySeverity[SeverityInfo] }

// Tier classifies how an Architecture's connectivity was derived. An empty Tier
// reads as TierDeclared (the v0/declared-only default), so existing fixtures and
// reports without observed telemetry serialize byte-identically.
type Tier string

const (
	// TierObserved: edges are MEASURED from a mesh/CNI telemetry source.
	TierObserved Tier = "observed"
	// TierPartial: some namespaces have observed edges, others only declared wiring.
	TierPartial Tier = "partial"
	// TierDeclared: declared-only wiring derived from Ingress/Service/NetworkPolicy.
	TierDeclared Tier = "declared"
)

// ObservedEdge is one MEASURED edge from a mesh/CNI telemetry source. It is
// DISTINCT from the declared GraphEdge: GraphEdge carries only From/To/Kind/Label
// strings and is wiring; ObservedEdge carries real numbers, server-aggregated at
// ONE pinned reporter. The two never merge — conflating measured with declared is
// the honesty problem the declared-graph guards.
type ObservedEdge struct {
	From           string  `json:"from"` // "Kind/Name" WorkloadNode ID, or "external/…"/"unknown/…"
	To             string  `json:"to"`
	Protocol       string  `json:"protocol"` // http | grpc | tcp
	RequestsPerSec float64 `json:"requestsPerSec"`
	ErrorRatePct   float64 `json:"errorRatePct"`
	P50Ms          float64 `json:"p50Ms,omitempty"`
	P99Ms          float64 `json:"p99Ms,omitempty"`
	MTLS           string  `json:"mtls"` // none | partial | strict
	// REMOVED 2026-09-10: `MTLSPct float64 json:"mtlsPct,omitempty"`. Superseded by MTLS above, which is
	// what internal/prom/servicemap.go actually computes — a three-value string derived from Istio's
	// connection_security_policy, never a ratio. Nothing ever set the percentage.
	VerdictDroppedPct float64 `json:"verdictDroppedPct,omitempty"` // Hubble L4
	Source            string  `json:"source"`                      // istio | linkerd | hubble | ingress
	Window            string  `json:"window"`                      // "5m"
	Confidence        string  `json:"confidence"`                  // high (destination-reporter) | partial
}

// SessionTrace is the report's session-trace appendix.
//
// It carries NO path, NO query string and NO header, because the records it is built from carry none. What it
// carries is the RBAC unit — (verbs × apiGroup/resource[/subresource] × scope) with counts — which is the unit
// the read-only claim is actually made in, the unit deploy/rbac.yaml grants in, and a unit this report already
// publishes unredacted in Methodology.CollectedKinds. That is deliberate: an appendix that added no new
// identifier needs no new redaction branch, and a design that DID need one would have leaked on its first
// release, because internal/redact rebuilds only the fields it names and already misses others.
type SessionTrace struct {
	Rows []SessionTraceRow `json:"rows"`

	// Total is every request this PROCESS issued, pre-flight included. Run and Preflight split it, because
	// presenting the run's number under a sentence about the session is an undercount wearing the word total.
	Total     int `json:"total"`
	Run       int `json:"run"`
	Preflight int `json:"preflight"`

	// ObjectWrites counts create/update/patch/delete against an object, and must be zero. Streams counts
	// opt-in proxied streams (create pods/portforward), which write no object and are reported separately
	// rather than folded into either total — both alternatives would be false.
	ObjectWrites int `json:"objectWrites"`
	Streams      int `json:"streams"`
	// External counts requests to a system the operator configured that is NOT the cluster — today an issue
	// tracker, reached only on an explicit opt-in push. Counted, on its own line, folded into neither
	// ObjectWrites nor the read total, for the reason trace.ClassExternal gives.
	//
	// It is ZERO on every path that exists today: `shoalcheck ticket push` is a separate command from an audit
	// and the desktop app has no ticket surface, so no process both audits and pushes. It is carried anyway
	// because Total claims to be every request THIS PROCESS issued, and a number that is only correct while
	// a coincidence holds is the kind of claim this schema exists to prevent.
	//
	// The DESTINATION is deliberately absent, here and on the rows: a self-hosted tracker's hostname names
	// the customer, and this document is what leaves their control. See TestSessionTrace_NeverCarriesAnExternalHost.
	External int `json:"external,omitempty"`

	// Denied counts requests the server refused, NoResponse those that never got an answer, Retried those
	// repeating a tuple after a throttle or failure. All three stay inside Total: they were issued.
	Denied     int `json:"denied,omitempty"`
	NoResponse int `json:"noResponse,omitempty"`
	Retried    int `json:"retried,omitempty"`

	// ExecCredentialPlugin names the kubeconfig's credential plugin when it has one. Those plugins are
	// SEPARATE PROCESSES that contact a cloud identity provider, so their requests are not HTTP requests in
	// this process and cannot be counted here at all. Naming the plugin is how the appendix scopes its own
	// claim honestly instead of implying totality it cannot have.
	ExecCredentialPlugin string `json:"execCredentialPlugin,omitempty"`
}

// SessionTraceRow is one appendix row: everything issued against one resource at one scope.
type SessionTraceRow struct {
	Verbs    []string `json:"verbs"`
	Resource string   `json:"resource"`
	Scope    string   `json:"scope"`
	Requests int      `json:"requests"`
	// Outcome summarises what came back, e.g. "ok" or "12 ok, 1 forbidden".
	Outcome string `json:"outcome"`
	// Class is "read", "stream", "write" or "external".
	Class string `json:"class"`
	// Paths lists the whitelisted discovery routes a non-resource row covers. Empty for resource rows.
	Paths []string `json:"paths,omitempty"`

	// Ref is this row's reference within THIS reading — "T-04" — so a finding can cite the requests that
	// read its inputs and a reader can find the row those chips point at.
	//
	// A POSITION IN A CANONICAL ORDER, NOT AN ARRIVAL NUMBER. Numbering by the order requests happened to
	// land would make two readings of one cluster produce different numbers whenever the collector's
	// concurrency interleaved differently, so the two documents could not be laid side by side. Numbered by
	// the tuple instead, which is the row's real identity.
	//
	// It is a reference into this document and NOT a durable identifier: add a resource to the cluster and
	// the numbers after it shift, which is inherent to any dense numbering. Anything joining two readings
	// joins on Resource and Scope, which every row prints.
	Ref string `json:"ref,omitempty"`

	// ConsumedBy names the rules whose findings rest on the kind this row's requests read — Dependencies.Kinds
	// inverted. This is the join that makes the document falsifiable in the other direction: the ledger stops
	// being a list of traffic and becomes an answer to "what did you do with it".
	//
	// Empty is a real answer, not missing data: a request whose reading no rule consumed was still issued, and
	// saying so is the honest thing. The renderer prints that state rather than a blank cell.
	ConsumedBy []string `json:"consumedBy,omitempty"`
}
