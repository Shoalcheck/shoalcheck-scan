// Package rules contains shoalcheck's detection rules. Each rule reads
// the read-only Inventory and emits schema-v1 Findings. Evidence is built
// ONLY from collected data — never from sources a collector can't know.
package rules

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Shoalcheck/shoalcheck-scan/internal/buildinfo"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type Options struct {
	// IncludeSystem evaluates rules inside kube-system & friends.
	// Default false: operator-managed namespaces drown reports in noise —
	// the #1 false-positive complaint about cluster scanners.
	IncludeSystem bool

	// Usage holds 7-day p95/max container usage keyed by "ns/pod/container".
	// nil unless --prometheus-url given; enables usage-based rules (Rightsizing).
	// Rules that don't read it ignore it, so adding it is non-breaking.
	Usage map[string]prom.ContainerUsage

	// UsageWindow is the span the usage above actually covers — "7d" when Prometheus holds the week the
	// queries ask for, "1h" when it was started an hour ago, "" when nothing measured it.
	//
	// IT WAS NOT HERE, AND THE RULES PRINTED THE SPAN OF THE QUERY INSTEAD. Measured on the mesh testbed
	// after an hour of Prometheus: the methodology block said window "1h" with a caveat naming the shortfall,
	// and the finding beside it said "requests 900m CPU, 7d p95 usage 0m". The honest number was one field
	// away and the sentence that travels into a ticket had the wrong one. prom's provider computes this; the
	// pipeline passes it; a rule that does not have it says "observed" and never a figure.
	UsageWindow string

	// Prices is the resolved price provider for this run — embedded, cache or live bundle. nil means the
	// embedded snapshot, which is what every test that builds Options{} gets.
	//
	// EVERY DOLLAR A RULE STATES GOES THROUGH THIS. Until 2026-09-02 rules called the package-level pricing
	// functions directly, so a refreshed bundle moved the cover's spend and never a finding's figure, and the
	// two priced the same machine from two tables on one page. prices() below is the one door.
	Prices pricing.PriceProvider

	// Temporal holds the signals only the second data source can produce — firing alerts, CFS throttling,
	// scrape health. See internal/prom/temporal.go.
	//
	// NIL MEANS NOT ASSESSED, and that is a third state distinct from "assessed and clean". It is nil when
	// no metrics source resolved AND when one resolved but could not be PROVEN to be this cluster's — the
	// B-145 state, Tier 1b — because a temporal claim built on another cluster's series is wrong the same
	// way a dollar figure is, and reads more confidently. Rules that read it are silent on nil.
	Temporal *prom.Temporal

	// PriorReadings is the read-only view of the time axis: what earlier readings of this cluster recorded about
	// its node pools (see prior.go). nil means no history was offered — the common case for a first reading or a
	// run without --save-history — and a rule that reads it says nothing rather than "0 of 0".
	PriorReadings []PriorReading
}

type Rule interface {
	ID() string
	Version() string
	// RequiredKinds names the collector steps this rule's findings rest on, so a comparison between two
	// audits can tell a changed cluster from a changed reading. Mirrors StackAnalyzer.RequiredGVRs.
	// See deps.go for the discipline about what belongs in the list — and for why it gates comparison
	// rather than execution.
	RequiredKinds() []string
	Evaluate(inv *collect.Inventory, opts Options) []types.Finding
}

// All returns the registry in stable order.
func All() []Rule {
	// Stable order: security first, then reliability, then config/cost
	// hygiene — the order findings appear when severities tie.
	base := []Rule{
		ClusterAdminServiceAccount{},
		// The same grant held by a User or a Group (v0.1.1): a separate id, because the ServiceAccount rule's
		// says what it covers and a rule id is a contract. See rbac_cluster_admin_user.go for what it leaves to
		// its neighbours so that one binding never carries two findings arguing different things.
		ClusterAdminUserOrGroup{},
		// Role/ClusterRole BODIES — what a binding actually grants. Placed straight after
		// ClusterAdminServiceAccount because they read the same bindings from opposite ends: that rule
		// flags a binding to the one role everybody recognises, this one reads what any bound role
		// permits. See rbac_grants.go for the permission-union claims it refuses to make.
		RBACDangerousGrant{},
		PrivilegedHostAccess{},
		NoNetworkPolicy{},
		// Reference integrity — one object names another and the other is not there. From Sweep 2 of the
		// exhaustive-coverage epic, which called it the highest-yield of the four sweeps and the one whose
		// findings are unarguable: a name that resolves to nothing is a contradiction inside the operator's
		// own configuration rather than an opinion about best practice. See dangling.go for the consequences
		// these deliberately refuse to claim.
		DanglingServiceAccount{},
		DanglingRoleRef{},
		DanglingScaleTarget{},
		// Phase 1's reference-integrity additions: the three CLASS objects plus a StatefulSet's governing
		// Service. Each name was previously echoed rather than resolved — silent_failures.go printed a
		// PVC's storageClassName beside "the class object itself was not read" — and a name this product
		// repeats without resolving is a name it cannot tell from a typo. Every one was cleared through
		// the OVERLAP census against all 57 shipped rules before it was written.
		DanglingStorageClass{},
		DanglingIngressClass{},
		DanglingPriorityClass{},
		DanglingGoverningService{},
		// Kind 3 of the overlap census: a different claim about the same subject as condition-unchanged,
		// separated by the TIME axis. That rule reports a condition stuck for seven days; this reports
		// what the kubelet is saying now. Both cards name the other, which is what the census's rule
		// requires so a reader does not count one problem twice.
		PodNotReady{},
		// Declaration validity — a spec that contradicts itself inside ONE object. The narrowest claims
		// this product makes: nothing is joined, nothing is observed, and no second list's absence could
		// fabricate them.
		ProbePortNotDeclared{},
		DuplicateEnvVar{},
		ServiceTargetPortUndeclared{},
		// Structure and ownership: how many of something there is, and who is responsible for it.
		SingleControlPlaneNode{},
		UnmanagedPod{},
		PodCoveredByTwoPDBs{},
		// The last of Phase 1's buildable rows. replicas-below-desired and container-restart-total are
		// the two OBSERVABLE-ELSEWHERE rows: shipped, not suppressed, per Q1 — suppressing would make the
		// document depend on the reader's tooling rather than on the cluster's state.
		ReplicasBelowDesired{},
		ContainerRestartTotal{},
		ExternalTrafficPolicyConsequence{},
		CronJobNoStartingDeadline{},
		DanglingBindingSubject{},
		JobNoTTL{},
		HPABurstExceedsAllocatable{},
		// Spec versus status — what the operator asked for against what the controller wrote back. From
		// Sweep 3 of the same epic, which corrected the Sweep 1 census: "stuck conditions" came back
		// COVERED from a leaf probe and the code had three uses of LastTransitionTime, none of them the
		// general question. Placed next to the reference-integrity family because both report a
		// disagreement the cluster is already carrying, rather than one a future change would cause.
		StuckCondition{},
		DaemonSetMisscheduled{},
		VolumeExpansionIncomplete{},
		// Cross-object contradiction — two things the operator DECLARED that cannot both be satisfied.
		// From Sweep 4, and the distinction from the two families above is the wording: a dangling
		// reference is a typo or a deletion, a stale status is a controller's own report, and a
		// contradiction is two decisions that were each reasonable alone.
		SharedRWOVolume{},
		AutoscalerFloorBelowBudget{},
		// The oblique routes, from §3 of the exhaustive-coverage spec: when something looks unreachable,
		// ask what a controller wrote down about it. Image contents need a scanner and node posture needs
		// the node filesystem; the kubelet published a digest and a version about each, and until
		// oblique.go neither was read.
		ImageDigestDrift{},
		NodeVersionSkew{},
		DefaultSATokenAutomount{},
		SecretInEnvVar{},
		RBACBuiltinSubject{},
		// Pod Security Standards (PSS) — admission-level linchpin first, then the
		// per-container checks it makes honest. See internal/rules/pss.go.
		PodSecurityAdmissionNotEnforced{},
		SingleReplicaNoPDB{},
		NoAntiAffinity{},
		PDBBlocksDrains{},
		// Drain Preflight — per-node evacuation feasibility. Placed straight after
		// PDBBlocksDrains because they read the same budgets from opposite ends: that rule
		// flags a budget written to block every drain, these report what a specific node's
		// drain would actually run into. See node_drain.go for the list of claims these
		// deliberately refuse to make.
		NodeDrainBudget{},
		NodeDrainUnmanaged{},
		NodePlacementConcentration{},
		NodePinnedVolume{},
		// The fourth Drain Preflight rule and the two feasibility scenarios that stand on it. Placed here
		// because they read the same placement and the same volumes from a wider blast radius: NodePinnedVolume
		// asks what blocks draining ONE node, these ask what has nowhere to go when a node or a whole zone is
		// gone. See feasibility.go for the scheduler claims they refuse to make — and for why the negative is
		// sound while the positive is not.
		ZonePinnedVolume{},
		// Upgrade Preflight — what the cluster will stop serving, and what it cannot complete.
		DeprecatedAPIServed{},
		CRDConversionWebhookUnbacked{},
		NodePoolCannotRoll{},
		// The temporal axis — the signals only a proven metrics source can produce.
		AlertsFiring{}, ContainerThrottled{}, ScrapeTargetsDown{},
		ZoneLossFeasibility{},
		NodeLossFeasibility{},
		RiskyRolloutStrategy{},
		// Rollout Preflight — what a rolling update of a given workload runs into, decided by
		// arithmetic over the strategy fields. Placed straight after RiskyRolloutStrategy because
		// they read the same fields from opposite ends: that rule offers a remediation for a risky
		// strategy, these state the mechanism and refuse the impact language. See
		// rollout_preflight.go for why NO rule in that file reads a PodDisruptionBudget for a
		// rollout claim — a PDB does not gate a rolling update.
		RolloutDoesNotSelfRoll{},
		RolloutNeedsSurgeCapacity{},
		// Ground Truth — what the cluster's own controllers have published, in the present tense.
		// See rotation.go for the list of outcome claims these deliberately refuse.
		ServiceNoReadyEndpoints{},
		ServiceEndpointsOneNode{},
		// Ground Truth — states the cluster records and nothing reports. See silent_failures.go.
		HPAPinnedAtMax{},
		PVCPendingWithBlockedConsumer{},
		CronJobNoRecentSuccess{},
		MissingProbes{},
		MissingRequests{},
		MutableImageTags{},
		NoResourceGovernance{},
		// Config-hygiene half of Ground Truth and Rollout Preflight: each of these reports a
		// disagreement between two things already in the cluster, never a prediction.
		PodSelectedButUnpublished{},
		IngressBackendUnresolved{},
		RolloutContradictsDeclaredMinimum{},
		StatefulSetPartitionLeftBehind{},
		// The cluster that contradicts itself — a declaration the operator wrote against a label
		// set, a namespace list, or a count their own controller published. See
		// self_contradiction.go for why the PDB rule reads status.expectedPods and never matches a
		// selector itself, and for the list of scheduling verdicts none of these five make.
		PDBSelectsNoPods{},
		TopologyKeyNoNodeCarries{},
		NodeSelectorNoNodeCarries{},
		QuotaBelowCommitted{},
		NetPolPeerSelectsNoNamespace{},
		IdleLoadBalancer{},
		// A provisioned disk whose published phase says nothing is using it. Placed beside the idle
		// load balancer because they are the same shape of finding — a cloud resource billed with
		// nothing attached — and because both gate their dollar rather than assuming one. See
		// unattached_volumes.go for why this rule's gate is the volume's own source and not a cloud
		// providerID on some node.
		UnattachedVolume{},
		// Placed beside UnattachedVolume because both price PersistentVolumes through the one mapping in
		// collect.StorageDiskTypeFor — a second copy of that switch is the drift this package has paid for
		// before. This one states a RATE DIFFERENCE on storage that stays; that one states storage nobody
		// is using. They never describe the same volume the same way.
		Gp2WhereGp3IsCheaper{},
		// The other rule that names money leaving right now rather than money that could be rearranged:
		// a version past its provider's ordinary support is billed a surcharge every hour, and nothing
		// inside the cluster says so.
		VersionPastStandardSupport{},
		// Same machine, later name, lower list price — and the one honesty split that matters (x86 banked,
		// arm64 disclosed) is inside the rule. Measured before it was written: see its doc comment.
		InstanceGenerationLag{},
		// States a would-be figure and refuses to sum it — see the type's comment for why a snapshot cannot
		// justify a year-long commitment.
		CommitmentCandidate{},
		NodeHeadroom{},
		Rightsizing{},
	}
	// Splice in the table-driven PSS container checks (one Rule per pssChecks
	// entry, each with a distinct RuleID so findingIDs never collide).
	return append(base, pssRules()...)
}

// findingID derives a stable ID from rule + canonical resource ref (kind
// included: a Deployment and a StatefulSet may share ns/name), so the same
// issue keeps the same ID across runs (enables diffing later). 12 hex chars
// keep birthday-collision odds negligible even at thousands of findings.
// FindingIDFor is findingID for callers outside this package: a preflight that filters findings to a named node
// or zone has to compute the id a rule would have given it, and a second hash would be a second truth.
func FindingIDFor(ruleID, kind, ns, name string) string { return findingID(ruleID, kind, ns, name) }

func findingID(ruleID, kind, ns, name string) string {
	h := sha256.Sum256([]byte(ruleID + "|" + kind + "|" + ns + "|" + name))
	return "f-" + hex.EncodeToString(h[:])[:12]
}

// engineVersion stamps Provenance.Version on every finding. The plan
// referenced collect.Version, but internal/collect (merged in Task 3) exports
// no such constant and this task must not modify that package — so the
// version lives here until a shared build-version constant is introduced.
// engineVersion identifies the finding-producing engine, and internal/history's Gate 0 refuses to compare two
// readings that do not share it — because an absence explained by a rule we added is ours, not the customer's.
//
// IT WAS FROZEN AT 0.1.0 FROM THE FIRST RULES COMMIT UNTIL 2026-08-28 (B-105). Eleven rules shipped under it in
// two days, so the gate could not fire and a customer's next comparison would have reported our additions as
// their cluster's new problems. The gate was correct; its input was dead.
//
// It is no longer a thing to remember: pipeline.TestEngineVersion_MovesWhenTheFindingSetCan pins a digest of
// every rule AND analyzer identity, so adding, removing or renaming one fails the build until this moves.
// 0.3.0 (2026-08-28): RBACDangerousGrant added — Role and ClusterRole bodies are collected and the
// dangerous-grant family emits findings that did not exist in 0.2.0. Gate 0 must refuse to compare a 0.2.0
// reading with a 0.3.0 one, because every one of those findings would otherwise be reported as the
// customer's change. That is exactly the failure B-105 recorded: the version was frozen at 0.1.0 across
// eleven new rules and Gate 0 could never fire.
// 0.4.0 (2026-08-29): the B-5 resilience half — ZonePinnedVolume, ZoneLossFeasibility and
// NodeLossFeasibility. Three new finding families, so Gate 0 must refuse to compare a 0.3.0 reading with a
// 0.4.0 one or every one of them would be reported as the customer's change.
// 0.5.0 (2026-08-29): the reference-integrity family — three new finding families, so Gate 0 must refuse to
// compare a 0.4.0 reading with a 0.5.0 one or every one of them would be reported as the customer's change.
// 0.7.0 (2026-08-29): Sweep 4's two contradiction rules — AND B-138, which is the more important half of
// this bump. Fixing that ID changed the identity of every node-pinned-volume finding on a cluster where two
// pods share one pinned volume, so a 0.6.0 reading and a 0.7.0 one would show those as gone-and-arrived. A
// bug fix that changes finding IDs moves this version for the same reason adding a rule does.
// 0.23.0 (2026-10-21): the engine bench's first fixes — dangerous-grant stopped matching read-only grants as writes
// and `*` on unrelated resources as impersonation, escalation or webhook access; the zone/node-loss model and
// node-headroom stopped counting finished pods' requests as occupied room; dangerous-grant matches as the RBAC
// authorizer does and reports exec/attach; and the pod-security rules read every pod spec the cluster runs — bare
// Pods, Jobs and CronJobs too (pod_templates.go). Findings appear and disappear between 0.22.0 and 0.23.0 readings
// of an unchanged cluster, and Gate 0 must not report either as the customer's doing.
// 0.24.0 (2026-10-27, v0.1.1): ClusterAdminUserOrGroup — cluster-admin bound to a User or a Group is a finding — and
// binding-to-builtin-subject 1.1.0, which makes cluster-admin bound to system:authenticated, system:unauthenticated or
// system:anonymous critical. A 0.23.0 reading of an unchanged cluster can lack a finding a 0.24.0 one carries, or
// carry it at a lower severity, and Gate 0 must not report either as the customer's change.
//
// THE NUMBER ITSELF IS buildinfo.EngineVersion, so that a binary which cannot link this package — the MCP server,
// fenced away from the collector — prints the same ruleset in its version as `shoalcheck version` does. Bump it
// there; this history stays here.
const engineVersion = buildinfo.EngineVersion

// EngineVersion is the rule-engine version stamped on every finding, exported so a comparison between
// two audits can refuse to attribute a difference to the cluster when the engine itself changed
// between the readings.
func EngineVersion() string { return engineVersion }

// prices returns the run's provider, or the embedded snapshot when none was resolved.
func (o Options) prices() pricing.PriceProvider {
	if o.Prices != nil {
		return o.Prices
	}
	return pricing.Embedded()
}

// nodeMonthly adapts the provider's PricePoint to the (usd, ok) shape every rule reads: the ceiling is the
// on-demand list figure, and a spot pool gets the same number as an upper bound (see pricing.NodeMonthlyUSD).
func (o Options) nodeMonthly(provider, region, instanceType string, capacity types.CapacityType) (float64, bool) {
	pt, ok := o.prices().NodeMonthly(provider, region, instanceType, capacity)
	if !ok {
		return 0, false
	}
	return pt.Ceiling, true
}

func provenance() types.Provenance {
	return types.Provenance{Collector: "kubernetes", Version: engineVersion}
}

// TODO(founder): severity policy — this is a business-judgment call, not an
// engineering one. Today: missing requests = medium, missing probes = medium,
// single replica without PDB = high. Adjust the constants in each rule file
// (or extract a shared policy function here) when you calibrate against the
// first real clusters.
