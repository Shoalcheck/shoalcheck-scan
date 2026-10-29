package rules

import "github.com/Shoalcheck/shoalcheck-scan/internal/types"

// pillars.go — which of the product's two headline claims each rule's findings belong to.
//
// WHY THE DECLARATION LIVES HERE AND NOT IN THE RENDERER. scripts/depcheck.sh rule 1 forbids
// internal/report from importing internal/rules — "the renderer consumes an assembled report, it does not
// assemble one" — so a template cannot ask a rule anything. The alternative, a rule-ID-to-pillar map inside
// internal/report, would be a hand-maintained copy of this registry living in the renderer, and that is the
// defect class this project has found four times in two days: the duplicated browser-gate selector list, five
// spellings of "cr:", two private banned-word lists in app-check.mjs, and three hand-maintained control
// tables. So the pillar follows the path Basis, PriceBasis and Requests already took: declared here,
// serialised onto internal/types, populated in internal/pipeline.
//
// THE ASSIGNMENT TEST IS "status, NOT spec". A Ground Truth finding rests on what a controller published; a
// Change Preflight finding is arithmetic about an operation that has not happened yet. A rule is assigned by
// WHAT ITS CLAIM IS, never by what its claim could imply — see the two abstentions below, which are the
// interesting entries in this table.
var pillarByRule = map[string]types.Pillar{
	// ── Change Preflight: what will stop you when you try to change this cluster ──────────────
	// The drain family. Voluntary eviction is a future operation and these are its arithmetic.
	"k8s.reliability.node-drain-budget":            types.PillarChangePreflight,
	"k8s.reliability.node-drain-unmanaged-pod":     types.PillarChangePreflight,
	"k8s.reliability.node-placement-concentration": types.PillarChangePreflight,
	"k8s.reliability.node-pinned-volume":           types.PillarChangePreflight,
	// Change Preflight, like the rest of the drain family: each answers "what will stop your next change",
	// where the change is losing a node or a zone. Not Ground Truth — the constraint was always there and the
	// operator declared it; what is new is the arithmetic over it.
	"k8s.reliability.zone-pinned-volume":    types.PillarChangePreflight,
	"k8s.reliability.zone-loss-feasibility": types.PillarChangePreflight,
	"k8s.reliability.node-loss-feasibility": types.PillarChangePreflight,
	"k8s.reliability.pdb-blocks-drains":     types.PillarChangePreflight,
	// The rollout family.
	"k8s.reliability.rollout-does-not-self-roll":      types.PillarChangePreflight,
	"k8s.reliability.rollout-needs-surge-capacity":    types.PillarChangePreflight,
	"k8s.config.rollout-contradicts-declared-minimum": types.PillarChangePreflight,
	"k8s.config.statefulset-partition-left-behind":    types.PillarChangePreflight,
	// And the older rule that fires on Deployment Recreate alongside rollout-does-not-self-roll. Same
	// pillar ON PURPOSE: the collision this session declared rather than hid now appears in ONE place,
	// side by side, which is the first time it can be seen without reading Go. Not a fix — suppressing
	// either changes an existing claim and needs sign-off.
	"k8s.workload.risky-rollout-strategy": types.PillarChangePreflight,

	// ── Ground Truth: what is true right now that no dashboard shows you ─────────────────────
	// Every one of these rests on a controller's published status.
	"k8s.reliability.service-no-ready-endpoints": types.PillarGroundTruth, // EndpointSlice ready conditions
	"k8s.reliability.service-endpoints-one-node": types.PillarGroundTruth, // published endpoint node names
	"k8s.config.pod-selected-but-unpublished":    types.PillarGroundTruth, // slice membership vs selector
	"k8s.reliability.hpa-pinned-at-max":          types.PillarGroundTruth, // status.currentReplicas + condition
	"k8s.reliability.pvc-pending":                types.PillarGroundTruth, // status.phase
	"k8s.reliability.cronjob-no-recent-success":  types.PillarGroundTruth, // status.lastSuccessfulTime
	"k8s.config.ingress-backend-unresolved":      types.PillarGroundTruth, // backend Service + published endpoints
	// Two of the five self-contradiction rules, and only two. Both rest on a number a controller
	// published: the disruption controller's expectedPods, and the quota controller's used/hard.
	"k8s.config.pdb-selects-no-pods":   types.PillarGroundTruth, // status.expectedPods
	"k8s.config.quota-below-committed": types.PillarGroundTruth, // status.used vs status.hard
	// Sweep 3's spec-versus-status family. Ground Truth is not a close call for any of the three: the
	// assignment test on this table is "status, NOT spec", and status is the only thing they read.
	// numberMisscheduled is the purest of them — the controller published its own count of pods it is
	// running on nodes it no longer selects, and re-deriving that would mean re-running its matching
	// against every node.
	"k8s.reliability.condition-unchanged": types.PillarGroundTruth, // status.conditions + lastTransitionTime
	// Same pillar as the rule it sits beside, and for the pillar's own reason: it reads what a KUBELET
	// published about a pod it is running, which is the definition of Ground Truth here.
	"k8s.reliability.pod-not-ready":          types.PillarGroundTruth, // status.conditions + containerStatuses
	"k8s.reliability.daemonset-misscheduled": types.PillarGroundTruth, // status.numberMisscheduled
	"k8s.reliability.pvc-below-request":      types.PillarGroundTruth, // status.capacity vs spec.requests
	// SWEEP 4 SPLITS ACROSS TWO PILLARS, and the split is this table's own test working rather than a
	// judgement call. autoscaler-floor-below-budget's TITLE says "may scale X to 2 while PDB requires 3"
	// and its description is explicitly about the floor rather than about now — it makes the future claim,
	// so it takes the pillar that asks the future question. rwo-volume-shared's title and description are
	// present-tense declarations, and only its WhyItMatters mentions a drain; by the same rule that keeps
	// single-replica-no-pdb and the three self-contradiction rules out of Change Preflight, it abstains.
	// The assignment follows the wording; rewording first, with sign-off, then the pillar follows.
	"k8s.reliability.autoscaler-floor-below-budget": types.PillarChangePreflight,
	// The two oblique routes, and both are Ground Truth without argument: each reads something a KUBELET
	// published about itself. image-digest-drift reads the digest the kubelet recorded pulling, which is
	// the one place in the cluster where a moved tag is visible at all; node-version-skew reads
	// Node.status.nodeInfo, which every kubelet writes and nothing else reports.
	"k8s.workload.image-digest-drift":   types.PillarGroundTruth, // status.containerStatuses[].imageID
	"k8s.reliability.node-version-skew": types.PillarGroundTruth, // status.nodeInfo.kubeletVersion

	// ── Neither, and each is a decision ──────────────────────────────────────────────────────
	//
	// THE TWO ABSTENTIONS THAT MATTER. single-replica-no-pdb and no-anti-affinity are about availability
	// under disruption, and a drain of the wrong node is exactly what they bear on — so they LOOK like
	// Change Preflight. They are not assigned there because their claims are present-tense spec facts
	// ("spec.replicas = 1 and no PodDisruptionBudget selects these labels"), and the assignment would only
	// be honest if the wording made a claim about a future operation. Rewording an existing claim needs
	// founder approval, so the assignment follows the wording rather than leading it.
	"k8s.workload.single-replica-no-pdb": types.PillarNone,
	"k8s.workload.no-anti-affinity":      types.PillarNone,

	// THE OTHER THREE SELF-CONTRADICTION RULES, AND THE ABSTENTION IS THE SAME ARGUMENT AS ABOVE.
	// These three read spec on both sides — a declared topology key, a declared node label, a
	// declared namespace selector — against a label or namespace set. They look like Change
	// Preflight, because a placement requirement nothing satisfies is obviously something that
	// bears on the next rollout. They are not assigned there because their wording deliberately
	// makes NO claim about a future operation: self_contradiction.go bans "will not schedule" and
	// "cannot be scheduled" outright, and the pillar's own section heading asks "what will stop you
	// when you try to change this cluster?". Assigning them would put that question over cards that
	// decline to answer it. Rewording first, with sign-off, then the pillar follows.
	"k8s.config.topology-key-no-node-carries":     types.PillarNone,
	"k8s.config.node-selector-no-node-carries":    types.PillarNone,
	"k8s.config.netpol-peer-selects-no-namespace": types.PillarNone,
	// Reference integrity. NOT Ground Truth, and the distinction is the pillar's own: Ground Truth is what a
	// CONTROLLER published that no dashboard shows — status.expectedPods, disruptionsAllowed. A dangling
	// reference is two things the operator wrote that disagree, and nothing published it. NOT Change
	// Preflight either: the contradiction is already true, not waiting for the next change to reveal it.
	"k8s.config.serviceaccount-unresolved": types.PillarNone,
	"k8s.rbac.roleref-unresolved":          types.PillarNone,
	"k8s.config.hpa-target-unresolved":     types.PillarNone,
	// Phase 1's class references, same reasoning: a name that resolves to nothing is two things the
	// OPERATOR wrote that disagree, and no controller published it. Not Ground Truth, and not Change
	// Preflight either — the contradiction is already true rather than waiting for the next change.
	"k8s.config.storageclass-unresolved":      types.PillarNone,
	"k8s.config.ingressclass-unresolved":      types.PillarNone,
	"k8s.config.priorityclass-unresolved":     types.PillarNone,
	"k8s.config.governing-service-unresolved": types.PillarNone,
	// And rwo-volume-shared, for the reason recorded beside its Change Preflight sibling above.
	"k8s.reliability.rwo-volume-shared": types.PillarNone,
	// Declaration validity. Present-tense spec facts about one object, and every scanner that parses a
	// manifest can see them — which is exactly what Ground Truth is NOT.
	"k8s.config.probe-port-not-declared":       types.PillarNone,
	"k8s.config.duplicate-env-var":             types.PillarNone,
	"k8s.config.service-targetport-undeclared": types.PillarNone,
	// Structure and ownership. single-control-plane and pod-covered-by-two-pdbs are present-tense facts
	// about declarations; unmanaged-pod reads an ownerReference, which is written by a controller but is
	// not a STATUS — the pillar's test is "status, not spec", and an ownerReference is metadata.
	"k8s.reliability.single-control-plane": types.PillarNone,
	"k8s.reliability.unmanaged-pod":        types.PillarNone,
	"k8s.config.pod-covered-by-two-pdbs":   types.PillarNone,
	// Phase 1's last rows. Two read STATUS a controller published and take Ground Truth; four read spec
	// and abstain, by the table's own test.
	"k8s.reliability.replicas-below-desired":  types.PillarGroundTruth, // status.readyReplicas + observedGeneration
	"k8s.reliability.container-restart-total": types.PillarGroundTruth, // status.containerStatuses[].restartCount
	"k8s.config.external-traffic-policy":      types.PillarNone,
	"k8s.config.cronjob-no-starting-deadline": types.PillarNone,
	"k8s.rbac.binding-subject-unresolved":     types.PillarNone,
	"k8s.config.job-no-ttl":                   types.PillarNone,
	// The burst arithmetic reads spec ceilings against node allocatable — no controller published the
	// sum, and nothing has happened yet. It is the Change Preflight question asked of a change the
	// AUTOSCALER makes rather than the operator.
	"k8s.reliability.hpa-burst-exceeds-allocatable": types.PillarChangePreflight,

	// ── Upgrade Preflight, and the family SPLITS ACROSS BOTH PILLARS ──────────────────────────
	//
	// The temptation is to assign an epic, and the test forbids it: a rule is assigned by what its claim IS,
	// never by the epic that produced it or by what the claim could imply.
	//
	// `deprecated-api-served` is arithmetic about an operation that has not happened — a version this cluster
	// serves against a release that removes it — so it is Change Preflight, and the epic's name is a
	// coincidence rather than the reason.
	"k8s.upgrade.deprecated-api-served": types.PillarChangePreflight,
	// `node-pool-cannot-roll` composes Change Preflight findings into a Change Preflight claim.
	"k8s.upgrade.node-pool-cannot-roll": types.PillarChangePreflight,
	// `crd-conversion-webhook-unbacked` is GROUND TRUTH and this is the interesting entry in the family. Its
	// WhyItMatters explains that what usually needs a conversion webhook is a version change — but the
	// finding does not claim anything about an upgrade. It says the EndpointSlice controller has published no
	// ready address for this Service, which is true of the cluster as it stands and would be true if nobody
	// ever upgraded anything. Assigning it Change Preflight would let an implication in the prose decide the
	// pillar, which is the assignment leading the wording instead of following it.
	"k8s.upgrade.crd-conversion-webhook-unbacked": types.PillarGroundTruth,

	// ── The temporal axis abstains, and the pillar's own wording is why ───────────────────────
	//
	// Ground Truth is the tempting assignment and it is wrong twice over. The section above states its
	// test in one line — "every one of these rests on a CONTROLLER'S PUBLISHED STATUS" — and these three
	// rest on a metrics source, not on any object's status field. There is no status.throttled.
	//
	// The second reason is sharper and it is the pillar's other half: "what no dashboard shows you". These
	// signals come OUT OF the customer's dashboard data source, by definition. The engine-ceiling spec
	// §6b.2 defends building them on a narrower argument — we do not show them the metric, we show them
	// the question having been asked, because nobody has a panel per container for CFS throttling — and
	// that argument justifies the rule without justifying the pillar's sentence. Assigning them would let
	// a defence of the build become a claim in the document.
	//
	// Change Preflight is not it either: nothing here is arithmetic about an operation that has not
	// happened. These are observations of the last seven days.
	"k8s.observed.alerts-firing":       types.PillarNone,
	"k8s.observed.cpu-throttled":       types.PillarNone,
	"k8s.observed.scrape-targets-down": types.PillarNone,

	// Posture: present-tense spec facts, and not "what no dashboard shows you" — every admission
	// controller and every scanner shows a missing runAsNonRoot.
	"k8s.workload.runs-as-root":               types.PillarNone,
	"k8s.workload.allow-privilege-escalation": types.PillarNone,
	"k8s.workload.capabilities-not-dropped":   types.PillarNone,
	"k8s.workload.dangerous-capabilities":     types.PillarNone,
	"k8s.workload.privileged-host-access":     types.PillarNone,
	"k8s.workload.seccomp-not-enforced":       types.PillarNone,
	"k8s.workload.writable-root-filesystem":   types.PillarNone,
	// A reference in a pod template, not a ground truth about the cluster and not a change-preflight
	// question: it abstains, the way every other workload-hygiene rule here does.
	"k8s.workload.secret-in-env-var": types.PillarNone,
	// A binding read verbatim. Real, and not one of the three claims the document leads with.
	"k8s.rbac.binding-to-builtin-subject":     types.PillarNone,
	"k8s.workload.default-sa-token-automount": types.PillarNone,
	"k8s.workload.mutable-image-tags":         types.PillarNone,
	"k8s.workload.no-probes":                  types.PillarNone,
	"k8s.workload.missing-resource-requests":  types.PillarNone,
	"k8s.rbac.cluster-admin-serviceaccount":   types.PillarNone,
	"k8s.rbac.cluster-admin-user-or-group":    types.PillarNone,
	// A grant is a standing fact about the cluster, not something a change is about to break and not
	// something a reading establishes for the first time. Neither pillar's question is the one it answers.
	"k8s.rbac.dangerous-grant":                 types.PillarNone,
	"k8s.namespace.no-network-policy":          types.PillarNone,
	"k8s.namespace.no-resource-governance":     types.PillarNone,
	"k8s.namespace.pss-admission-not-enforced": types.PillarNone,
	"k8s.namespace.default-namespace-in-use":   types.PillarNone,

	// Cost is money, which is neither tense. It has its own section and its own reconciliation.
	"k8s.cost.idle-loadbalancer": types.PillarNone,
	"k8s.cost.unattached-volume": types.PillarNone,
	// A rate difference on storage that is not going anywhere: neither what is happening now
	// (ground truth) nor what a proposed change would do (preflight).
	"k8s.cost.ebs-gp2-where-gp3-is-cheaper": types.PillarNone,
	// A billing state the cluster is in right now. Not what is happening inside it (ground truth) and
	// not what a change would do (preflight) — the version simply crossed a date.
	"k8s.cost.kubernetes-version-past-standard-support": types.PillarNone,
	"k8s.cost.instance-generation-lag":                  types.PillarNone, // two list prices, no time axis
	"k8s.cost.commitment-candidate":                     types.PillarNone, // a published rate against a list price; no time axis
	"k8s.cost.node-headroom":                            types.PillarNone,
	"k8s.cost.overprovisioned-resources":                types.PillarNone,
}

// PillarByRule maps rule ID to pillar. Built from the table above rather than from a method on each rule so
// the whole assignment can be read in one screen — the point of the two pillars is the shape of the SET, and a
// property spread across thirty files cannot be reviewed.
//
// A rule with no entry is a build failure, not a PillarNone: see TestEveryRuleDeclaresAPillar.
func PillarByRule() map[string]types.Pillar {
	out := make(map[string]types.Pillar, len(pillarByRule))
	for k, v := range pillarByRule {
		out[k] = v
	}
	return out
}
