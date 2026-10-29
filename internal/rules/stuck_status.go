package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// stuck_status.go — WHAT THE OPERATOR ASKED FOR VERSUS WHAT THE CONTROLLER WROTE BACK.
//
// From Sweep 3 of the exhaustive-coverage epic (docs/qa/2026-08-29-sweep3-spec-vs-status.md), which found
// twelve unmined spec/status pairs and one census correction: "stuck conditions" came back COVERED from the
// Sweep 1 leaf probe and the code has exactly three uses of LastTransitionTime, none of them the general
// question. It is the clearest example in the epic of why a leaf match is weaker evidence than a chain.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DISCIPLINE THAT GOVERNS EVERY RULE HERE
//
//	STATUS IS CONTROLLER-OWNED AND MAY BE STALE. A finding built on it states the observation time. The
//	supportable sentence is "this condition has read X since T, and this reading was taken at T+n" — an
//	observation with both times named, never "it has been broken for n days". A condition's
//	lastTransitionTime says when the controller last CHANGED ITS MIND, not how long the underlying
//	situation has lasted, and a controller that stopped running leaves a stale timestamp that looks
//	exactly like a stable one. stuck_status_test.go enforces the phrase list mechanically.
//
//	A ZERO IS NOT A FALSE. B-125 is the precedent: nil from a guard is not a negative result. Here it
//	reappears twice — an ABSENT condition is unknown rather than unhealthy, and an unbound PVC's empty
//	status.capacity is unwritten rather than short. Both are adversarial cases in the test file.
//
//	ONE OWNER PER FACT. The polarity table below is deliberately INCOMPLETE. It omits the HPA's
//	ScalingLimited (silent_failures.go), the PDB's DisruptionAllowed (pdb_blocks_drains.go) and the
//	pod-level Ready gate rotation.go uses for settledness. A general rule that also read those would
//	state one problem twice at two severities, and a reader who sees that trusts neither.
//
//	NO DOLLARS. A controller's status field has no price.

// stuckAfter is how long a condition must have held its unhealthy reading before this family will say
// anything about it.
//
// SEVEN DAYS, AND THE NUMBER IS AN ARGUMENT RATHER THAN A TASTE. Everything ordinary that puts a condition
// into an unhealthy state resolves inside a day: a rollout, a node reboot, a disk filling and being
// cleaned up, a namespace deleting. A week is longer than all of them and it spans a full working week
// plus a weekend, so a condition that has held for seven days has survived at least one cycle of everyone
// who could have noticed it being at work. Below that threshold this family would be reporting operations
// in progress, which is B-131's defect: describing a cluster rather than reporting a problem.
const stuckAfter = 7 * 24 * time.Hour

// condPolarity is one row of the table: what this condition reads when things are FINE.
//
// KUBERNETES PUBLISHES NO MACHINE-READABLE POLARITY. Node.Ready is healthy at True and
// Node.MemoryPressure is healthy at False, and nothing in the API distinguishes them — so a rule that
// guessed would report every healthy node in the cluster. The table is therefore hand-written from the API
// contract and CLOSED: a condition type absent from it is skipped entirely, because "we do not know this
// condition's polarity" is a different statement from "this condition is fine". Custom controllers write
// conditions this product has never heard of, and none of them is judged here.
type condPolarity struct {
	healthy  corev1.ConditionStatus
	severity types.Severity
	// meaning is what the UNHEALTHY reading says, in the controller's own terms — never what it will cause.
	meaning string
}

var conditionPolarity = map[string]map[string]condPolarity{
	"Node": {
		string(corev1.NodeReady): {corev1.ConditionTrue, types.SeverityMedium,
			"the kubelet is not reporting this node as ready to the control plane"},
		string(corev1.NodeMemoryPressure): {corev1.ConditionFalse, types.SeverityMedium,
			"the kubelet has signalled that available memory on this node is below its eviction threshold"},
		string(corev1.NodeDiskPressure): {corev1.ConditionFalse, types.SeverityMedium,
			"the kubelet has signalled that free disk or inodes on this node are below its eviction threshold"},
		string(corev1.NodePIDPressure): {corev1.ConditionFalse, types.SeverityMedium,
			"the kubelet has signalled that available process IDs on this node are below its threshold"},
		string(corev1.NodeNetworkUnavailable): {corev1.ConditionFalse, types.SeverityMedium,
			"the network plugin has signalled that this node's network is not correctly configured"},
	},
	"Deployment": {
		string(appsv1.DeploymentAvailable): {corev1.ConditionTrue, types.SeverityMedium,
			"the deployment controller does not consider this Deployment to have minimum availability"},
		string(appsv1.DeploymentProgressing): {corev1.ConditionTrue, types.SeverityMedium,
			"the deployment controller is not recording progress on this Deployment's rollout"},
		string(appsv1.DeploymentReplicaFailure): {corev1.ConditionFalse, types.SeverityMedium,
			"the replica set controller recorded a failure creating or deleting pods for this Deployment"},
	},
	"Pod": {
		// PodScheduled is the row that justifies including pods at all: a Deployment with three of four
		// replicas placed still reports Available=True, so an unschedulable replica is invisible at the
		// workload level. It is also the difference between this family and the feasibility rules — those
		// answer a hypothetical, this one reports a pod that has actually been waiting for weeks.
		string(corev1.PodScheduled): {corev1.ConditionTrue, types.SeverityMedium,
			"the scheduler has not placed this pod on a node"},
		string(corev1.PodInitialized): {corev1.ConditionTrue, types.SeverityMedium,
			"this pod's init containers have not all completed"},
		string(corev1.PodReady): {corev1.ConditionTrue, types.SeverityMedium,
			"the kubelet does not consider this pod ready to serve"},
		string(corev1.ContainersReady): {corev1.ConditionTrue, types.SeverityLow,
			"the kubelet does not consider every container in this pod ready"},
		// DisruptionTarget is deliberately absent: it marks a pod the API server is in the middle of
		// evicting, which is an operation rather than a state.
	},
	"Namespace": {
		string(corev1.NamespaceDeletionContentFailure): {corev1.ConditionFalse, types.SeverityLow,
			"the namespace controller could not delete some content in this namespace"},
		string(corev1.NamespaceDeletionDiscoveryFailure): {corev1.ConditionFalse, types.SeverityLow,
			"the namespace controller could not discover which resources this namespace still holds"},
		string(corev1.NamespaceDeletionGVParsingFailure): {corev1.ConditionFalse, types.SeverityLow,
			"the namespace controller could not parse a group-version while deleting this namespace"},
		string(corev1.NamespaceContentRemaining): {corev1.ConditionFalse, types.SeverityLow,
			"the namespace controller reports objects still remaining in this deleting namespace"},
		string(corev1.NamespaceFinalizersRemaining): {corev1.ConditionFalse, types.SeverityLow,
			"the namespace controller reports finalizers still held on objects in this deleting namespace"},
	},
}

// seenCondition is one condition normalised out of the four differently-typed but identically-shaped
// structs Kubernetes uses (NodeCondition, DeploymentCondition, PodCondition, NamespaceCondition).
type seenCondition struct {
	kind, namespace, name string
	condType              string
	status                corev1.ConditionStatus
	reason, message       string
	transition            time.Time
	// groupKey collapses replicas of one workload into a single finding. Without it a Deployment whose
	// six pods are all unschedulable produces six findings for one problem.
	groupKey, groupLabel string
}

// ── Rule: a condition that has read the same unhealthy value for a long time ─────────────────────

// StuckCondition reports conditions that have held a non-healthy reading since before stuckAfter.
type StuckCondition struct{}

func (StuckCondition) ID() string { return "k8s.reliability.condition-unchanged" }

// Version 1.1.0 (2026-08-30): the reciprocal cross-reference to pod-not-ready. Evidence changed, so Gate 2
// withholds a comparison across it rather than reporting the extra line as a cluster change.
func (StuckCondition) Version() string { return "1.1.0" }

// RequiredKinds names every list the polarity table draws from. All four are load-bearing in the same
// direction — a denied list means the rule saw none of that kind's conditions and must say nothing about
// them — and `deployments` is additionally load-bearing for the pod half, because resolving a pod's owner
// up to its Deployment is what keeps six replicas from becoming six findings.
func (StuckCondition) RequiredKinds() []string {
	return sortedKinds([]string{"deployments", "namespaces", "nodes", "pods"})
}

func (r StuckCondition) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if inv == nil {
		return nil
	}
	reading := readingTime(inv)
	cutoff := reading.Add(-stuckAfter)

	var seen []seenCondition
	if observed(inv, "nodes") {
		for i := range inv.Nodes {
			n := &inv.Nodes[i]
			for _, c := range n.Status.Conditions {
				seen = append(seen, seenCondition{
					kind: "Node", name: n.Name, condType: string(c.Type), status: c.Status,
					reason: c.Reason, message: c.Message, transition: c.LastTransitionTime.Time,
					groupKey: "Node/" + n.Name, groupLabel: "Node " + n.Name,
				})
			}
		}
	}
	if observed(inv, "deployments") {
		for i := range inv.Deployments {
			d := &inv.Deployments[i]
			if !opts.IncludeSystem && isSystemNamespace(d.Namespace) {
				continue
			}
			// A DEPLOYMENT SCALED TO ZERO IS Available=False ON PURPOSE. This is the single largest false
			// positive available to this rule: every deliberately parked workload in the cluster carries an
			// old Available=False, and reporting them would fire on a state the operator chose.
			if d.Spec.Replicas != nil && *d.Spec.Replicas == 0 {
				continue
			}
			for _, c := range d.Status.Conditions {
				seen = append(seen, seenCondition{
					kind: "Deployment", namespace: d.Namespace, name: d.Name, condType: string(c.Type),
					status: c.Status, reason: c.Reason, message: c.Message,
					transition: c.LastTransitionTime.Time,
					groupKey:   "Deployment/" + d.Namespace + "/" + d.Name,
					groupLabel: fmt.Sprintf("Deployment %s/%s", d.Namespace, d.Name),
				})
			}
		}
	}
	if observed(inv, "pods") {
		owners := newOwnerIndex(inv) // one lookup per pod, not a walk of every Deployment per pod
		for i := range inv.Pods {
			p := &inv.Pods[i]
			if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
				continue
			}
			// A POD THAT HAS FINISHED IS Ready=False FOREVER, BY DESIGN. Every completed Job leaves one
			// behind, and a cluster that runs backups nightly accumulates them by the hundred.
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				continue
			}
			// A pod already being deleted is mid-operation, not stuck.
			if p.DeletionTimestamp != nil {
				continue
			}
			key, label := podGroup(owners, inv, p)
			for _, c := range p.Status.Conditions {
				seen = append(seen, seenCondition{
					kind: "Pod", namespace: p.Namespace, name: p.Name, condType: string(c.Type),
					status: c.Status, reason: c.Reason, message: c.Message,
					transition: c.LastTransitionTime.Time,
					groupKey:   key, groupLabel: label,
				})
			}
		}
	}
	if observed(inv, "namespaces") {
		for i := range inv.Namespaces {
			ns := &inv.Namespaces[i]
			if !opts.IncludeSystem && isSystemNamespace(ns.Name) {
				continue
			}
			for _, c := range ns.Status.Conditions {
				seen = append(seen, seenCondition{
					kind: "Namespace", name: ns.Name, condType: string(c.Type), status: c.Status,
					reason: c.Reason, message: c.Message, transition: c.LastTransitionTime.Time,
					groupKey: "Namespace/" + ns.Name, groupLabel: "Namespace " + ns.Name,
				})
			}
		}
	}

	// Group by (groupKey, condition type) so one problem across N replicas is one finding.
	type bucket struct {
		pol   condPolarity
		label string
		kind  string
		ns    string
		items []seenCondition
	}
	buckets := map[string]*bucket{}
	for _, c := range seen {
		byKind, ok := conditionPolarity[c.kind]
		if !ok {
			continue
		}
		pol, known := byKind[c.condType]
		if !known {
			// NOT OURS TO JUDGE. A condition type absent from the table has no polarity we can read.
			continue
		}
		if c.status == pol.healthy {
			continue
		}
		if c.transition.IsZero() {
			// A CONDITION WITH NO lastTransitionTime CANNOT BE AGED, and age is the whole claim.
			continue
		}
		if c.transition.After(cutoff) {
			continue
		}
		k := c.groupKey + "\x00" + c.condType
		b := buckets[k]
		if b == nil {
			b = &bucket{pol: pol, label: c.groupLabel, kind: c.kind, ns: c.namespace}
			buckets[k] = b
		}
		b.items = append(b.items, c)
	}

	var out []types.Finding
	for _, b := range buckets {
		sort.Slice(b.items, func(i, j int) bool { return b.items[i].name < b.items[j].name })
		first := b.items[0]
		// The OLDEST transition in the group is the one quoted: it is the earliest moment this reading
		// can be shown to have held, and any later one would understate what the cluster published.
		oldest := first.transition
		for _, it := range b.items {
			if it.transition.Before(oldest) {
				oldest = it.transition
			}
		}

		// B-141: THE SUBJECT MUST BE WHAT THE FIELD WAS READ FROM, NEVER ONLY WHAT IT WAS GROUPED UNDER.
		//
		// A pod group is LABELLED by its controller, and that controller can be anything — on a real AKS
		// cluster it was a CloudNativePG `Cluster`, a custom resource this product does not collect. The
		// first version wrote "Cluster linen/pgsql-linen has read Ready=False", which passed every
		// banned-phrase check and still told the reader we had read that resource's status. We had not,
		// and we cannot: it is outside RequiredKinds entirely.
		//
		// So the pod count is now ALWAYS in the sentence, singular included. The owner stays as context,
		// where it is genuinely useful, and stops being the subject.
		subject, verb := b.label, "has"
		if b.kind == "Pod" {
			if len(b.items) == 1 {
				subject, verb = fmt.Sprintf("1 pod of %s", b.label), "has"
			} else {
				subject, verb = fmt.Sprintf("%d pods of %s", len(b.items), b.label), "have"
			}
			// A bare pod is its own group, and "1 pod of Pod ns/name" is nonsense.
			if strings.HasPrefix(b.label, "Pod ") {
				subject, verb = b.label, "has"
			}
		}

		// THE FIELD SENTENCE NAMES THE OBJECT THE FIELD CAME FROM. For a pod group that is the pod, not
		// the owner it was grouped under — see B-141 above.
		readFrom := b.label
		if b.kind == "Pod" {
			readFrom = fmt.Sprintf("pod %s/%s", first.namespace, first.name)
			if len(b.items) > 1 {
				readFrom += fmt.Sprintf(" (and %d more under %s)", len(b.items)-1, b.label)
			}
		}
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s: status.conditions[%s].status = %q, and the healthy reading for this condition is %q",
				readFrom, first.condType, string(first.status), string(b.pol.healthy)),
			condTimeNote(oldest, reading),
		}
		if first.reason != "" || first.message != "" {
			evidence = append(evidence, fmt.Sprintf("controller reason=%s message=%s",
				emptyAs(first.reason, "(none)"), emptyAs(truncateMessage(first.message), "(none)")))
		}
		if len(b.items) > 1 {
			names := make([]string, 0, len(b.items))
			for _, it := range b.items {
				names = append(names, it.name)
			}
			evidence = append(evidence, fmt.Sprintf("%s in this group read the same way: %s", nWord(len(names), "object", "objects"), strings.Join(names, ", ")))
		}
		evidence = append(evidence, "lastTransitionTime records when the controller last CHANGED this "+
			"condition, not how long the situation behind it has lasted; a controller that stopped writing "+
			"leaves a timestamp that reads the same as a stable one")
		if b.kind == "Pod" {
			// THE RECIPROCAL CROSS-REFERENCE. k8s.reliability.pod-not-ready reports the same pods from the
			// other side of the time axis — what the kubelet is saying NOW, with its own word for it —
			// and a pod unready for more than seven days appears in both. Naming the other rule here is
			// what stops a reader counting one problem twice; the founder's kind-3 rule requires it, and
			// NodeDrainBudget/PDBBlocksDrains is the precedent.
			evidence = append(evidence, "a pod appearing here and in k8s.reliability.pod-not-ready is one "+
				"problem described twice: that rule states what the kubelet reports now, this one states "+
				"how long the condition has held")
		}

		refs := make([]types.ResourceRef, 0, len(b.items))
		for _, it := range b.items {
			refs = append(refs, types.ResourceRef{Kind: it.kind, Namespace: it.namespace, Name: it.name})
		}

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), b.kind, b.ns, b.label+"/"+first.condType),
			IDBasis:     &types.ResourceRef{Kind: b.kind, Namespace: b.ns, Name: b.label + "/" + first.condType},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s read %s=%s since %s",
				subject, verb, first.condType, string(first.status), stamp(oldest)),
			Description: fmt.Sprintf("The %s condition on %s has read %q since %s, and this reading was "+
				"taken at %s. In the controller's own terms, %s. Nothing in this reading says what has "+
				"happened in between: the timestamp records the last change, so an unattended condition and "+
				"a controller that stopped writing look the same from here.",
				first.condType, readFrom, string(first.status), stamp(oldest), stamp(reading), b.pol.meaning),
			WhyItMatters: "A condition that has held the same non-healthy reading for longer than any " +
				"ordinary operation takes is one the cluster has stopped resolving on its own. It is also the " +
				"kind of state that is easy to stop seeing: it was noticed once, it did not clear, and it " +
				"became part of the background.",
			Evidence:          evidence,
			Severity:          b.pol.severity,
			Category:          types.CategoryReliability,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortMedium,
			// The READING is exact; what is uncertain is whether the situation behind it is still live,
			// because a controller that stopped running leaves an identical timestamp.
			Confidence: 0.8,
			Provenance: provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// podGroup collapses a pod onto the workload that owns it, resolving a ReplicaSet up to its Deployment so
// the group is named the way an operator thinks of it. A pod with no controller is its own group.
//
// THROUGH THE OWNER INDEX, which the caller builds once: resolving a ReplicaSet walked every Deployment, once per
// pod, and four rules group every pod in the cluster this way.
func podGroup(owners *ownerIndex, inv *collect.Inventory, p *corev1.Pod) (key, label string) {
	ref := controllerRef(*p)
	if ref == nil {
		return "Pod/" + p.Namespace + "/" + p.Name, fmt.Sprintf("Pod %s/%s", p.Namespace, p.Name)
	}
	kind, name := ref.Kind, ref.Name
	// The `observed` check is not redundant with the loop below finding nothing. A denied list is an
	// empty list at runtime, so both paths reach the same answer today — but the rule DECLARES
	// `deployments` as a dependency, and a rule that would read a list it declared unread is one
	// collector change away from doing exactly that. The declaration and the read agree here on purpose.
	if kind == "ReplicaSet" && observed(inv, "deployments") {
		if d := owners.deploymentForReplicaSet(p.Namespace, name); d != nil {
			kind, name = "Deployment", d.Name
		}
	}
	return kind + "/" + p.Namespace + "/" + name, fmt.Sprintf("%s %s/%s", kind, p.Namespace, name)
}

// truncateMessage keeps a controller's message from dominating the evidence block. Controller messages are
// free text written by whatever wrote the condition, so they are bounded here rather than trusted.
func truncateMessage(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ── Rule: the DaemonSet controller wrote down that pods are running where they should not be ─────

// DaemonSetMisscheduled reports a non-zero status.numberMisscheduled.
//
// THIS IS §3'S OBLIQUE PATTERN IN ITS PUREST FORM. Working out which pods are on nodes their DaemonSet no
// longer selects would mean re-running the controller's own matching against every node — instead the
// controller published the count itself, and reading it is a fact where the re-derivation would be an
// inference. It is also the one place in this file where the zero value is safe: >0 is something the
// controller ASSERTED, so only the positive is claimed and a zero is left silent.
type DaemonSetMisscheduled struct{}

func (DaemonSetMisscheduled) ID() string      { return "k8s.reliability.daemonset-misscheduled" }
func (DaemonSetMisscheduled) Version() string { return "1.0.0" }

func (DaemonSetMisscheduled) RequiredKinds() []string { return sortedKinds([]string{"daemonsets"}) }

func (r DaemonSetMisscheduled) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "daemonsets") {
		return nil
	}
	var out []types.Finding
	for i := range inv.DaemonSets {
		ds := &inv.DaemonSets[i]
		if !opts.IncludeSystem && isSystemNamespace(ds.Namespace) {
			continue
		}
		n := ds.Status.NumberMisscheduled
		if n <= 0 {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "DaemonSet", ds.Namespace, ds.Name),
			IDBasis:     &types.ResourceRef{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("DaemonSet %s/%s reports %s running on nodes it does not select",
				ds.Namespace, ds.Name, nWord(int(n), "pod", "pods")),
			Description: fmt.Sprintf("The DaemonSet controller wrote status.numberMisscheduled = %d for "+
				"%s/%s, which is its own count of pods it is running on nodes that no longer match the "+
				"DaemonSet's node selector, affinity or tolerations. The controller does not remove these "+
				"on its own in every case, and this reading does not say which nodes they are on.",
				n, ds.Namespace, ds.Name),
			WhyItMatters: "A DaemonSet's whole contract is one pod per selected node. A non-zero " +
				"misscheduled count is the controller reporting that its actual placement and its own " +
				"selection rules disagree — usually after a node label changed underneath it.",
			Evidence: []string{
				snapshotNote(inv),
				fmt.Sprintf("DaemonSet %s/%s: status.numberMisscheduled = %d, status.desiredNumberScheduled = %d, "+
					"status.numberReady = %d", ds.Namespace, ds.Name, n,
					ds.Status.DesiredNumberScheduled, ds.Status.NumberReady),
				fmt.Sprintf("spec.template.spec.nodeSelector = %s",
					emptyAs(labelsAsText(ds.Spec.Template.Spec.NodeSelector), "(none)")),
				"the count is the controller's own; this reading did not re-derive it from the node list",
			},
			Severity:          types.SeverityLow,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── Rule: a bound claim holds less than it asked for ─────────────────────────────────────────────

// VolumeExpansionIncomplete reports Bound PVCs whose status.capacity is below spec.resources.requests.
//
// THE ADVERSARIAL CASE IS THE UNBOUND CLAIM. A Pending PVC has no status.capacity at all, and reading that
// empty ResourceList as "zero bytes, so it fell short" would report every claim waiting on a provisioner —
// which on a WaitForFirstConsumer StorageClass is every claim whose pod has not been scheduled yet. The
// phase check is what makes the comparison meaningful: only a Bound claim has a capacity its controller
// actually wrote.
type VolumeExpansionIncomplete struct{}

func (VolumeExpansionIncomplete) ID() string      { return "k8s.reliability.pvc-below-request" }
func (VolumeExpansionIncomplete) Version() string { return "1.0.0" }

func (VolumeExpansionIncomplete) RequiredKinds() []string {
	return sortedKinds([]string{"persistentvolumeclaims"})
}

func (r VolumeExpansionIncomplete) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "persistentvolumeclaims") {
		return nil
	}
	var out []types.Finding
	for i := range inv.PVCs {
		pvc := &inv.PVCs[i]
		if !opts.IncludeSystem && isSystemNamespace(pvc.Namespace) {
			continue
		}
		if pvc.Status.Phase != corev1.ClaimBound {
			continue
		}
		want, hasWant := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
		if !hasWant {
			// No request means nothing to compare against — a claim can be sized entirely by its class.
			continue
		}
		got, hasGot := pvc.Status.Capacity[corev1.ResourceStorage]
		if !hasGot {
			// Bound with no capacity written is a controller that has not caught up, not a shortfall.
			continue
		}
		if got.Cmp(want) >= 0 {
			// A provisioner that rounded UP gave more than was asked for, which is the common case on
			// block storage with a minimum allocation unit.
			continue
		}

		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("PVC %s/%s: spec.resources.requests.storage = %s, status.capacity.storage = %s",
				pvc.Namespace, pvc.Name, want.String(), got.String()),
			fmt.Sprintf("status.phase = %s, so the capacity above is a value the volume's controller wrote",
				string(pvc.Status.Phase)),
		}
		for _, c := range pvc.Status.Conditions {
			if c.Type == corev1.PersistentVolumeClaimResizing || c.Type == corev1.PersistentVolumeClaimFileSystemResizePending {
				evidence = append(evidence, fmt.Sprintf("status.conditions[%s] = %s; %s",
					string(c.Type), string(c.Status), condTimeNote(c.LastTransitionTime.Time, readingTime(inv))))
			}
		}
		evidence = append(evidence, "whether the expansion is still progressing is not readable from this "+
			"reading; the two numbers disagreeing is what it shows")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolumeClaim", pvc.Namespace, pvc.Name),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("PVC %s/%s holds %s and asks for %s",
				pvc.Namespace, pvc.Name, got.String(), want.String()),
			Description: fmt.Sprintf("PersistentVolumeClaim %s/%s is Bound with status.capacity = %s while "+
				"spec.resources.requests.storage asks for %s. A bound claim's capacity is written by its "+
				"controller, so the two values are a request the storage layer has not matched — most often "+
				"an expansion that was accepted and did not finish, and sometimes a StorageClass with "+
				"allowVolumeExpansion unset.",
				pvc.Namespace, pvc.Name, got.String(), want.String()),
			WhyItMatters: "Editing a PVC's request is how a volume is grown, and the edit is accepted " +
				"whether or not anything acts on it. The claim then reads as the larger size in every " +
				"manifest while the volume behind it stays the smaller one.",
			Evidence: evidence,
			Severity: types.SeverityMedium,
			Category: types.CategoryReliability,
			AffectedResources: []types.ResourceRef{
				{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}},
			EstimatedEffort: types.EffortMedium,
			Confidence:      1.0,
			Provenance:      provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
