package boundaries

// Package boundaries holds what a finding does NOT establish.
//
// WHY ITS OWN PACKAGE, AND IT IS NOT TIDINESS. The table is pure data keyed by rule id, so it could sit in
// internal/rules beside the rules it describes — and it did, for about an hour. But internal/rules imports
// internal/collect, which imports client-go, and cmd/shoalcheck-mcp's strongest claim is that it CANNOT reach a
// cluster: no kubeconfig, no client-go, asserted by a test over its import graph. Serving boundaries from the
// registry pulled all of it back in, and the fence went from provable to prose. A table of sentences has no
// business living behind a Kubernetes client.
//
// boundaries.go — WHAT A FINDING DOES NOT ESTABLISH.
//
// Every finding already carries what it rests on: `Basis` names the kinds read and the kinds refused, and the
// evidence quotes the fields. That is the first rung of the provenance ladder and it answers "why do you say
// this?". This file is the second rung and answers the question a careful reader asks next, which the product
// has never answered in a machine-readable form: "what does this NOT tell me?"
//
// IT IS THE FEATURE, NOT THE GUARD. The corpus — a thousand adjudicated findings — is why an agent or a
// reader gets value here. The boundaries are why anyone should trust what they do with it. A model handed a
// finding and no boundary will confidently extend it; handed the boundary in the same object, it can refuse.
// Filing this as a safety measure is what the original brief did and it is the wrong shape.
//
// TWO PRODUCERS, ONE FIELD.
//
//   FAMILY boundaries are properties of the rule, true on every cluster, and live in the table below. They are
//   grouped by CLAIM SHAPE rather than by package, which is why roughly a dozen blocks cover 85 rules.
//
//   CONDITIONAL boundaries are properties of THIS RUN and are the more valuable half, because they say what
//   this particular reading could not establish — "three of these pods matched no endpoint entry", "this
//   cluster carries only the beta zone label". A rule appends those itself at Evaluate time. They cannot live
//   in a static table and a table that pretended to hold them would be the weaker feature wearing the name of
//   the stronger one.
//
// WHERE THE TEXT CAME FROM. Most of it was already written, in the header comments of the rule files, where
// only a developer reading source could ever find it: node_drain.go states seven refusals in prose,
// feasibility.go argues the soundness of the negative and the unsoundness of the positive, rbac_grants.go
// explains why effective permissions are unreadable. Lifting them here is not a summary of those comments —
// each line below was checked against the rule it describes, and where the comment was broader than the code
// the code won.

// Family is one claim shape and the rules that share it.
type Family struct {
	// Name is for the developer reading this table and for the gate's failure message. It is not served.
	Name string
	// Rules are the rule IDs in this family. A rule may appear in more than one family; the lookup returns
	// the union, sorted, because two families each contributing a true sentence is the normal case and
	// picking one of them would be a choice nobody made deliberately.
	Rules []string
	// Lines are the boundaries themselves, in the product's own voice: each one states what the finding does
	// not establish, never what it does.
	Lines []string
}

// For returns every family boundary that applies to a rule, in DECLARATION ORDER and de-duplicated. An
// empty result is a defect, not a state: rules.TestEveryRuleCarriesABoundary fails on one.
//
// IT USED TO SORT THEM ALPHABETICALLY, and the reason was determinism — two readings of one cluster must
// produce the same bytes. That property is real and it was never the sort's to give: Families is a slice and
// each family's Lines is a slice, so this loop is already deterministic. What the sort DID do was throw away
// the order somebody wrote. Measured on stack.hpa.no-headroom in `shoalcheck explain`: the sentence saying what
// KIND of claim the finding is — "this is arithmetic on the numbers the object states about itself" — came
// third, behind two qualifications of a claim the reader had not yet been told the shape of.
//
// A rule in two families gets the first family's lines first. That is a choice, and it is the only one that
// does not need a second table to express: the order families appear in this file.
func For(ruleID string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range Families {
		for _, r := range f.Rules {
			if r != ruleID {
				continue
			}
			for _, l := range f.Lines {
				if !seen[l] {
					seen[l] = true
					out = append(out, l)
				}
			}
		}
	}
	return out
}

// NOT HERE YET: the per-rule interface and the conditional boundaries. A rule with a boundary of its own
// beyond its family's would implement an optional `ClaimBoundaries() []string`, the same shape as
// usageDependent in deps.go; a boundary about THIS RUN — "three of these pods matched no endpoint entry",
// "this cluster carries only the beta zone label" — is appended by the rule onto the finding at Evaluate
// time. Both need somewhere on the finding to live, which is `Finding.ClaimBoundaries`, and that is a
// forever-contract schema addition awaiting the founder's decision (Epic M spec §13.1). Declaring the
// interface before anything can consume it would be a dead symbol; the family table is useful on its own.

// Families is the table itself, exported so the gates in internal/rules can walk it against the registry.
var Families = []Family{
	// ── THE STACK ANALYZERS. SIXTEEN finding-producing rules in internal/analyzers carried NO boundary at
	// all: measured 2026-09-09, `For()` returned nothing for every one of them, and 21 of 2,176 findings
	// across the eight newest readings shipped with an empty ClaimBoundaries while the product's headline
	// claim is that every finding says what it does not establish. Only three of the sixteen fire on the
	// local testbed, which is why the gap was small enough to miss — on a cluster running Argo CD,
	// cert-manager, Flux, Gateway API, KEDA or Strimzi it is most of them.
	//
	// The scoping mistake is worth naming: TestEveryRuleCarriesABoundary walks rules.All(), and the
	// analyzers are not in that registry. A gate over one producer proves nothing about the other.
	//
	// AND THE COUNT MOVED TWICE WHILE THIS WAS BEING WRITTEN, both times because a scan named the shapes it
	// expected. Thirteen came from a grep for `RuleID: "stack.…"`. The fourteenth, stack.linkerd.opaque-port,
	// was found by the first version of the gate: its id is assigned through a named constant. The fifteenth
	// and sixteenth, both in hpa.go, were found by RUNNING A READING and counting empty boundaries — the gate
	// still could not see them, because that file passes its id as an argument to a helper. The gate now
	// collects every stack.* literal and subtracts the analyzer registration ids, which names no shape at
	// all, and it additionally refuses an id built by concatenation so that a literal scan stays complete.
	{
		Name: "a controller's own status condition",
		Rules: []string{
			"stack.argocd.degraded",
			"stack.argocd.outofsync",
			"stack.certmanager.not-issued",
			"stack.flux.not-ready",
			"stack.gateway.not-programmed",
			"stack.keda.not-ready",
			"stack.strimzi.not-ready",
		},
		Lines: []string{
			"This is the controller's own report about itself, read from the object's status. Nothing here independently verifies it: a controller that has stopped writing status, or is writing a stale one, produces exactly this reading.",
			"A snapshot cannot distinguish a resource that is mid-reconcile from one that is stuck. The condition says what it said at the moment of the read, and a controller reconciling normally passes through the same states.",
			"Nothing here is a claim about users or traffic. A degraded or not-ready resource is a statement about declared state, and whether anything depending on it was actually affected was not observed.",
			"The controller's own health was not examined. Whether it is running, has permission to act, or is failing for a reason of its own is outside what this reading looked at.",
		},
	},
	{
		Name:  "a date read from an object, not from the wire",
		Rules: []string{"stack.certmanager.expiring"},
		Lines: []string{
			"The date comes from the Certificate object's status, not from a certificate anybody presented. Nothing was connected to, so an endpoint serving a different or newer certificate than its object claims reads the same way here.",
			"Whether any client is affected was not observed. A certificate can be expired in an object and unused in practice, and this reading cannot tell those apart.",
		},
	},
	{
		Name: "a selector that matched nothing in this reading",
		Rules: []string{
			"stack.monitoring.podmonitor-selects-nothing",
			"stack.monitoring.servicemonitor-selects-nothing",
		},
		Lines: []string{
			"An empty selection at the instant of this reading is not a statement that the selector never matched. A target that was deleted, is starting, or carries its labels at a different moment produces the same emptiness.",
			"No scrape was attempted. That the selector matches nothing is read from labels, not from Prometheus, and whether the intended target exists under a different label was not searched for.",
		},
	},
	{
		Name: "a declaration read without the component that loaded it",
		Rules: []string{
			// stack.linkerd.opaque-port is here because the gate found it and the grep that wrote this
			// table did not: its rule id is assigned through a named constant rather than as a literal at
			// the RuleID site, so a scan for `RuleID: "stack.…"` missed it. Fourteenth of sixteen.
			"stack.istio.permissive-mtls",
			"stack.linkerd.opaque-port",
			"stack.monitoring.alert-route-receiver-missing",
			"stack.monitoring.prometheus-storage-ephemeral",
		},
		Lines: []string{
			"This is what the object declares, not what the running component loaded. A configuration changed after the process started, or overridden by something outside the object, reads the same way here.",
			"A half of the configuration that lives in a Secret was never read — Secret values are outside this tool's access by construction — so a receiver, a credential or a volume supplied that way is invisible to this finding rather than absent.",
			"No consequence is asserted. Nothing here says an alert failed to deliver, that history was lost, that any plaintext connection was actually made, or that a request lost a retry; each of those is an event, and this reading is of a declaration.",
			"Nothing here is a claim about encryption. A declaration that reduces what the mesh can see at a port is not a statement that traffic on it was unencrypted, and the two are read from different fields.",
		},
	},
	{
		// FIFTEENTH AND SIXTEENTH. Both were found by a live reading, not by the gate that was supposed to
		// find them: hpa.go passes its rule id as an argument to a per-analyzer helper, so a scan for
		// `RuleID: "stack.…"` saw nothing. The gate now names no shape at all.
		Name: "an autoscaler's declared range, not a scaling event",
		Rules: []string{
			"stack.hpa.no-headroom",
			"stack.hpa.pinned-at-max",
		},
		Lines: []string{
			"This is arithmetic on the numbers the HorizontalPodAutoscaler object states about itself. Nothing was observed scaling, or failing to scale; no scaling decision, event or history was read.",
			"A range with no room in it is not by itself a mistake. A workload that must run at a fixed count — a singleton, a leader-elected controller, a process licensed per instance — declares exactly this, and the reading cannot tell a deliberate ceiling from an oversight.",
			"Whether this object is where a change belongs was not established. Autoscaler bounds are commonly written by a chart, an overlay or a GitOps template, in which case an edit to the live object is reverted by whatever owns it.",
			"No load was measured. The reading carries no request rate and no resource pressure for the target, so whether the range is actually constraining anything was not observed.",
		},
	},
	{
		Name: "drain — the voluntary path only",
		Rules: []string{
			"k8s.reliability.node-drain-budget",
			"k8s.reliability.node-drain-unmanaged-pod",
			"k8s.reliability.node-pinned-volume",
			"k8s.reliability.pdb-blocks-drains",
			"k8s.reliability.rollout-needs-surge-capacity",
		},
		Lines: []string{
			"A PodDisruptionBudget gates voluntary eviction only. Node loss, force-deletion, `kubectl delete pod` and kubelet node-pressure eviction all bypass it, so this says nothing about what happens when a node dies.",
			"No duration is stated, and none can be. A floor derived from readiness probes inverts exactly where it is most dangerous — a workload with no probe would score fastest — and pod-recovery time is not service-downtime time.",
			"Nothing here is a claim about users or traffic. A pod matching a Service selector is not evidence it was in rotation, and a published endpoint is not a request.",
			"This is a statement about placement and mechanism, not a rating. There is no survival score, no single-point-of-failure verdict and no dollar figure, because the snapshot holds no traffic, revenue or SLA data.",
			"Whether the control plane would evict at all is unreadable: node-monitor-grace-period and DefaultTolerationSeconds are provider-set flags on a managed cluster, and taint-based eviction can be disabled outright.",
		},
	},
	{
		Name: "feasibility — a refusal is sound, a placement is not",
		Rules: []string{
			"k8s.reliability.node-loss-feasibility",
			"k8s.reliability.zone-loss-feasibility",
		},
		Lines: []string{
			"The model checks a SUBSET of the scheduler's predicates, which is what makes the negative sound: a model more permissive than the scheduler finding no fit means the scheduler finds none either. The positive does not follow and is never asserted — that no pod here is listed is not a claim that any pod would be placed.",
			"The scheduler's own configuration is unreadable on a managed cluster, admission injects containers into the pod that actually gets placed, and per-node volume-attach limits and max-pods are not read. Preemption is unmodelled.",
			"No cost follows from this. Not a node count, not a smaller configuration, not a figure — a pod having nowhere to go says nothing about what the cluster should be sized at.",
		},
	},
	{
		Name: "upgrade — we can see the cluster, not its clients",
		Rules: []string{
			"k8s.upgrade.deprecated-api-served",
			"k8s.upgrade.crd-conversion-webhook-unbacked",
			"k8s.upgrade.node-pool-cannot-roll",
		},
		Lines: []string{
			"This says what the cluster will stop SERVING, never what will break. When a version is removed the existing objects keep being served at the surviving version; what breaks is clients — YAML in a repository, a Helm chart, a controller's library, a CI pipeline — and none of those is inside a kubeconfig.",
			"No workload is named as being at risk, deliberately. The object is precisely the thing that survives a version removal, so naming one would assert the opposite of what is true.",
			"What is SERVED is not what is APPLIED. `last-applied-configuration` would be the obvious source for the latter and is refused: it is absent on every GitOps cluster, nothing updates it on a storage migration, and it holds the entire applied manifest.",
			"A group/version string is not a stable identity across releases — one API was removed in 1.22 and reintroduced in 1.28 — so the removal schedule is read as a dated dataset with a version and a stamp, not as a permanent fact.",
			"Silence from this family means these checks ran and found nothing. It is not a statement that the upgrade will succeed.",
		},
	},
	{
		Name: "cost, priced — a list price, not the bill",
		Rules: []string{
			"k8s.cost.commitment-candidate",
			"k8s.cost.ebs-gp2-where-gp3-is-cheaper",
			"k8s.cost.idle-loadbalancer",
			"k8s.cost.instance-generation-lag",
			"k8s.cost.overprovisioned-resources",
			"k8s.cost.unattached-volume",
		},
		Lines: []string{
			"The figure is computed from a dated public list price, not from your bill. No credential of yours was used and no invoice was read, so a negotiated rate, a private offer or a credit is invisible here.",
			"Whether a commitment already covers this footprint is a billing-account fact this product cannot see. A saving stated at the on-demand rate is wrong for the term of any plan that already applies.",
			"Identified is not realised. Nothing here has been reclaimed, and the arithmetic assumes the freed capacity is actually given up rather than absorbed elsewhere.",
		},
	},
	{
		Name:  "usage-derived — a measured window, with its own coverage",
		Rules: []string{"k8s.cost.overprovisioned-resources"},
		Lines: []string{
			"This rests on a measured window from a metrics source, so it is only as long as that source has been running: a young Prometheus reports a short window and the confidence says so. Without a usage source the rule emits nothing rather than guessing.",
			"Requests are compared against observed p95 with headroom, taking the busiest replica rather than the mean. It is a statement about reserved capacity, never about whether the workload is fast enough.",
		},
	},
	{
		Name: "cost, evidence-only — deliberately not banked",
		Rules: []string{
			"k8s.cost.node-headroom",
			"k8s.cost.kubernetes-version-past-standard-support",
		},
		Lines: []string{
			"The dollar impact is zero on purpose. This is a candidate to investigate with real utilisation, not a saving: requests-only slack cannot tell an idle pool from one whose pods under-request against what they actually use, and acting on the second packs a cluster into an OOM.",
		},
	},
	{
		Name: "reference integrity — a name that resolves to nothing",
		Rules: []string{
			"k8s.config.governing-service-unresolved", "k8s.config.hpa-target-unresolved",
			"k8s.config.ingress-backend-unresolved", "k8s.config.ingressclass-unresolved",
			"k8s.config.priorityclass-unresolved", "k8s.config.serviceaccount-unresolved",
			"k8s.config.storageclass-unresolved", "k8s.config.netpol-peer-selects-no-namespace",
			"k8s.config.node-selector-no-node-carries", "k8s.config.topology-key-no-node-carries",
			"k8s.config.pdb-selects-no-pods", "k8s.config.probe-port-not-declared",
			"k8s.config.service-targetport-undeclared", "k8s.rbac.binding-subject-unresolved",
			"k8s.rbac.roleref-unresolved",
		},
		Lines: []string{
			"The finding is that the reference resolves to nothing in this reading. It is not a prediction of what will happen: a pod created after the target went away behaves differently from one that has been running for a month on a token it already holds, and the snapshot cannot tell which it is looking at.",
			"This is an absence claim over the TARGET list, so it is made only when that list was actually read. A refused list produces silence here rather than a cluster that appears entirely broken.",
			"Kinds this product does not collect are excluded and counted, never reported as missing — an autoscaler may target an Argo Rollout or a KEDA ScaledObject, and calling those absent would fire on every cluster running one.",
		},
	},
	{
		// ONE RULE OF THE DANGLING FAMILY READS BINDINGS, and Kubernetes writes some for controllers a cluster
		// may never run. The exclusion is this rule's alone, so it is stated here and not in the family's lines.
		Name:  "a binding Kubernetes writes for itself",
		Rules: []string{"k8s.rbac.binding-subject-unresolved"},
		Lines: []string{
			"The bindings Kubernetes writes for itself are excluded: the label kubernetes.io/bootstrapping: rbac-defaults AND the exact upstream binding — name, role and subjects. Some name ServiceAccounts for cloud controllers a cluster never runs, so their absence is the distribution's. A labelled binding that is not the upstream one, or an unlabelled one, is reported.",
		},
	},
	{
		Name: "absence — configured is not enforced",
		Rules: []string{
			"k8s.namespace.no-network-policy", "k8s.namespace.pss-admission-not-enforced",
			"k8s.namespace.no-resource-governance", "k8s.namespace.default-namespace-in-use",
		},
		Lines: []string{
			"This reports what is not configured, which is not the same as what is not enforced. A CNI may carry segmentation in its own policy objects, which this product does not read, so the absence of an upstream NetworkPolicy is not the absence of isolation.",
			"An admission control governs what may be applied next. It says nothing about what is already running, which was admitted under whatever policy was in force at the time.",
		},
	},
	{
		Name: "observed — from metrics, where absent means not assessed",
		Rules: []string{
			"k8s.observed.alerts-firing", "k8s.observed.cpu-throttled", "k8s.observed.scrape-targets-down",
		},
		Lines: []string{
			"This is sourced from a metrics endpoint, so its absence is a third state — not assessed — distinct from clean. When no source was reachable the rule emits nothing rather than an all-clear.",
			"Throttling is a ratio of period counters over the measured window. It is not a count of seconds a container spent throttled, and it is not a statement that anything was slow.",
		},
	},
	{
		// SPLIT FROM ONE FAMILY OF FIFTEEN, because its middle line was false for five of them.
		//
		// "The count is per container and states its denominator" is a true and useful limit for a rule that
		// reads a container field. It is not true of a rule that reads spec.replicas, a rollout strategy, a
		// pod-level automount flag or a PodDisruptionBudget selector — those findings have no container
		// denominator to state, and their evidence names no container.
		//
		// MEASURED, not reasoned about: on a real 839-finding production reading, every one of the ten rules
		// below named a container in every finding's evidence (allow-privilege-escalation 64/64,
		// writable-root-filesystem 74/74, no-probes 52/52, …), and the five in the family after this one
		// named a container in ZERO of theirs — 138 findings in that one reading carrying a sentence about a
		// denominator they do not have. The two rules with no findings there (dangerous-capabilities,
		// image-digest-drift) build their evidence as "<container> <name> in <workload>" and "…, container
		// %q: …" respectively, which is why they are here.
		//
		// A boundary that is false for the finding it travels with is worse than no boundary: it is a claim
		// about a claim, in the one place this product says what it does not know.
		Name: "posture — a per-container fact with its denominator",
		Rules: []string{
			"k8s.workload.allow-privilege-escalation", "k8s.workload.capabilities-not-dropped",
			"k8s.workload.dangerous-capabilities", "k8s.workload.runs-as-root",
			"k8s.workload.seccomp-not-enforced", "k8s.workload.writable-root-filesystem",
			"k8s.workload.missing-resource-requests", "k8s.workload.mutable-image-tags",
			"k8s.workload.image-digest-drift", "k8s.workload.no-probes",
		},
		Lines: []string{
			"This is read from the workload's declared pod template, not from what is running. Admission may inject or mutate containers, so the pod the scheduler placed is not always the pod described here.",
			"The count is per container and states its denominator: a workload where some containers set a field and others do not says how many of how many, because a partial workload rendered as a whole one is the same defect as an absence rendered as a pass.",
			"A declared setting is not a demonstrated behaviour. Nothing here says a container attempted anything, only what its specification permits.",
		},
	},
	{
		// THE SAME READING, ONE LEVEL UP. These rules read the workload itself — replicas, a rollout
		// strategy, a pod-level flag, the PodDisruptionBudget that does or does not select its pods — so the
		// declared-not-running limit holds exactly as it does above and the per-container denominator does
		// not exist. The third line is worded for a workload rather than for a container for the same
		// reason: "nothing here says a container attempted anything" is a sentence about the wrong subject.
		Name: "posture — a workload-level declaration",
		Rules: []string{
			"k8s.workload.default-sa-token-automount", "k8s.workload.privileged-host-access",
			"k8s.workload.no-anti-affinity", "k8s.workload.risky-rollout-strategy",
			"k8s.workload.single-replica-no-pdb",
		},
		Lines: []string{
			"This is read from the workload's declared pod template, not from what is running. Admission may inject or mutate containers, so the pod the scheduler placed is not always the pod described here.",
			"A declared setting is not a demonstrated behaviour. Nothing here says this workload behaved in any particular way, only what its specification declares.",
		},
	},
	{
		// A REFERENCE IS NOT ITS TARGET, and this rule is the clearest case the registry has: it reports a
		// Secret reaching an environment WITHOUT reading one Secret. Every limit below follows from that.
		Name:  "a reference read without its target",
		Rules: []string{"k8s.workload.secret-in-env-var"},
		Lines: []string{
			"The Secret itself was not read. This is the reference in the pod template — a name and a key — so nothing here says what the value is, whether it is sensitive, or whether it is set at all. A Secret holding a feature flag reads exactly like one holding a database password.",
			"Nothing leaked, as far as this reading knows. It is a declaration in a specification, not an observation of a process, a log line or a request. No disclosure is claimed and none was looked for.",
			"Whether the Secret exists was not checked. A reference to an absent Secret produces a pod that will not start, which is a different finding this reading cannot make.",
			"A mounted file is not automatically safer. The control asks for a shape; a Secret mounted world-readable into a shared volume is worse than an environment variable, and the mode of any mount is outside what this finding examined.",
			"This is the workload's declared pod template, not what is running. Admission can inject containers and rewrite environments, so the pod the scheduler placed may differ from the one described here.",
		},
	},
	{
		// MEMBERSHIP OF A BUILT-IN SUBJECT IS NOT IN THE CLUSTER. This is the boundary CIS 5.1.7 is forced to
		// MANUAL for, quoted from internal/rules/compliance.go: only explicit RBAC bindings are observable.
		Name:  "a subject whose membership is decided outside the cluster",
		Rules: []string{"k8s.rbac.binding-to-builtin-subject"},
		Lines: []string{
			"An absence here is not an absence of the subject. Membership is decided outside the cluster — a client certificate's O=, an OIDC claim, a provider's IAM mapping, or for the unauthenticated identities the simple absence of a credential — so a reading with no such binding has not established that nobody holds it.",
			"Whether the grant is reachable was not established. Anonymous requests are accepted or refused by a control-plane flag a managed cluster does not expose, so a binding naming an unauthenticated subject may be live or may be unreachable, and this reading cannot tell those apart.",
			"Nothing here is a statement about the role's contents. This finding is about the subject a binding names; what the referenced role permits is a separate reading, and a harmless role bound to a dangerous subject is reported here exactly as a powerful one is — with one exception, matched by the role's name alone: the built-in ClusterRole cluster-admin bound to system:authenticated, system:unauthenticated or system:anonymous is critical at any scope.",
			"A permission is not a use. Nothing here says the grant was exercised; the snapshot carries no audit log and no request history.",
			"The bindings Kubernetes writes for itself are excluded: the label kubernetes.io/bootstrapping: rbac-defaults AND the exact binding the upstream bootstrap policy writes — its name, its role and its subjects, no more and no fewer. The label alone is not trusted, because anybody who can create a binding can set it; a labelled binding that is not the upstream one is reported like any other. A binding an installer created without that label is reported even where it is that installer's normal behaviour, because a rule that decided which installers to trust would be making a judgement this reading cannot support.",
		},
	},
	{
		// CLUSTER-ADMIN HELD BY AN IDENTITY THE CLUSTER DOES NOT STORE. Not in the "rbac — what a role permits"
		// family below: that family's first line is about reading a role's rules, and this rule reads none — it
		// matches the built-in role by its name, as the ServiceAccount rule does.
		Name:  "a grant to an identity the cluster does not store",
		Rules: []string{"k8s.rbac.cluster-admin-user-or-group"},
		Lines: []string{
			"Who holds the identity was not established. A User or a Group is not an object in the cluster: a client certificate, an identity provider's token or a cloud IAM mapping decides who it is, so this names the grant and cannot list the people or machines it reaches.",
			"This is one binding, not a total. What an identity can do is the union over every binding that names it or any group it belongs to, so a reading with no such binding has not established that nobody holds cluster-admin.",
			"A permission is not a use. Nothing here says the grant was exercised; the snapshot carries no audit log and no request history.",
			"The role is matched by its name: the built-in ClusterRole cluster-admin. A custom role granting every verb on every resource is reported by k8s.rbac.dangerous-grant, a ServiceAccount by k8s.rbac.cluster-admin-serviceaccount, and system:masters, system:anonymous, system:unauthenticated and system:authenticated by k8s.rbac.binding-to-builtin-subject — each is left to that rule rather than reported twice.",
			"The bindings a cluster's own software writes are excluded, each matched whole — name, role and every subject: the API server's (the label kubernetes.io/bootstrapping: rbac-defaults as well), and kubeadm's kubeadm:cluster-admins only where the reading shows kubeadm's control plane — a kube-apiserver pod in kube-system carrying kubeadm's annotation; elsewhere a binding of that shape is reported, saying so. Only these two are known to this build. No AKS, EKS or GKE reading has been captured to name a provider's own, so a provider-created admin binding is reported like any other, and a binding that reuses one of the two names with another subject is reported too.",
			"A RoleBinding inside a system namespace such as kube-system is reported whether or not the run includes system namespaces: cluster-admin there reaches every controller's ServiceAccount token in it.",
		},
	},
	{
		Name: "observed state — one instant, never a rate or a cause",
		Rules: []string{
			"k8s.reliability.pod-not-ready", "k8s.reliability.replicas-below-desired",
			"k8s.reliability.container-restart-total", "k8s.reliability.condition-unchanged",
			"k8s.reliability.pvc-pending", "k8s.reliability.pvc-below-request",
			"k8s.reliability.cronjob-no-recent-success", "k8s.reliability.daemonset-misscheduled",
			"k8s.reliability.unmanaged-pod", "k8s.reliability.rwo-volume-shared",
			"k8s.reliability.service-no-ready-endpoints", "k8s.reliability.service-endpoints-one-node",
			"k8s.reliability.single-control-plane", "k8s.reliability.node-placement-concentration",
			"k8s.reliability.node-version-skew", "k8s.reliability.hpa-pinned-at-max",
			// The analyzers' own rule of the same shape. It reads status.currentReplicas, so the instant
			// and no-cause lines below are true of it; stack.hpa.no-headroom is NOT here, because its two
			// arms read minReplicas and maxReplicas from the spec and never look at an observed count —
			// attaching an "instant" boundary to a finding that reads no instant would be a false one.
			"stack.hpa.pinned-at-max",
			"k8s.reliability.hpa-burst-exceeds-allocatable", "k8s.reliability.autoscaler-floor-below-budget",
			"k8s.reliability.rollout-does-not-self-roll", "k8s.reliability.zone-pinned-volume",
			"k8s.config.statefulset-partition-left-behind", "k8s.config.quota-below-committed",
			"k8s.config.rollout-contradicts-declared-minimum", "k8s.config.cronjob-no-starting-deadline",
			"k8s.config.duplicate-env-var", "k8s.config.external-traffic-policy",
			"k8s.config.job-no-ttl", "k8s.config.pod-covered-by-two-pdbs",
			"k8s.config.pod-selected-but-unpublished",
		},
		Lines: []string{
			"This is a state read at one instant. The snapshot has no time axis, so nothing here is a rate, a trend or a duration — a restart count is a total the kubelet reports, not a frequency.",
			"No cause is asserted. The reading records what the cluster says about itself; why it says it is outside what a read-only client can see.",
		},
	},
	{
		Name: "rbac — what a role permits, never what a subject can do",
		// binding-to-builtin-subject IS NOT HERE, and it was for one commit. This family's first line says
		// "this names one role's rules and the bindings that activate it" — that rule reads no role at all,
		// so the sentence was false on every finding it produced. Read on a live one before it was noticed.
		// The half that does apply — a permission is not a use — is repeated in its own family below.
		Rules: []string{
			"k8s.rbac.cluster-admin-serviceaccount",
			"k8s.rbac.dangerous-grant",
		},
		Lines: []string{
			"This names one role's rules and the bindings that activate it. It is not a total: a subject's effective permissions are the union over every binding that names it or any group it belongs to, and group membership is decided by the authenticator rather than by anything in the cluster.",
			"A permission is not a use. Nothing here says the grant was exercised; the snapshot carries no audit log and no request history.",
			"The bindings Kubernetes writes for itself are not counted as activating a role: the label kubernetes.io/bootstrapping: rbac-defaults AND the exact upstream binding — name, role and subjects. The label alone is not trusted. Two upstream bindings are counted anyway, because their roles may have been edited and the API server never removes a permission: one naming a broad group such as system:authenticated, and one whose role grants every verb on every resource and is not cluster-admin. A bootstrap role edited in any narrower way is not detected.",
		},
	},
}
