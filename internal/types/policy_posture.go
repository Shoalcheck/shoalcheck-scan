package types

// policy_posture.go — THE POLICY SHAPE OF A CLUSTER, as a first-class part of the artifact.
//
// Spec: `docs/superpowers/specs/2026-08-28-fleet-divergence-design.md` §2.3, which found that fleet
// divergence was blocked not on a comparison engine but on the report carrying nothing to compare. Every row
// of the intended compare column — namespace PSS labels, NetworkPolicy presence, quota presence, which
// operators are installed, admission posture — was read by the collector, consumed by a rule, and then
// discarded. `assembleFleet` keeps only the reports; the Inventory goes out of scope when Run returns.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY A PROJECTION AND NOT A DIFF OF FINDINGS
//
// "Cluster B has no `no-network-policy` finding for namespace `payments`" has at least four causes: the
// namespace does not exist there · it has a NetworkPolicy · the NetworkPolicy list was DENIED · no workload
// in it triggered the rule. Reporting that as a policy difference is the absence-versus-denial defect
// relocated one cluster sideways. So the shape is recorded directly, with its readability beside it, and
// nothing downstream has to infer a declaration from the silence of a rule.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS TYPE STRUCTURALLY CANNOT CARRY, AND THAT IS THE DESIGN
//
// NO SCALE. No replica counts, node counts, instance types, request values or pod counts. Two clusters are
// EXPECTED to differ on all of them — staging is smaller than production and that is not a finding — and a
// surface that could render them would bury the signal in noise. The exclusion is structural rather than a
// convention: the fields do not exist, so the divergence surface cannot show them even by mistake.
//
// NO COST. Two clusters in two regions price differently for reasons that are not policy.
//
// NO VERDICT. Nothing here is "correct" or "expected". A PSS label is recorded as the string the namespace
// carries; whether that string is the right one for that namespace is not a question this type answers.
//
// A field's ZERO VALUE IS NEVER A FACT. Every dimension pairs its value with a Read flag, because "this
// namespace has no NetworkPolicy" and "we were not allowed to list NetworkPolicies" are opposite conclusions
// that produce the identical empty value. This is the same discipline as collect.Observed, carried into the
// schema so a consumer cannot lose it.

// PolicyPosture is the readable policy shape of one cluster. Additive to AuditReport and omitempty, so a
// report written before this shipped stays valid v1.
type PolicyPosture struct {
	// Namespaces is one entry per namespace this reading saw, sorted by name.
	Namespaces []NamespacePosture `json:"namespaces,omitempty"`

	// Operators names the operator API groups discovery reported as served, sorted. It is the projection of
	// collect.Inventory.PresentGVRs, which never reached the report before: Architecture.Stack is prose
	// (Layer/Name/Note) written for a human, and comparing prose across clusters is not comparing anything.
	//
	// Group only, NEVER the version. A cluster serving cert-manager.io/v1 and one serving cert-manager.io/v1
	// beta1 both have cert-manager installed; reporting the version difference as a policy divergence would
	// make every fleet with a staggered operator upgrade look like a policy problem.
	Operators []string `json:"operators,omitempty"`

	// OperatorsRead records whether discovery succeeded. Without it, an empty Operators list means either
	// "no operators" or "discovery was refused", and the divergence surface would render the second as the
	// first for every cluster whose discovery failed.
	OperatorsRead bool `json:"operatorsRead"`
}

// NamespacePosture is the policy shape of one namespace.
//
// EVERY DIMENSION CARRIES ITS OWN Read FLAG rather than one flag for the namespace, because RBAC is granted
// per resource: a reading commonly lists NetworkPolicies and is refused ResourceQuotas in the same
// namespace. One flag would force the whole namespace to be reported as unreadable to stay honest about one
// dimension, discarding what was legitimately read.
type NamespacePosture struct {
	Name string `json:"name"`

	// PodSecurity is the three Pod Security Admission labels as the namespace carries them. An empty string
	// means the label is absent, which is a real and different state from "restricted" — the namespace is
	// then governed by whatever the cluster default is, which this reading does not see.
	PodSecurity PodSecurityLabels `json:"podSecurity"`
	// PodSecurityRead is whether the namespace object itself was read. Namespaces being denied is rare and
	// possible; when it happens the labels above are meaningless rather than absent.
	PodSecurityRead bool `json:"podSecurityRead"`

	// NetworkPolicies is how many NetworkPolicy objects the namespace holds. A COUNT and not a list: the
	// names are cluster-local strings chosen by an operator and two clusters naming the same policy
	// differently is not a policy difference. Zero with NetworkPoliciesRead true is the meaningful state.
	NetworkPolicies     int  `json:"networkPolicies"`
	NetworkPoliciesRead bool `json:"networkPoliciesRead"`

	// ResourceQuotas and LimitRanges, same shape and same reasoning.
	ResourceQuotas     int  `json:"resourceQuotas"`
	ResourceQuotasRead bool `json:"resourceQuotasRead"`
	LimitRanges        int  `json:"limitRanges"`
	LimitRangesRead    bool `json:"limitRangesRead"`
}

// PodSecurityLabels holds the three PSA modes a namespace may declare.
type PodSecurityLabels struct {
	Enforce string `json:"enforce,omitempty"`
	Audit   string `json:"audit,omitempty"`
	Warn    string `json:"warn,omitempty"`
}

// Empty reports whether the namespace declares no Pod Security Admission label at all.
func (p PodSecurityLabels) Empty() bool {
	return p.Enforce == "" && p.Audit == "" && p.Warn == ""
}
