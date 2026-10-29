package rules

import (
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// BuildCompliance derives a compliance map from the findings an audit produced.
//
// IMPORTANT — these are OBSERVATIONS mapped to controls, never an audit verdict.
// shoalcheck is not a QSA/auditor and cannot assert that a control is
// "violated". Each emitted row carries Status="gap", which the renderer reframes
// as "Potential gap" (see internal/report/funcs.go complianceLabel). The map
// only states "we observed something relevant to this control" — interpreting
// it against the actual control text is the customer's auditor's job.
//
// For every control with at least one matching finding, exactly one
// ComplianceRow is emitted, carrying the matching finding IDs (capped — see
// maxFindingIDs). Controls with zero matching findings are NOT emitted: we only
// report what we observed. Rows are returned in deterministic order, sorted by
// Framework then Control. Empty input returns nil.
func BuildCompliance(findings []types.Finding) []types.ComplianceRow {
	// Group matching finding IDs per control, keyed by control identity.
	type key struct{ framework, control string }
	matched := map[key]*types.ComplianceRow{}

	for _, f := range findings {
		for _, c := range complianceMap[f.RuleID] {
			k := key{c.Framework, c.Control}
			row, ok := matched[k]
			if !ok {
				row = &types.ComplianceRow{
					Framework: c.Framework,
					Control:   c.Control,
					Title:     c.Title,
					Status:    "gap",
				}
				matched[k] = row
			}
			row.FindingIDs = append(row.FindingIDs, f.ID)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	rows := make([]types.ComplianceRow, 0, len(matched))
	for _, row := range matched {
		row.FindingIDs = capFindingIDs(row.FindingIDs)
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Framework != rows[j].Framework {
			return rows[i].Framework < rows[j].Framework
		}
		return rows[i].Control < rows[j].Control
	})
	return rows
}

// maxFindingIDs caps how many finding IDs a single compliance row lists, so a
// noisy cluster doesn't render a wall of hashes against one control. The cap is
// presentational only — the underlying findings remain in ar.Findings.
const maxFindingIDs = 8

// capFindingIDs trims FindingIDs to maxFindingIDs while preserving order.
func capFindingIDs(ids []string) []string {
	if len(ids) > maxFindingIDs {
		return ids[:maxFindingIDs]
	}
	return ids
}

// controlRef is one (framework, control, human title) target a rule maps to.
type controlRef struct {
	Framework string
	Control   string
	Title     string
}

// complianceMap maps each detection rule's ID to the framework controls it
// provides EVIDENCE about. This is intentionally a hand-maintained table so the
// founder can correct control numbers against the authoritative framework text.
//
// Control numbers cited from widely published reference points:
//   - PCI-DSS v4.0 requirement numbers
//   - SOC 2 (TSC 2017) Common Criteria (CC*) and Availability (A1.*) series
//   - CIS Kubernetes Benchmark v1.9 Section 5 numbers
//   - NSA/CISA Kubernetes Hardening Guidance (see scheme below)
//
// NSA/CISA SYNTHETIC-CITATION SCHEME: the NSA/CISA "Kubernetes Hardening
// Guidance" is narrative hardening advice organized into sections, NOT a
// numbered control catalog like CIS/PCI — there is no "NSA 5.2.2" to cite. So
// each NSA/CISA row uses a synthetic "<SectionLetter>.<topic>" citation in the
// Control field (e.g. "PS.privileged", "NET.netpol", "AUTH.least-priv") while
// the human Title carries the REAL section name from the guidance. The section
// letters are:
//   - PS.*    Pod Security
//   - NET.*   Network Separation & Hardening
//   - AUTH.*  Authentication & Authorization
//   - (Audit Logging & Threat Detection, plus control-plane and
//     version/scanning slices, are STRUCTURALLY out of read-only API reach and
//     are surfaced as explicit "NOT covered" rows via nsaCisaManual below —
//     never silently omitted, or a green section would read as full coverage.)
//   - UPG.*   Upgrading & Application Security
//
// The framing is identical to CIS/PCI/SOC2: observations mapped to guidance,
// never a verdict; every NSA-CISA row still emits Status="gap" and renders via
// the existing gap→"Potential gap" path. NSA-CISA is informational mapping, not
// a certifiable control catalog (the UI title says so).
//
// CIS VERSION-SKEW DECISION (founder call): CIS renumbered Section 5.2 between
// versions (privileged was 5.2.5 in older releases, 5.2.2 in newer). To match
// the cisVersionString below ("...v1.9...") we use the v1.9 Section-5 numbering
// THROUGHOUT, including the privileged-host-access row, which under v1.9 maps to
// 5.2.2 (privileged) / 5.2.3 (hostPID) / 5.2.4 (hostNetwork) / 5.2.5 (hostIPC) /
// 5.2.12 (hostPath) / 5.2.13 (hostPort). Do NOT ship mixed numbering in a
// customer deliverable.
//
// TODO(founder): these are defensible "well-known" control numbers, not a
// certified mapping. Review each row against the framework's authoritative text
// before any control number appears in a customer deliverable, and adjust here.
// A rule absent from this table (e.g. cost rules like k8s.cost.node-headroom)
// deliberately contributes NO compliance rows.
var complianceMap = map[string][]controlRef{
	// --- Access control / least privilege ---
	"k8s.rbac.cluster-admin-serviceaccount": {
		{"PCI-DSS", "7.2.1", "Access to system components is restricted to least privilege"},
		{"SOC2", "CC6.3", "Logical access — least privilege & role-based authorization"},
		{"CIS-K8s", "5.1.1", "Ensure cluster-admin role is only used where required"},
		{"NSA-CISA", "AUTH.least-priv", "Authentication & Authorization — enforce least-privilege RBAC"},
	},
	// THE SAME FOUR CONTROLS, AND 5.1.1 IS SHARED, NOT MOVED. "Ensure cluster-admin role is only used where
	// required" is about every subject, and until v0.1.1 it was evidenced by the ServiceAccount rule alone — so a
	// reading in which a User held cluster-admin could PASS it. Both rules now evidence it, and a PASS needs both to
	// have run clean.
	"k8s.rbac.cluster-admin-user-or-group": {
		{"PCI-DSS", "7.2.1", "Access to system components is restricted to least privilege"},
		{"SOC2", "CC6.3", "Logical access — least privilege & role-based authorization"},
		{"CIS-K8s", "5.1.1", "Ensure cluster-admin role is only used where required"},
		{"NSA-CISA", "AUTH.least-priv", "Authentication & Authorization — enforce least-privilege RBAC"},
	},
	// Role and ClusterRole BODIES — what a binding actually grants (B-1 Option C). Eight of the nine §5.1
	// controls that sat at MANUAL are evidenced here.
	//
	// 5.1.3 IS NOT IN THIS LIST, deliberately. "Minimize wildcard use in Roles and ClusterRoles" is a
	// statement about role TEXT regardless of whether anything is bound to it, and this rule reports only
	// BOUND roles — an unbound wildcard ClusterRole grants nothing to anybody and is not reported. It also
	// flags only a rule that is `*` on all three of verbs, groups and resources, while the control covers
	// any wildcard. Two independent gaps, either of which would make a PASS false, so it stays MANUAL with
	// a rationale that says exactly that. See docs/qa/bug-ledger.md.
	"k8s.rbac.dangerous-grant": {
		{"CIS-K8s", "5.1.2", "Minimize access to secrets"},
		{"CIS-K8s", "5.1.4", "Minimize access to create pods"},
		{"CIS-K8s", "5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions"},
		{"CIS-K8s", "5.1.9", "Minimize access to create persistent volumes"},
		{"CIS-K8s", "5.1.10", "Minimize access to the proxy sub-resource of nodes"},
		{"CIS-K8s", "5.1.11", "Minimize access to the approval sub-resource of CSRs"},
		{"CIS-K8s", "5.1.12", "Minimize access to webhook configuration objects"},
		{"CIS-K8s", "5.1.13", "Minimize access to the service account token creation"},
		{"PCI-DSS", "7.2.1", "Access to system components is restricted to least privilege"},
		{"SOC2", "CC6.3", "Logical access — least privilege & role-based authorization"},
		{"NSA-CISA", "AUTH.least-priv", "Authentication & Authorization — enforce least-privilege RBAC"},
	},
	"k8s.workload.secret-in-env-var": {
		// ONE CITATION, AND ONLY ONE. The control exists verbatim in the generic benchmark and in all three
		// provider ones; a PCI or SOC2 row would be this file guessing which clause a secret in an
		// environment variable belongs to, and the header above says not to.
		{"CIS-K8s", "5.4.1", "Prefer using secrets as files over secrets as environment variables"},
	},
	"k8s.rbac.binding-to-builtin-subject": {
		{"CIS-K8s", "5.1.7", "Avoid use of system:masters group"},
	},
	"k8s.workload.default-sa-token-automount": {
		{"SOC2", "CC6.1", "Logical access controls restrict unauthorized access"},
		{"CIS-K8s", "5.1.5", "Ensure default service accounts are not actively used"},
		{"CIS-K8s", "5.1.6", "Ensure SA tokens are only mounted where necessary"},
		{"NSA-CISA", "AUTH.sa-token", "Authentication & Authorization — disable default ServiceAccount token automount"},
	},

	// --- Host isolation / secure configuration ---
	// privileged-host-access aggregates several PSS-Baseline offenses into one
	// rule, so it maps to every CIS v1.9 control it can produce evidence for:
	// privileged (5.2.2), hostPID (5.2.3), hostNetwork (5.2.4), hostIPC (5.2.5),
	// hostPath (5.2.12), hostPort (5.2.13 — added in Version 1.1.0).
	"k8s.workload.privileged-host-access": {
		{"PCI-DSS", "2.2.1", "Configuration standards address known security vulnerabilities"},
		{"CIS-K8s", "5.2.2", "Minimize the admission of privileged containers"},
		{"CIS-K8s", "5.2.3", "Minimize the admission of containers sharing the host process ID namespace"},
		{"CIS-K8s", "5.2.4", "Minimize the admission of containers sharing the host network namespace"},
		{"CIS-K8s", "5.2.5", "Minimize the admission of containers sharing the host IPC namespace"},
		{"CIS-K8s", "5.2.12", "Minimize the admission of containers with hostPath volumes"},
		{"CIS-K8s", "5.2.13", "Minimize the admission of containers using hostPorts"},
		{"NSA-CISA", "PS.privileged", "Pod Security — reject privileged / host-namespace pods"},
		{"NSA-CISA", "PS.hostpath", "Pod Security — restrict hostPath volume mounts"},
	},
	"k8s.workload.dangerous-capabilities": {
		{"CIS-K8s", "5.2.8", "Minimize the admission of containers with the NET_RAW capability"},
		{"CIS-K8s", "5.2.9", "Minimize the admission of containers with added capabilities"},
		{"PCI-DSS", "2.2.1", "Configuration standards address known security vulnerabilities"},
		{"NSA-CISA", "PS.caps", "Pod Security — drop unnecessary Linux capabilities"},
	},
	"k8s.workload.capabilities-not-dropped": {
		{"CIS-K8s", "5.2.10", "Minimize the admission of containers with capabilities assigned"},
		{"NSA-CISA", "PS.caps", "Pod Security — drop unnecessary Linux capabilities"},
	},
	"k8s.workload.runs-as-root": {
		{"CIS-K8s", "5.2.7", "Minimize the admission of root containers"},
		{"SOC2", "CC6.1", "Logical access controls restrict unauthorized access"},
		{"NSA-CISA", "PS.nonroot", "Pod Security — run containers as non-root"},
	},
	"k8s.workload.allow-privilege-escalation": {
		{"CIS-K8s", "5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation"},
		{"NSA-CISA", "PS.nonroot", "Pod Security — run containers as non-root"},
	},
	"k8s.workload.seccomp-not-enforced": {
		{"CIS-K8s", "5.2.1", "Ensure the seccomp profile is set to runtime/default (PSS restricted)"},
		{"NSA-CISA", "PS.seccomp", "Pod Security — apply a seccomp profile"},
	},
	"k8s.workload.writable-root-filesystem": {
		{"CIS-K8s", "5.2.1", "Apply security context to pods/containers (read-only root FS — PSS restricted)"},
		{"NSA-CISA", "PS.rofs", "Pod Security — use an immutable (read-only) root filesystem"},
	},
	"k8s.namespace.pss-admission-not-enforced": {
		{"CIS-K8s", "5.2.1", "Ensure the cluster has at least one active Pod Security policy control mechanism"},
		{"PCI-DSS", "2.2.1", "Configuration standards address known security vulnerabilities"},
	},
	"k8s.namespace.default-namespace-in-use": {
		{"CIS-K8s", "5.7.4", "The default namespace should not be used"},
	},

	// --- Network segmentation ---
	"k8s.namespace.no-network-policy": {
		{"PCI-DSS", "1.3.1", "Restrict inbound traffic to the cardholder data environment"},
		{"CIS-K8s", "5.3.2", "Ensure all namespaces have NetworkPolicies defined"},
		{"NSA-CISA", "NET.netpol", "Network Separation & Hardening — define NetworkPolicies per namespace"},
	},

	// --- Change management / image integrity ---
	"k8s.workload.mutable-image-tags": {
		{"SOC2", "CC8.1", "Changes are authorized, designed, tested and approved"},
		{"CIS-K8s", "5.5.1", "Configure image provenance using ImagePolicyWebhook"},
		{"NSA-CISA", "PS.immutable-image", "Pod Security — pin immutable image tags / digests"},
		{"NSA-CISA", "UPG.image-hygiene", "Upgrading & Application Security — image hygiene (partial; full coverage needs a scanner)"},
	},

	// --- Resource governance ---
	"k8s.namespace.no-resource-governance": {
		{"SOC2", "CC6.6", "Boundary protection — restrict access between segments"},
		{"CIS-K8s", "5.7.3", "Apply security context / resource limits to namespaces"},
		{"NSA-CISA", "NET.ns-isolation", "Network Separation & Hardening — namespace isolation via resource governance (partial)"},
	},

	// --- Availability / reliability (SOC2 Availability series) ---
	"k8s.workload.missing-resource-requests": {
		{"SOC2", "A1.1", "Capacity is managed to meet availability commitments"},
	},
	"k8s.workload.no-probes": {
		{"SOC2", "A1.2", "Recovery and failover mechanisms protect availability"},
	},
	"k8s.workload.single-replica-no-pdb": {
		{"SOC2", "A1.2", "Recovery and failover mechanisms protect availability"},
	},
	"k8s.workload.no-anti-affinity": {
		{"SOC2", "A1.2", "Recovery and failover mechanisms protect availability"},
	},
	"k8s.reliability.pdb-blocks-drains": {
		{"SOC2", "A1.2", "Recovery and failover mechanisms protect availability"},
	},
	"k8s.workload.risky-rollout-strategy": {
		{"SOC2", "A1.2", "Recovery and failover mechanisms protect availability"},
	},

	// --- Cost rules intentionally map to NO control ---
	// k8s.cost.idle-loadbalancer and k8s.cost.node-headroom are efficiency
	// findings, not compliance evidence, so they are deliberately absent.
}

// cisVersionString scopes the assessment so "N of M pass" can never read as the
// whole benchmark. The "(Section 5 subset)" qualifier is load-bearing honesty:
// Sections 1–4 are architecturally out of reach for a read-only API client on a
// managed cluster (see cisControlUniverse Rationale strings).
const cisVersionString = "CIS Kubernetes Benchmark v1.9 (Section 5 subset)"

// universeControl is one entry in the hand-maintained CIS control universe: the
// authoritative enumeration of which controls Shoalcheck reasons about, independent
// of whether a finding fired. Status is DERIVED at build time, not stored here —
// this table carries only the static facts (number, title, profile) plus, for
// controls with no automated check today, the Rationale that keeps the honest
// invariant intact (MANUAL/NA controls explain *why* they aren't PASS).
//
// HONESTY INVARIANT (the whole point of the product):
//   - A control becomes PASS only if a real evidence rule exists for it
//     (len(EvidenceRuleIDs) > 0, reverse-indexed from complianceMap) AND no
//     finding maps to it. PASS means "a check ran and found nothing", never
//     "we didn't look."
//   - A control with NO evidence rule today is MANUAL (or NA for §1-4), carrying
//     a Rationale. It is NEVER promoted to PASS.
//   - Sections 1–4 are NA — provider-managed control plane / worker node, out of
//     read-only API scope. Never PASS/FAIL.
//
// Evidence-bearing controls (those present in complianceMap with Framework
// "CIS-K8s" today) intentionally carry an EMPTY rationale here: their verdict is
// fully machine-derived. The drift-guard test
// (TestBuildComplianceAssessment_EveryCISControlInMapIsEnumerated) asserts every
// such mapped control also appears below, so the two tables can never disagree.
type universeControl struct {
	Control   string             // "5.1.1" — identity key, must match complianceMap controlRef.Control
	Title     string             // human title (redacted like ComplianceRow.Title)
	Profile   types.ProfileLevel // 1|2 CIS profile, 0 = unspecified
	Rationale string             // why MANUAL/NA; MUST be empty for evidence-bearing controls
	// forceStatus, when set, pins the control to MANUAL or NA regardless of
	// findings — used for §1-4 (NA) and in-scope-but-not-yet-automated §5
	// controls (MANUAL). Evidence-bearing controls leave this "" so their
	// verdict is derived (PASS/FAIL) from findings + EvidenceRuleIDs.
	forceStatus types.ControlStatus
}

// cisControlUniverse is the hand-maintained enumeration of the CIS Section 5
// controls Shoalcheck reasons about, plus representative §1-4 NA markers. It is the
// SECOND hand-maintained table (companion to complianceMap) and is kept in sync
// by the drift-guard test. After P2, the controls that appear in complianceMap
// with Framework "CIS-K8s" have automated evidence rules and their verdict is
// derived PASS/FAIL. The remaining §5 controls (RBAC role-body controls,
// 5.2.11 Windows, 5.7.2/5.7.4) are MANUAL until their detection rules ship (the
// spec's "partial-auto" set), and §1-4 are NA.
//
// TODO(founder): scoped subset, not the full ~30 §5 controls. The Version string
// and the section title keep that explicit so the pass count never reads as the
// whole benchmark. Review against authoritative CIS v1.9 text before any control
// number ships in a customer deliverable.
var cisControlUniverse = []universeControl{
	// --- §1 Control plane — provider-managed, out of read-only API scope (NA) ---
	{Control: "1.1.1", Title: "Control-plane node configuration file permissions", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusNA, Rationale: "Not assessed — provider-managed control plane, out of read-only API scope (node filesystem)."},
	{Control: "1.2.1", Title: "API server configuration flags", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusNA, Rationale: "Not assessed — provider-managed control plane, out of read-only API scope (process argv)."},

	// --- §2 etcd — provider-owned, not a visible Pod (NA) ---
	{Control: "2.1", Title: "etcd configuration (cert/peer/auto-tls flags)", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusNA, Rationale: "Not assessed — provider-managed control plane, out of read-only API scope (etcd is not a visible Pod)."},

	// --- §3 Control-plane auth & logging — apiserver flags + audit policy (NA) ---
	{Control: "3.2.1", Title: "API server audit policy / logging configuration", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusNA, Rationale: "Not assessed — provider-managed control plane, out of read-only API scope (apiserver flags / audit-policy file)."},

	// --- §4 Worker nodes / kubelet — node filesystem + kubelet config (NA) ---
	{Control: "4.2.1", Title: "Kubelet runtime configuration (anonymous-auth, read-only-port, etc.)", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusNA, Rationale: "Not assessed — provider-managed worker node, out of read-only API scope (kubelet config; nodeInfo is version-only)."},

	// --- §5.1 RBAC and Service Accounts ---
	// 5.1.1 / 5.1.5 / 5.1.6 have automated evidence rules today (in complianceMap). 5.1.1 has two since v0.1.1:
	// the ServiceAccount rule and the User/Group one, because the control is about every subject.
	{Control: "5.1.1", Title: "Ensure cluster-admin role is only used where required", Profile: types.ProfileLevel1},
	// 5.1.2, 5.1.4, 5.1.8-5.1.13: evidenced by k8s.rbac.dangerous-grant since 2026-08-28 (B-1 Option C —
	// Role/ClusterRole bodies are collected). They PASS only when the bodies were actually read: a denied
	// `clusterroles` degrades them to MANUAL naming the kind, because a control is never passed on a read
	// that did not happen. 5.1.3 stays MANUAL for a reason of its own, stated on its entry.
	{Control: "5.1.2", Title: "Minimize access to secrets", Profile: types.ProfileLevel1},
	{Control: "5.1.3", Title: "Minimize wildcard use in Roles and ClusterRoles", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusManual, Rationale: "Bodies ARE collected now, and this control still cannot be passed automatically: it is about role TEXT whether or not anything is bound to it, while k8s.rbac.dangerous-grant reports only BOUND roles — an unbound wildcard ClusterRole grants nothing to anybody. It also flags only a rule that is `*` on verbs AND groups AND resources, while the control covers any wildcard. Findings for wildcard grants do appear; the PASS is what is withheld."},
	{Control: "5.1.4", Title: "Minimize access to create pods", Profile: types.ProfileLevel1},
	{Control: "5.1.5", Title: "Ensure default service accounts are not actively used", Profile: types.ProfileLevel1},
	{Control: "5.1.6", Title: "Ensure SA tokens are only mounted where necessary", Profile: types.ProfileLevel1},
	{Control: "5.1.7", Title: "Avoid use of system:masters group", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusManual, Rationale: "Cannot assert clean — client-cert O=system:masters is invisible to API-only collection; only explicit RBAC Group bindings are observable. Since 2026-09-10 those bindings ARE reported, by k8s.rbac.binding-to-builtin-subject: findings appear when one exists, and the PASS is what stays withheld, because an absence of bindings is not an absence of the group."},
	{Control: "5.1.8", Title: "Limit use of the Bind, Impersonate and Escalate permissions", Profile: types.ProfileLevel1},
	{Control: "5.1.9", Title: "Minimize access to create persistent volumes", Profile: types.ProfileLevel1},
	{Control: "5.1.10", Title: "Minimize access to the proxy sub-resource of nodes", Profile: types.ProfileLevel1},
	{Control: "5.1.11", Title: "Minimize access to the approval sub-resource of CSRs", Profile: types.ProfileLevel1},
	{Control: "5.1.12", Title: "Minimize access to webhook configuration objects", Profile: types.ProfileLevel1},
	{Control: "5.1.13", Title: "Minimize access to the service account token creation", Profile: types.ProfileLevel1},

	// --- §5.2 Pod Security Standards ---
	// P2 UNIVERSE UPGRADE: every control below that now has a real evidence rule
	// in complianceMap (5.2.1/5.2.2/5.2.3/5.2.4/5.2.5/5.2.6/5.2.7/5.2.8/5.2.9/
	// 5.2.10/5.2.12/5.2.13) drops its forced-MANUAL override so the verdict is
	// derived PASS/FAIL from findings + reverse-indexed EvidenceRuleIDs. Controls
	// still WITHOUT a rule (5.2.11 Windows HostProcess) stay MANUAL.
	{Control: "5.2.1", Title: "Ensure the cluster has at least one active Pod Security control mechanism", Profile: types.ProfileLevel1},
	{Control: "5.2.2", Title: "Minimize the admission of privileged containers", Profile: types.ProfileLevel1},
	{Control: "5.2.3", Title: "Minimize the admission of containers sharing the host process ID namespace", Profile: types.ProfileLevel1},
	{Control: "5.2.4", Title: "Minimize the admission of containers sharing the host network namespace", Profile: types.ProfileLevel1},
	{Control: "5.2.5", Title: "Minimize the admission of containers sharing the host IPC namespace", Profile: types.ProfileLevel1},
	{Control: "5.2.6", Title: "Minimize the admission of containers with allowPrivilegeEscalation", Profile: types.ProfileLevel1},
	{Control: "5.2.7", Title: "Minimize the admission of root containers", Profile: types.ProfileLevel1},
	{Control: "5.2.8", Title: "Minimize the admission of containers with the NET_RAW capability", Profile: types.ProfileLevel1},
	{Control: "5.2.9", Title: "Minimize the admission of containers with added capabilities", Profile: types.ProfileLevel1},
	{Control: "5.2.10", Title: "Minimize the admission of containers with capabilities assigned", Profile: types.ProfileLevel1},
	{Control: "5.2.11", Title: "Minimize the admission of Windows HostProcess containers", Profile: types.ProfileLevel1,
		forceStatus: types.ControlStatusManual, Rationale: "Out of scope for Linux focus; checkable but not implemented (rare on Linux clusters)."},
	{Control: "5.2.12", Title: "Minimize the admission of containers with hostPath volumes", Profile: types.ProfileLevel1},
	{Control: "5.2.13", Title: "Minimize the admission of containers using hostPorts", Profile: types.ProfileLevel1},

	// --- §5.3 Network Policies and CNI ---
	{Control: "5.3.2", Title: "Ensure all namespaces have NetworkPolicies defined", Profile: types.ProfileLevel2},

	// --- §5.5 Image registries and scanning ---
	// §5.4 SECRETS MANAGEMENT — the section this catalog had no entry for until 2026-09-10, because nothing
	// could evidence it. k8s.workload.secret-in-env-var reads `env[].valueFrom.secretKeyRef` and
	// `envFrom[].secretRef` out of the pod template, which is a reference and not a Secret: the check needs
	// no Secret read, and internal/collect never lists them.
	//
	// PROFILE LEVEL DELIBERATELY UNSPECIFIED. The Level 1 / Level 2 split lives only in the CIS PDFs, which
	// sit behind registration; docs/qa/2026-08-31-provider-benchmark-measurement.md states that none were
	// invented for that measurement and none are invented here. ProfileLevel's zero value means exactly this.
	{Control: "5.4.1", Title: "Prefer using secrets as files over secrets as environment variables"},
	{Control: "5.5.1", Title: "Configure image provenance using ImagePolicyWebhook", Profile: types.ProfileLevel2},

	// --- §5.7 General Policies ---
	// 5.7.2 has no discrete evidence rule — the seccomp signal is folded into
	// 5.2.1 in CIS v1.9 numbering (the seccomp-not-enforced rule maps there) — so
	// 5.7.2 stays intentionally MANUAL. 5.7.4 now has the default-namespace-in-use
	// evidence rule and is derived PASS/FAIL like the other PSS-backed controls.
	{Control: "5.7.2", Title: "Ensure that the seccomp profile is set to docker/default in pod definitions", Profile: types.ProfileLevel2,
		forceStatus: types.ControlStatusManual, Rationale: "Seccomp signal is folded into 5.2.1 in CIS v1.9 numbering; no discrete 5.7.2 evidence rule — intentionally MANUAL."},
	{Control: "5.7.3", Title: "Apply security context / resource limits to namespaces", Profile: types.ProfileLevel2},
	{Control: "5.7.4", Title: "The default namespace should not be used", Profile: types.ProfileLevel2},
}

// uncollectedFor returns the collector steps an evidence rule declares that this reading did not manage to
// collect, sorted and deduplicated. Empty when coverage is unknown (a nil func) or everything was read.
//
// It reads RequiredKinds, which is the rule's own statement of what its CLAIM rests on (deps.go). A kind
// that only changes a finding's wording is deliberately not in that list, so a wording input being absent
// does not downgrade a control — only a claim input does.
func uncollectedFor(ruleIDs []string, collected func(kind string) bool) []string {
	if collected == nil {
		return nil
	}
	byID := map[string]Rule{}
	for _, r := range All() {
		byID[r.ID()] = r
	}
	seen := map[string]bool{}
	var missing []string
	for _, id := range ruleIDs {
		r, ok := byID[id]
		if !ok {
			continue
		}
		for _, k := range r.RequiredKinds() {
			if !collected(k) && !seen[k] {
				seen[k] = true
				missing = append(missing, k)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// cisEvidenceRuleIndex reverse-indexes complianceMap so the assessment view and
// the evidence-pointer view can never disagree about which rule checks a CIS
// control. For each control number it collects every RuleID whose controlRef has
// Framework "CIS-K8s" and that Control. Returns map[control] -> sorted ruleIDs.
//
// This is the single source of truth for the honesty invariant: a control gets
// EvidenceRuleIDs ONLY if a real rule maps to it here. No rule → no evidence →
// the control can never be PASS.
func cisEvidenceRuleIndex() map[string][]string {
	idx := map[string][]string{}
	for ruleID, refs := range complianceMap {
		for _, c := range refs {
			if c.Framework != "CIS-K8s" {
				continue
			}
			idx[c.Control] = append(idx[c.Control], ruleID)
		}
	}
	for control := range idx {
		sort.Strings(idx[control])
	}
	return idx
}

// BuildComplianceAssessment produces the control-by-control CIS assessment from
// the audit's findings. It enumerates cisControlUniverse, reverse-indexes
// EvidenceRuleIDs from complianceMap, maps findings to FAIL, and scores
// denominator-honestly (Scored = Passed + Failed; MANUAL/NA excluded from
// PassRate). Controls are returned sorted by control number.
//
// HONESTY INVARIANT enforced here:
//   - PASS requires len(EvidenceRuleIDs) > 0 AND no matching finding. A control
//     with no evidence rule today is forced MANUAL/NA (per its universe entry).
//   - FAIL requires >=1 matching finding (which by construction means an
//     evidence rule exists). FindingIDs are capped via capFindingIDs.
//   - §1-4 are NA (provider-managed). §5 controls without a shipped rule are
//     MANUAL with a Rationale.
//
// Always returns a non-nil assessment (the control universe is static and
// non-empty), so the report carries it whenever the pipeline runs.
// BuildComplianceAssessment is the coverage-free entry point. It cannot know whether a read was refused, so
// it does not pretend to: use BuildComplianceAssessmentWithCoverage from anywhere that has the collector's
// own account of what it managed to read.
func BuildComplianceAssessment(findings []types.Finding) *types.ComplianceAssessment {
	return BuildComplianceAssessmentWithCoverage(findings, nil)
}

// BuildComplianceAssessmentWithCoverage is the same assessment, told which collector steps actually
// produced data.
//
// WHY THE PARAMETER EXISTS. PASS has exactly one path: an evidence rule maps to the control and produced no
// finding. That is correct when the rule ran, and it is a false clean bill when the rule's INPUTS were
// refused — because every rule in this package carries a denial guard and returns nothing rather than
// asserting an absence it could not observe. From the outside the two are identical: no findings.
//
// It became load-bearing when nine CIS §5.1 controls stopped being MANUAL (B-1 Option C). RBAC is the read a
// customer's cluster is most likely to refuse: a scoped auditor Role that omits `clusterroles` is an
// ordinary thing to hand a vendor. "5.1.2 Minimize access to secrets: PASS" on a cluster whose roles we
// could not read is exactly the sentence the PASS-invariant exists to prevent.
//
// collected reports whether a collector step produced data. A nil func means "no coverage information" and
// keeps the previous behaviour — which is honest for a caller that genuinely has none, and is why the
// pipeline passes a real one.
func BuildComplianceAssessmentWithCoverage(findings []types.Finding, collected func(kind string) bool) *types.ComplianceAssessment {
	evidence := cisEvidenceRuleIndex()

	// findingIDsByControl[control] = finding IDs whose ruleID maps to that
	// CIS-K8s control. Built once from findings × complianceMap.
	findingIDsByControl := map[string][]string{}
	for _, f := range findings {
		for _, c := range complianceMap[f.RuleID] {
			if c.Framework != "CIS-K8s" {
				continue
			}
			findingIDsByControl[c.Control] = append(findingIDsByControl[c.Control], f.ID)
		}
	}

	controls := make([]types.ComplianceControl, 0, len(cisControlUniverse))
	score := types.ComplianceScore{Totals: map[types.ControlStatus]int{}}

	for _, u := range cisControlUniverse {
		cc := types.ComplianceControl{
			Control:   u.Control,
			Title:     u.Title,
			Profile:   u.Profile,
			Rationale: u.Rationale,
		}
		evidenceRules := evidence[u.Control]
		matched := findingIDsByControl[u.Control]
		// A build fact: this control has an automated check, whether or not this run could exercise it.
		if u.forceStatus == "" && len(evidenceRules) > 0 {
			score.Checkable++
		}

		switch {
		case u.forceStatus == types.ControlStatusNA:
			// Sections 1-4: out of read-only API scope. Never PASS/FAIL.
			cc.Status = types.ControlStatusNA
		case u.forceStatus == types.ControlStatusManual:
			// In scope, and the automated verdict is withheld for the reason the Rationale states.
			//
			// IT STILL POINTS AT WHAT WAS FOUND. 5.1.7 is the case that made this necessary: a clean read
			// cannot assert that nobody holds system:masters, because a client certificate carrying O= that
			// group leaves no RBAC object — so the PASS stays withheld forever. But since
			// k8s.rbac.binding-to-builtin-subject exists, a reading CAN hold the bindings that name it, and
			// the control row was printing "assess manually" with no pointer to a finding two sections away.
			// The force is about the verdict, not about the evidence.
			cc.Status = types.ControlStatusManual
			if len(matched) > 0 {
				cc.EvidenceRuleIDs = evidenceRules
				cc.FindingIDs = capFindingIDs(matched)
			}
		case len(matched) > 0:
			// A real rule fired against this control: FAIL.
			cc.Status = types.ControlStatusFail
			cc.EvidenceRuleIDs = evidenceRules
			cc.FindingIDs = capFindingIDs(matched)
		case len(evidenceRules) > 0 && len(uncollectedFor(evidenceRules, collected)) > 0:
			// The evidence rule exists and its inputs were refused. NOT a pass, and not a fail either —
			// nothing was measured. The rationale names the kind, because "assess manually" without saying
			// which read failed leaves the operator to guess whether their RBAC or our collector was at
			// fault.
			missing := uncollectedFor(evidenceRules, collected)
			cc.Status = types.ControlStatusManual
			cc.Rationale = "Not assessed — this control's evidence rule rests on " +
				strings.Join(missing, ", ") + ", which this reading could not collect (denied or absent). " +
				"A control is never passed on a read that did not happen."
		case len(evidenceRules) > 0:
			// A real evidence rule exists, its inputs were read, and it found nothing: PASS. This is the
			// ONLY path to PASS — it requires len(EvidenceRuleIDs) > 0.
			cc.Status = types.ControlStatusPass
			cc.EvidenceRuleIDs = evidenceRules
		default:
			// Safety net: an evidence-bearing universe entry lost its mapping,
			// or a non-forced entry has no rule. Never silently PASS — degrade
			// to MANUAL so the invariant (no PASS without a rule) holds even if
			// the two tables drift. The drift-guard test prevents this in CI.
			cc.Status = types.ControlStatusManual
			if cc.Rationale == "" {
				cc.Rationale = "No automated evidence rule maps to this control today; assess manually."
			}
		}

		score.Totals[cc.Status]++
		switch cc.Status {
		case types.ControlStatusPass:
			score.Passed++
		case types.ControlStatusFail:
			score.Failed++
		case types.ControlStatusManual:
			score.Manual++
		case types.ControlStatusNA:
			score.NA++
		}
		controls = append(controls, cc)
	}

	sort.Slice(controls, func(i, j int) bool { return controls[i].Control < controls[j].Control })

	score.Total = len(controls)
	score.InScope = score.Total - score.NA
	score.Scored = score.Passed + score.Failed
	if score.Scored > 0 {
		score.PassRate = float64(score.Passed) / float64(score.Scored)
	}

	return &types.ComplianceAssessment{
		Framework: "CIS-K8s",
		Version:   cisVersionString,
		Controls:  controls,
		Score:     score,
	}
}
