package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Pod Security Standards (PSS) rules.
//
// SCOPE & READ-ONLY CONTRACT: every check reads only objects already in
// collect.Inventory — workload PodSpecs (via workloads()) and Namespace labels.
// Nothing touches Secrets/ConfigMaps/env. Each PSS field lives in
// PodSpec.SecurityContext or Container.SecurityContext, so field-presence is
// observed with Confidence 1.0 (same rationale as privileged.go).
//
// HONESTY CONSTRAINT (mirrors the netpol CNI caveat): a workload spec can omit a
// field that PodSecurity admission / a mutating webhook would otherwise reject or
// fill. Shoalcheck reads the spec AS AUTHORED, not as admitted. So the per-container
// checks say "the spec does not assert X"; the admission-level check
// (PodSecurityAdmissionNotEnforced) tells the reader whether the cluster actually
// ENFORCES a profile. The two are read together — every per-container rule
// cross-references the admission rule in its description.
//
// CRITICAL ENGINE CONSTRAINT: findingID hashes only (ruleID|kind|ns|name) — no
// per-check discriminator. Two checks sharing one RuleID on the same workload
// would collide and validate.go would abort the whole audit. Therefore each
// control below gets a DISTINCT RuleID (the table's id field).

// pssCheck is one table-driven container-level PSS control. ID()/Version()/
// Evaluate() are implemented ONCE on *pssCheck; the per-control logic lives in
// the detect closure, which returns the evidence lines for one workload (empty
// → no finding) and an optional remediation YAML patch.
type pssCheck struct {
	id       string
	version  string
	title    string // finding title template fragment; "%s/%s" filled with ns/name
	why      string
	severity types.Severity
	category types.Category
	effort   types.EffortLevel
	// detect inspects one workload and returns evidence lines for every
	// offending container (empty slice = clean = no finding) plus an optional
	// remediation YAML patch. The description is composed by Evaluate so the
	// cross-reference to the admission check is uniform.
	detect func(w workload) (evidence []string, remediationYAML string)
	// description, when set, overrides the default composed description. It receives the workload ref
	// string, the number of offending containers, and the TOTAL number of containers in the pod
	// template — the denominator, per condition (c) of the 2026-08-29 collapse decision. "3 of 5
	// containers" and "5 of 5 containers" are different facts about a workload, and without the total a
	// reader cannot tell an unhardened sidecar from a wholly unhardened workload.
	description func(ref string, n, total int) string
	// dynamicSeverity, when set, overrides the static severity per workload.
	// Used by runs-as-root so the headline severity tracks real-world impact:
	// HIGH only when root is confirmed/near-certain, MEDIUM when it's merely
	// unconfirmed (matching the sibling PSS-field-unset checks). nil → use
	// the static severity field.
	dynamicSeverity func(w workload) types.Severity
}

func (c *pssCheck) ID() string      { return c.id }
func (c *pssCheck) Version() string { return c.version }

func (c *pssCheck) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	// Every pod spec the cluster runs, not only the three workload kinds: a root, unconfined, capability-keeping
	// container in a bare Pod or a CronJob runs exactly as one in a Deployment (podTemplates).
	for _, w := range podTemplates(inv, opts) {
		evidence, remediationYAML := c.detect(w)
		if len(evidence) == 0 {
			continue
		}
		ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
		desc := c.composeDescription(ref, len(evidence), len(allContainers(w)))
		severity := c.severity
		if c.dynamicSeverity != nil {
			severity = c.dynamicSeverity(w)
		}
		out = append(out, types.Finding{
			ID:                findingID(c.id, w.Kind, w.Namespace, w.Name),
			IDBasis:           &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:            c.id,
			RuleVersion:       c.version,
			Title:             fmt.Sprintf(c.title, w.Namespace, w.Name),
			Description:       desc,
			WhyItMatters:      c.why,
			Evidence:          evidence,
			Severity:          severity,
			Category:          c.category,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   c.effort,
			RemediationYAML:   remediationYAML,
			Confidence:        1.0, // presence/absence of a spec field — no estimation
			Provenance:        provenance(),
		})
	}
	return out
}

// composeDescription appends the spec-as-authored vs admitted cross-reference to
// every per-container finding so the reader knows to read it alongside the
// namespace admission check.
func (c *pssCheck) composeDescription(ref string, n, total int) string {
	const admissionNote = " This reads the spec AS AUTHORED, not as admitted: a PodSecurity admission profile or mutating webhook could reject or fill this field at admission time. Read alongside the namespace's PodSecurity admission level (k8s.namespace.pss-admission-not-enforced) to know whether the cluster actually enforces it."
	if c.description != nil {
		return c.description(ref, n, total) + admissionNote
	}
	return fmt.Sprintf("%s has %s whose securityContext does not assert this Pod Security Standards control (see evidence).", ref, containerCount(n, total)) + admissionNote
}

// containerCount renders the offending count against the total. The denominator is condition (c) of the
// 2026-08-29 collapse decision, and it is the difference between "a sidecar is unhardened" and "nothing in
// this workload is". A total of zero should not be reachable — a workload with no containers produces no
// evidence — but it is handled rather than trusted.
func containerCount(n, total int) string {
	if total <= 0 || n > total {
		return nWord(n, "container", "containers")
	}
	return fmt.Sprintf("%d of %s", n, nWord(total, "container",

		// pssRules returns one Rule per table entry. Taking &pssChecks[i] (not a loop
		// copy) keeps the receiver pointing at the table entry.
		"containers"))
}

func pssRules() []Rule {
	out := make([]Rule, 0, len(pssChecks))
	for i := range pssChecks {
		out = append(out, &pssChecks[i])
	}
	return out
}

// ---------------------------------------------------------------------------
// Pod→container inheritance helpers (§4.3).
//
// runAsNonRoot / runAsUser / seccompProfile MAY be set at the pod
// (PodSpec.SecurityContext) level and inherited, or overridden per container.
// privileged / allowPrivilegeEscalation / capabilities / readOnlyRootFilesystem
// are CONTAINER-ONLY. The "effective" helpers compute container, else pod, else
// the Kubernetes default — without them, runs-as-root and seccomp false-positive
// on pod-level hardening.
// ---------------------------------------------------------------------------

// effectiveRunAsNonRoot returns the effective runAsNonRoot for a container:
// container value if set, else pod value if set, else nil (unset → K8s default
// is "may run as root").
func effectiveRunAsNonRoot(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *bool {
	if c != nil && c.RunAsNonRoot != nil {
		return c.RunAsNonRoot
	}
	if pod != nil && pod.RunAsNonRoot != nil {
		return pod.RunAsNonRoot
	}
	return nil
}

// effectiveRunAsUser returns the effective runAsUser (container, else pod, else nil).
func effectiveRunAsUser(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *int64 {
	if c != nil && c.RunAsUser != nil {
		return c.RunAsUser
	}
	if pod != nil && pod.RunAsUser != nil {
		return pod.RunAsUser
	}
	return nil
}

// effectiveSeccompProfile returns the effective seccomp profile (container, else
// pod, else nil → unset).
func effectiveSeccompProfile(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *corev1.SeccompProfile {
	if c != nil && c.SeccompProfile != nil {
		return c.SeccompProfile
	}
	if pod != nil && pod.SeccompProfile != nil {
		return pod.SeccompProfile
	}
	return nil
}

// allContainers returns containers + init containers with a label prefix, so
// inheritance helpers and detect closures iterate every workload container the
// same way privileged.go does (over-reporting init containers is acceptable and
// consistent).
type labeledContainer struct {
	label string
	c     corev1.Container
}

func allContainers(w workload) []labeledContainer {
	out := make([]labeledContainer, 0, len(w.PodSpec.Containers)+len(w.PodSpec.InitContainers))
	for i := range w.PodSpec.Containers {
		out = append(out, labeledContainer{"container", w.PodSpec.Containers[i]})
	}
	for i := range w.PodSpec.InitContainers {
		out = append(out, labeledContainer{"init container", w.PodSpec.InitContainers[i]})
	}
	return out
}

// ---------------------------------------------------------------------------
// detect closures (§4.2 table).
// ---------------------------------------------------------------------------

// dangerousCapabilities is the HOST-COMPROMISE-class capability set: adding one
// (or ALL) turns a code-execution bug into host/kernel compromise or network
// spoofing — that is what makes this a High "dangerous capabilities" finding.
//
// Benign default-set caps a container may legitimately add back (CHOWN,
// DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SETPCAP, NET_BIND_SERVICE,
// SYS_CHROOT, MKNOD, AUDIT_WRITE, SETFCAP) are deliberately NOT here: e.g. an
// init-chown helper that adds CHOWN is not a host-compromise risk, and flagging
// it as "dangerous" at High overclaims (founder QA against a real cluster:
// grafana's init-chown-data carries add=[CHOWN]). Those are a PSS-Restricted
// nicety, not a security finding.
var dangerousCapabilities = map[string]bool{
	"SYS_ADMIN": true, "SYS_MODULE": true, "SYS_RAWIO": true, "SYS_PTRACE": true,
	"SYS_BOOT": true, "SYS_TIME": true, "NET_ADMIN": true, "NET_RAW": true,
	"DAC_READ_SEARCH": true, "BPF": true, "PERFMON": true, "MAC_ADMIN": true,
	"MAC_OVERRIDE": true, "LINUX_IMMUTABLE": true, "WAKE_ALARM": true,
	"AUDIT_CONTROL": true, "SYSLOG": true, "IPC_LOCK": true, "IPC_OWNER": true,
}

func detectDangerousCapabilities(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	var ev []string
	for _, lc := range allContainers(w) {
		c := lc.c
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			continue
		}
		var added []string
		for _, capName := range c.SecurityContext.Capabilities.Add {
			name := strings.ToUpper(string(capName))
			if name == "ALL" {
				added = append(added, "ALL (every Linux capability)")
				continue
			}
			// Only host-compromise-class caps make this finding fire; a benign
			// default-set add (e.g. CHOWN on an init-chown helper) is not dangerous.
			if dangerousCapabilities[name] {
				added = append(added, name)
			}
		}
		if len(added) > 0 {
			sort.Strings(added)
			ev = append(ev, fmt.Sprintf("%s %s in %s: capabilities.add=[%s]", lc.label, c.Name, ref, strings.Join(added, ", ")))
		}
	}
	return ev, ""
}

func detectCapabilitiesNotDropped(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	var ev []string
	for _, lc := range allContainers(w) {
		c := lc.c
		dropsAll := false
		if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
			for _, capName := range c.SecurityContext.Capabilities.Drop {
				if strings.EqualFold(string(capName), "ALL") {
					dropsAll = true
					break
				}
			}
		}
		if !dropsAll {
			ev = append(ev, fmt.Sprintf("%s %s in %s: capabilities.drop does not include ALL", lc.label, c.Name, ref))
		}
	}
	if len(ev) == 0 {
		return nil, ""
	}
	return ev, ""
}

// knownRootBaseImages are base-image name prefixes that ship with USER root by
// default. We can only observe the image NAME via a read-only API client (never
// the resolved USER directive), so the name prefix is a HEURISTIC: when one of
// these is the image and the spec asserts no non-root, root is near-certain
// rather than merely unconfirmed. This is deliberately conservative — only the
// canonical OS base images whose published default is root.
var knownRootBaseImages = []string{
	"alpine", "ubuntu", "busybox", "debian", "centos", "fedora",
}

// imageRefIsKnownRootBase reports whether an image ref names one of the
// canonical root-by-default OS base images. It strips a registry host and any
// repository path so "docker.io/library/alpine:3.19" and "ubuntu" both match,
// then compares the bare repository name against the known-root prefixes. It is
// intentionally a NAME heuristic only: the actual USER directive is not
// API-observable.
func imageRefIsKnownRootBase(image string) bool {
	if image == "" {
		return false
	}
	// Drop tag/digest: "alpine:3.19" / "alpine@sha256:..." → "alpine".
	name := image
	if i := strings.IndexAny(name, "@"); i >= 0 {
		name = name[:i]
	}
	// Strip the last path segment's tag (the colon may also appear in a
	// registry port, so only split the final segment).
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		seg := name[slash+1:]
		if c := strings.IndexByte(seg, ':'); c >= 0 {
			seg = seg[:c]
		}
		name = seg
	} else if c := strings.IndexByte(name, ':'); c >= 0 {
		name = name[:c]
	}
	name = strings.ToLower(name)
	for _, base := range knownRootBaseImages {
		if name == base {
			return true
		}
	}
	return false
}

// runsAsRootClass classifies one container's root posture from the spec as
// authored. confirmedRoot means root is certain/near-certain (the only basis for
// a HIGH headline); unconfirmed means we cannot confirm root and must not claim
// it; clean means a non-root assertion is present (no finding).
type runsAsRootClass int

const (
	runsAsRootClean       runsAsRootClass = iota // non-root asserted → no finding
	runsAsRootUnconfirmed                        // cannot confirm root (no signal)
	runsAsRootConfirmed                          // root certain/near-certain
)

// classifyContainerRoot computes the root posture of one container under
// pod→container inheritance (§4.3) and returns the evidence line to emit when
// the posture is not clean.
func classifyContainerRoot(pod *corev1.PodSecurityContext, c corev1.Container, label, ref string) (runsAsRootClass, string) {
	nonRoot := effectiveRunAsNonRoot(pod, c.SecurityContext)
	uid := effectiveRunAsUser(pod, c.SecurityContext)

	// Explicit root: runAsUser:0 — confirmed, the only case we state plainly.
	if uid != nil && *uid == 0 {
		return runsAsRootConfirmed, fmt.Sprintf("%s %s in %s: runAsUser=0 — runs as UID 0 (root)", label, c.Name, ref)
	}
	// Hardened: runAsNonRoot=true OR a non-zero runAsUser — clean, no finding.
	if (nonRoot != nil && *nonRoot) || (uid != nil && *uid != 0) {
		return runsAsRootClean, ""
	}
	// Explicit runAsNonRoot:false with no non-zero uid: the spec OPTS IN to
	// allowing root — confirmed-class (we still cannot prove the image runs as
	// root, but the workload has explicitly removed the non-root guarantee).
	if nonRoot != nil && !*nonRoot {
		return runsAsRootConfirmed, fmt.Sprintf("%s %s in %s: runAsNonRoot=false and no non-zero runAsUser — root explicitly permitted (image USER directive is not API-observable)", label, c.Name, ref)
	}
	// No non-root signal at all. If the image is a known root-by-default base,
	// root is near-certain (confirmed-class by the NAME heuristic); otherwise it
	// is genuinely unconfirmed. Either way the image USER directive itself is
	// invisible to API-only collection, so we NEVER say "runs as root" outright.
	if imageRefIsKnownRootBase(c.Image) {
		return runsAsRootConfirmed, fmt.Sprintf("%s %s in %s: no non-root assertion and image %q is a known root-by-default base — root near-certain (image USER directive is not API-observable; matched on image name)", label, c.Name, ref, c.Image)
	}
	return runsAsRootUnconfirmed, fmt.Sprintf("%s %s in %s: runAsNonRoot not set and no non-zero runAsUser — unconfirmed non-root (image USER directive is not API-observable)", label, c.Name, ref)
}

func detectRunsAsRoot(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	pod := w.PodSpec.SecurityContext
	var ev []string
	for _, lc := range allContainers(w) {
		class, line := classifyContainerRoot(pod, lc.c, lc.label, ref)
		if class == runsAsRootClean {
			continue
		}
		ev = append(ev, line)
	}
	if len(ev) == 0 {
		return nil, ""
	}
	return ev, ""
}

// runsAsRootSeverity returns the HEADLINE severity for the runs-as-root finding
// on one workload. It is HIGH only when at least one container's root is
// confirmed/near-certain (explicit runAsUser:0 / runAsNonRoot:false, or a
// known-root base image with no non-root assertion). When every offending
// container is merely UNCONFIRMED non-root, the severity is MEDIUM — matching
// the sibling PSS-field-unset checks (allow-privilege-escalation,
// seccomp-not-enforced, capabilities-not-dropped). This keeps the severity
// honest: a missing defense-in-depth flag is not framed as a confirmed
// root-execution defect.
func runsAsRootSeverity(w workload) types.Severity {
	pod := w.PodSpec.SecurityContext
	for _, lc := range allContainers(w) {
		if class, _ := classifyContainerRoot(pod, lc.c, lc.label, ""); class == runsAsRootConfirmed {
			return types.SeverityHigh
		}
	}
	return types.SeverityMedium
}

func detectAllowPrivilegeEscalation(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	var ev []string
	for _, lc := range allContainers(w) {
		c := lc.c
		// nil defaults to true; explicit true also flagged.
		if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil {
			ev = append(ev, fmt.Sprintf("%s %s in %s: allowPrivilegeEscalation not set (defaults to true)", lc.label, c.Name, ref))
			continue
		}
		if *c.SecurityContext.AllowPrivilegeEscalation {
			ev = append(ev, fmt.Sprintf("%s %s in %s: allowPrivilegeEscalation=true", lc.label, c.Name, ref))
		}
	}
	if len(ev) == 0 {
		return nil, ""
	}
	return ev, ""
}

func detectSeccompNotEnforced(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	pod := w.PodSpec.SecurityContext
	var ev []string
	for _, lc := range allContainers(w) {
		c := lc.c
		prof := effectiveSeccompProfile(pod, c.SecurityContext)
		switch {
		case prof == nil || prof.Type == "":
			// nil OR an empty Type both mean "not enforced". The K8s API normally
			// rejects an empty Type, but treat it as unset for defensive
			// completeness so a malformed/empty profile never reads as enforced.
			ev = append(ev, fmt.Sprintf("%s %s in %s: no seccompProfile set (effective: unset)", lc.label, c.Name, ref))
		case prof.Type == corev1.SeccompProfileTypeUnconfined:
			ev = append(ev, fmt.Sprintf("%s %s in %s: seccompProfile.type=Unconfined — syscall filtering disabled", lc.label, c.Name, ref))
		}
	}
	if len(ev) == 0 {
		return nil, ""
	}
	return ev, ""
}

func detectWritableRootFilesystem(w workload) ([]string, string) {
	ref := fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
	var ev []string
	for _, lc := range allContainers(w) {
		c := lc.c
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			ev = append(ev, fmt.Sprintf("%s %s in %s: readOnlyRootFilesystem not set to true", lc.label, c.Name, ref))
		}
	}
	if len(ev) == 0 {
		return nil, ""
	}
	return ev, ""
}

// detectDefaultNamespaceInUse flags a workload that lives in the "default"
// namespace (CIS 5.7.4). This is a hygiene/governance signal, not a
// vulnerability: the default namespace has no PSA labels, no NetworkPolicy
// scope, and no resource quotas applied by convention, so workloads there sit
// outside every namespace-scoped guardrail this report otherwise checks.
//
// SCOPE HONESTY: this evaluates WORKLOADS only (Deployments/StatefulSets/
// DaemonSets via workloads()). Standalone Services/Pods in the default
// namespace are NOT evaluated by this check.
func detectDefaultNamespaceInUse(w workload) ([]string, string) {
	if w.Namespace != "default" {
		return nil, ""
	}
	return []string{
		fmt.Sprintf("%s %s/%s runs in the default namespace", w.Kind, w.Namespace, w.Name),
	}, ""
}

// pssChecks is the table-driven family. Each entry has a DISTINCT RuleID (the id
// field) so two checks on the same workload can never collide on findingID.
//
// SEVERITY CALIBRATION (§4.2 warning): high-fanout checks
// (writable-root-filesystem, capabilities-not-dropped) are Low/Medium, NOT High
// — a real AKS cluster produced a 738-medium unreadable pile from over-eager
// rules. Aggregate exposure shows via the by-issue-type rollup, not per-finding
// severity.
var pssChecks = []pssCheck{
	{
		id:       "k8s.workload.dangerous-capabilities",
		version:  "1.2.0",
		title:    "Drop dangerous Linux capabilities from %s/%s",
		why:      "Added capabilities like SYS_ADMIN or NET_RAW hand a container kernel-level powers that turn a code-execution bug into host compromise or network spoofing.",
		severity: types.SeverityHigh,
		category: types.CategorySecurity,
		effort:   types.EffortMedium,
		detect:   detectDangerousCapabilities,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s adds host-compromise-class Linux capabilities (see the evidence). These hand a container kernel-level powers most apps never need; remove the capabilities.add entries, or scope them to the single container that genuinely requires them. (Benign default-set caps like CHOWN are not flagged here.)", ref)
		},
	},
	{
		id:       "k8s.workload.capabilities-not-dropped",
		version:  "1.2.0",
		title:    "Drop ALL capabilities then add back only what %s/%s needs",
		why:      "Containers keep a default capability set (including NET_RAW) unless they explicitly drop ALL — a wide kernel surface most apps never use.",
		severity: types.SeverityMedium, // high-fanout: must NOT be High (738-medium-pile lesson)
		category: types.CategorySecurity,
		effort:   types.EffortLow,
		detect:   detectCapabilitiesNotDropped,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s has %s that do not drop ALL capabilities, so each keeps the default Linux capability set (NET_RAW included). The PSS-Restricted profile requires capabilities.drop:[ALL]; add back only NET_BIND_SERVICE if the container binds a privileged port.", ref, containerCount(n, total))
		},
	},
	{
		id:      "k8s.workload.runs-as-root",
		version: "1.2.0",
		title:   "Enforce non-root at the API for %s/%s (runAsNonRoot unset)",
		why:     "A container that does not assert non-root may run as UID 0, so a container escape inherits root on the node instead of an unprivileged user.",
		// Default is MEDIUM (matches the sibling PSS-field-unset checks); the
		// dynamicSeverity below promotes to HIGH only when root is confirmed or
		// near-certain. The static field is the fallback if dynamicSeverity is nil.
		severity:        types.SeverityMedium,
		category:        types.CategorySecurity,
		effort:          types.EffortMedium,
		detect:          detectRunsAsRoot,
		dynamicSeverity: runsAsRootSeverity,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s does not enforce non-root execution at the API in %s: runAsNonRoot is unset and no non-zero runAsUser is set. The container image's USER directive is invisible to a read-only API client, so an unset spec is reported as UNCONFIRMED non-root, never \"runs as root\" — and rated Medium, like the other PSS fields a spec can leave unset. It is rated High only when root is confirmed or near-certain: an explicit runAsUser:0 / runAsNonRoot:false, or a known root-by-default base image with no non-root assertion (each called out per container in the evidence). Set runAsNonRoot:true (and a non-zero runAsUser) on the pod or container securityContext to make non-root intent explicit and admission-enforceable.", ref, containerCount(n, total))
		},
	},
	{
		id:       "k8s.workload.allow-privilege-escalation",
		version:  "1.2.0",
		title:    "Disable privilege escalation for %s/%s",
		why:      "allowPrivilegeEscalation lets a process gain more privileges than its parent (e.g. via setuid binaries), undercutting non-root and capability hardening.",
		severity: types.SeverityMedium,
		category: types.CategorySecurity,
		effort:   types.EffortLow,
		detect:   detectAllowPrivilegeEscalation,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s has %s where allowPrivilegeEscalation is unset (it defaults to true) or explicitly true. Set allowPrivilegeEscalation:false on each container's securityContext — required by the PSS-Restricted profile.", ref, containerCount(n, total))
		},
	},
	{
		id:       "k8s.workload.seccomp-not-enforced",
		version:  "1.2.0",
		title:    "Enforce a seccomp profile on %s/%s",
		why:      "Without a seccomp profile the container can call the full Linux syscall surface, so a kernel-bug exploit has the widest possible reach.",
		severity: types.SeverityMedium,
		category: types.CategorySecurity,
		effort:   types.EffortLow,
		detect:   detectSeccompNotEnforced,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s has %s whose effective seccompProfile is unset or Unconfined (computed pod then container). Set seccompProfile.type:RuntimeDefault at the pod level so every container inherits syscall filtering — required by PSS-Restricted (CIS 5.7.2 maps to 5.2.1 in this benchmark version).", ref, containerCount(n, total))
		},
	},
	{
		id:       "k8s.workload.writable-root-filesystem",
		version:  "1.2.0",
		title:    "Make the root filesystem read-only for %s/%s",
		why:      "A writable root filesystem lets an attacker drop binaries or tamper with the running image; a read-only root forces writes into auditable, scoped volumes.",
		severity: types.SeverityLow, // high-fanout + PSS does NOT require it: Low, never High
		category: types.CategorySecurity,
		effort:   types.EffortMedium,
		detect:   detectWritableRootFilesystem,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s has %s without a read-only root filesystem. Note: PSS does NOT require this (it is a hardening extension, not part of the Baseline or Restricted profile), so this is a Low-severity defense-in-depth suggestion — set readOnlyRootFilesystem:true and mount writable paths as emptyDir/PVC volumes where the app genuinely needs to write.", ref, containerCount(n, total))
		},
	},
	{
		id:       "k8s.namespace.default-namespace-in-use",
		version:  "1.2.0",
		title:    "Move %s/%s out of the default namespace",
		why:      "The default namespace has no PSA labels, NetworkPolicy scope, or resource quotas applied by convention, so anything running there sits outside the namespace-scoped guardrails this report otherwise checks — a governance and blast-radius hygiene gap.",
		severity: types.SeverityLow, // hygiene/governance signal, not a vulnerability
		category: types.CategorySecurity,
		effort:   types.EffortLow,
		detect:   detectDefaultNamespaceInUse,
		description: func(ref string, n, total int) string {
			return fmt.Sprintf("%s runs in the default namespace (CIS 5.7.4). This check flags WORKLOADS in the default namespace; standalone Services/Pods are not evaluated by this check. kubectl cannot move a resource between namespaces in place — recreate it in a dedicated, named namespace (e.g. `kubectl create namespace <name>`, then re-apply the manifest with `metadata.namespace: <name>` and delete the original) so it inherits that namespace's PodSecurity admission, NetworkPolicies, and quotas.", ref)
		},
	},
}

// ---------------------------------------------------------------------------
// PodSecurityAdmissionNotEnforced (§4.4) — the admission-level linchpin.
//
// This is NOT part of the table-driven family: it iterates namespaces (not
// workloads) and emits one finding per namespace. It is the rule that makes the
// per-container checks honest — the per-container checks read the spec as
// authored; this one reads whether the cluster actually enforces a profile.
// ---------------------------------------------------------------------------

// PodSecurityAdmissionNotEnforced flags every non-system namespace that runs
// workloads but does not enforce a PodSecurity admission profile of baseline or
// restricted. PSA is per-namespace via labels
// pod-security.kubernetes.io/<MODE>: <PROFILE> where MODE ∈ enforce/audit/warn
// (only enforce blocks) and PROFILE ∈ privileged/baseline/restricted.
type PodSecurityAdmissionNotEnforced struct{}

func (PodSecurityAdmissionNotEnforced) ID() string { return "k8s.namespace.pss-admission-not-enforced" }

// 1.1.0 (2026-10-21): a namespace that runs only bare Pods, Jobs or CronJobs runs pods too (podTemplates).
func (PodSecurityAdmissionNotEnforced) Version() string { return "1.1.0" }

const (
	psaEnforceLabel = "pod-security.kubernetes.io/enforce"
	psaWarnLabel    = "pod-security.kubernetes.io/warn"
	psaAuditLabel   = "pod-security.kubernetes.io/audit"
)

func (r PodSecurityAdmissionNotEnforced) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Namespaces that actually run workloads (the netpol.go join pattern).
	hasWorkloads := map[string]bool{}
	for _, w := range podTemplates(inv, opts) { // podTemplates() already applies the system-ns filter
		hasWorkloads[w.Namespace] = true
	}

	// DENIAL GUARD (audit finding #1): the namespaces LIST may have been
	// RBAC-denied or timed out, in which case Collect() records "namespaces: …"
	// in Meta.Denied and continues with inv.Namespaces empty. We must NOT read
	// an empty/partial namespace set as "no PSA labels" and emit a confident
	// false positive. namespacesCollected reports whether we can trust label
	// absence; when false, every per-namespace lookup is UNKNOWN, not unset.
	namespacesCollected := psaNamespacesCollected(inv, len(hasWorkloads))

	// Index namespace labels so we can read the PSA labels for each. A namespace
	// present here was OBSERVED (its label set is authoritative). A namespace
	// MISSING here (map miss) was not in our snapshot — distinct from "labels
	// confirmed absent" (audit finding #3).
	labelsByNS := map[string]map[string]string{}
	observed := map[string]bool{}
	for _, ns := range inv.Namespaces {
		labelsByNS[ns.Name] = ns.Labels
		observed[ns.Name] = true
	}

	var flagged []string
	for ns := range hasWorkloads {
		// If we couldn't collect namespaces at all, or this specific namespace
		// object wasn't observed, we cannot read its enforce label — emit an
		// UNKNOWN finding rather than suppress, but never the confident one.
		if !namespacesCollected || !observed[ns] {
			flagged = append(flagged, ns)
			continue
		}
		enforce := strings.ToLower(labelsByNS[ns][psaEnforceLabel])
		// baseline/restricted enforce → cluster blocks unsafe pods → no finding
		// (keep noise down). enforce absent or privileged → flag.
		if enforce == "baseline" || enforce == "restricted" {
			continue
		}
		flagged = append(flagged, ns)
	}
	sort.Strings(flagged) // map iteration is random; findings must be stable

	var out []types.Finding
	for _, ns := range flagged {
		// Classify why we're flagging: confirmed gap, or label set unknown.
		nsUnknown := !namespacesCollected || !observed[ns]
		if nsUnknown {
			out = append(out, r.unknownFinding(ns, namespacesCollected))
			continue
		}
		out = append(out, r.gapFinding(ns, labelsByNS[ns]))
	}
	return out
}

// gapFinding is the confirmed-gap case: the namespace object was observed and
// its enforce label is genuinely absent/privileged. Label presence/absence is
// certain here, so Confidence stays 1.0.
func (r PodSecurityAdmissionNotEnforced) gapFinding(ns string, labels map[string]string) types.Finding {
	enforce := valueOrUnset(labels, psaEnforceLabel)
	warn := valueOrUnset(labels, psaWarnLabel)
	audit := valueOrUnset(labels, psaAuditLabel)

	evidence := []string{
		fmt.Sprintf("namespace %s: enforce=%s, warn=%s, audit=%s — admission does not block any pod", ns, enforce, warn, audit),
	}

	return types.Finding{
		ID:          findingID(r.ID(), "Namespace", "", ns),
		IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: "", Name: ns},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("Enforce a PodSecurity admission profile on namespace %s", ns),
		Description: fmt.Sprintf(
			"Namespace %s runs workloads but does not enforce a PodSecurity admission profile of baseline or restricted (enforce=%s). Without enforcement, the per-container PSS findings in this report describe the spec AS AUTHORED — nothing in the cluster actually blocks a privileged, root, or capability-laden pod from being admitted here. Apply the labels gradually: set warn and audit first to surface what would break, then set enforce. Enforcing restricted on a namespace that already runs noncompliant pods does NOT evict them, but it WILL block the next admission (a redeploy or rollout) — stage it. baseline is the safe first target (it blocks privileged, hostPath, hostNetwork, and host namespaces); however, the per-container findings in this report for this namespace (seccomp, drop-ALL capabilities, allowPrivilegeEscalation, runAsNonRoot) are Restricted-profile controls, so enforce=restricted is required to fully close them — baseline alone will not.",
			ns, enforce),
		WhyItMatters:      "PodSecurity admission is the only thing that turns securityContext hardening from a suggestion into a guarantee — without it, a single noncompliant manifest re-opens every gap the per-container checks flag.",
		Evidence:          evidence,
		Severity:          types.SeverityMedium,
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: ns}},
		EstimatedEffort:   types.EffortLow,
		RemediationCommand: fmt.Sprintf(
			"kubectl label --overwrite namespace %s pod-security.kubernetes.io/warn=baseline pod-security.kubernetes.io/audit=baseline   # surface breakage first, then set enforce=baseline; use restricted (not baseline) on both warn/audit/enforce to close the per-container seccomp/capabilities/runAsNonRoot findings",
			ns),
		Confidence: 1.0, // label presence/absence is certain — namespace was observed
		Provenance: provenance(),
	}
}

// unknownFinding is the not-observed case (audit findings #1 and #3): either the
// namespaces LIST was denied/timed out (collectedAll=false) or this specific
// namespace object was simply absent from the snapshot (collectedAll=true but
// the ns wasn't in inv.Namespaces). In both cases we did NOT read the enforce
// label, so we must say "enforcement status UNKNOWN", never "admission does not
// block any pod", and drop Confidence well below 1.0. This mirrors the netpol
// CNI caveat: the same honesty bar applies when the input itself is missing.
func (r PodSecurityAdmissionNotEnforced) unknownFinding(ns string, collectedAll bool) types.Finding {
	var reason, evDetail string
	if !collectedAll {
		reason = "the namespaces list was denied or timed out during collection (see Meta.Denied / the Methodology section)"
		evDetail = "namespace objects were not collected"
	} else {
		reason = "this namespace object was not present in the collected snapshot (it may have been created mid-collection, or excluded by the collector)"
		evDetail = "namespace object not collected"
	}

	evidence := []string{
		fmt.Sprintf("namespace %s: enforce=<%s>, warn=<%s>, audit=<%s> — PSA labels were NOT read; enforcement status is UNKNOWN, not confirmed-absent", ns, evDetail, evDetail, evDetail),
	}

	return types.Finding{
		ID:          findingID(r.ID(), "Namespace", "", ns),
		IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: "", Name: ns},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("PodSecurity admission for namespace %s not assessed (labels not collected)", ns),
		Description: fmt.Sprintf(
			"Namespace %s runs workloads, but %s, so Shoalcheck could NOT read its pod-security.kubernetes.io/{enforce,warn,audit} labels. This is NOT a finding that admission is unenforced — the enforcement status is UNKNOWN. The namespace may already enforce baseline or restricted; Shoalcheck simply could not observe it. Re-run with a token that can list Namespace objects (cluster-scoped get/list on namespaces), or check manually: `kubectl get namespace %s -o jsonpath='{.metadata.labels}'`. Do not treat this as a confirmed security gap.",
			ns, reason, ns),
		WhyItMatters:      "An audit must never assert observed-absence for a kind it did not collect; reporting UNKNOWN here preserves the report's credibility — a namespace that actually enforces restricted must not be presented as having zero enforcement.",
		Evidence:          evidence,
		Severity:          types.SeverityLow, // informational gap, not a confirmed exposure
		Category:          types.CategorySecurity,
		AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: ns}},
		EstimatedEffort:   types.EffortLow,
		// No RemediationCommand: there is nothing safe to "fix" — the right next
		// step (re-collect / verify) lives in the Description, not a kubectl patch.
		Confidence: 0.2, // candidate needing verification — the label was never read
		Provenance: provenance(),
	}
}

// psaNamespacesCollected reports whether the namespaces LIST succeeded, so a
// missing label can be trusted as "confirmed absent" rather than "never read".
// It is false when Collect() recorded a "namespaces: …" failure in Meta.Denied,
// OR (the cheap fallback for inventories built without Meta — e.g. a partial
// snapshot or a fixture) when no namespaces were collected while workloads exist.
// The kind label "namespaces" matches collect.go's step("namespaces", …).
func psaNamespacesCollected(inv *collect.Inventory, workloadNSCount int) bool {
	for _, d := range inv.Meta.Denied {
		if d == "namespaces" || strings.HasPrefix(d, "namespaces:") {
			return false
		}
	}
	// If Meta explicitly lists "namespaces" as collected, trust it even when the
	// cluster genuinely has zero namespaces in scope.
	for _, c := range inv.Meta.Collected {
		if c == "namespaces" {
			return true
		}
	}
	// Meta is silent (older inventory / fixture). Treat an empty namespace set as
	// "not collected" only when workloads exist — otherwise there is nothing to
	// reconcile and the absence is genuine.
	if len(inv.Namespaces) == 0 && workloadNSCount > 0 {
		return false
	}
	return true
}

// valueOrUnset returns the label value or the literal "<unset>" placeholder used
// in evidence so the reader sees exactly which PSA modes are missing.
func valueOrUnset(labels map[string]string, key string) string {
	if v, ok := labels[key]; ok && v != "" {
		return v
	}
	return "<unset>"
}

// RequiredKinds — The enforcement level lives in namespace labels.
// See deps.go for what belongs in this list.
func (r PodSecurityAdmissionNotEnforced) RequiredKinds() []string {
	return podTemplateKinds("namespaces")
}

// RequiredKinds — Every PSS container check reads pod templates.
// See deps.go for what belongs in this list.
func (c *pssCheck) RequiredKinds() []string { return podTemplateKinds() }
