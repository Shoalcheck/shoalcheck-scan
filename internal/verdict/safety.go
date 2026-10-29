package verdict

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// SafetyClass is how safe a finding's remediation would be to apply.
//
// It is a SEPARATE axis from types.Finding.Confidence, and keeping them separate is a
// requirement rather than a preference. Confidence means problem-certainty: how sure the rule
// is that the problem is real. Safety means blast radius: what happens to the cluster if
// someone applies the fix. A finding can be certain and dangerous (a ClusterRoleBinding is
// definitely over-privileged; removing it at 3pm may lock out the deploy pipeline) or
// uncertain and harmless. Any code that reads Confidence to decide safety is a bug — see
// the honesty policy and TestSafety_IgnoresConfidence.
type SafetyClass string

const (
	// SafeNow — a remediation exists and applying it neither restarts nor disconnects
	// anything. Only these may be offered as "start here", and only these are eligible for
	// EPIC 2's closed loop.
	SafeNow SafetyClass = "safe-now"

	// NeedsReview — a remediation exists, but applying it restarts workloads, changes replica
	// counts, or alters what can reach what.
	NeedsReview SafetyClass = "needs-review"

	// Manual — no remediation to apply, or one that is a hedged suggestion rather than a
	// change.
	Manual SafetyClass = "manual"
)

// additiveYAMLMarkers are the remediation shapes that genuinely do not touch a running pod.
//
// The list is short on purpose, and it shrank once the live podium was read. It originally
// included "resources:" and "requests:" — the rightsizing shape, the product's flagship fix —
// which looks additive in YAML and is not: editing container resources edits the Deployment's
// pod template, which creates a new ReplicaSet and rolls every pod. See B-008.
//
// The wider fact behind the shortness: almost nothing in Kubernetes is restart-free. Resources,
// probes, security contexts and images all live in the pod template; scaling adds pods;
// NetworkPolicy changes reachability; a PodDisruptionBudget changes drain behaviour. What
// survives here are namespace-scoped objects that constrain future pods without disturbing
// current ones.
// docSeparator matches a YAML document break at the start of a line, so "---" inside a comment or a
// quoted string does not split a manifest in two.
var docSeparator = regexp.MustCompile(`(?m)^---[ \t]*$`)

// kindLine reads a document's own top-level kind. Anchored to the line start so a nested `kind:`
// (a LimitRange's `- type: Container`, a CRD's schema) cannot answer for the document.
var kindLine = regexp.MustCompile(`(?m)^kind:[ \t]*(.+?)[ \t]*$`)

var additiveYAMLMarkers = []string{
	"kind: LimitRange",
	"kind: ResourceQuota",
}

// podTemplateMarkers appear in remediations that edit a workload's pod template. Applying one
// is a rolling restart — controlled and ordinary, but a restart, and the product may not
// describe it as "additive".
var podTemplateMarkers = []string{
	"spec:\n  template:", "template:\n    spec:", "containers:",
	"resources:", "requests:", "limits:",
	"livenessprobe:", "readinessprobe:", "startupprobe:",
	"securitycontext:", "image:", "env:", "volumemounts:",
}

// mutatingCommandVerbs act on live objects in ways that remove, replace or reroute something. Any
// of these anywhere in a remediation command disqualifies SafeNow outright, whatever the
// accompanying YAML looks like.
//
// `scale` is deliberately NOT here: scaling is the one mutating verb whose direction decides its
// safety, and the direction is only knowable against the target's current replica count. See
// scaleUpOnly.
var mutatingCommandVerbs = []string{
	" delete ", " patch ", " edit ", " replace ", " rollout ", " drain ",
	" cordon ", " uncordon ", " taint ", " set ", " create ", " apply ", " evict ",
}

// thirdPerson is a command verb as the sentence needs it: "patches", "deletes", "applies" — not "patchs".
func thirdPerson(v string) string {
	switch {
	case strings.HasSuffix(v, "ch"), strings.HasSuffix(v, "sh"), strings.HasSuffix(v, "s"), strings.HasSuffix(v, "x"):
		return v + "es"
	case strings.HasSuffix(v, "y") && len(v) > 1 && !strings.ContainsRune("aeiou", rune(v[len(v)-2])):
		return v[:len(v)-1] + "ies"
	}
	return v + "s"
}

// ReplicaLookup answers the current replica count for an affected resource. It exists because
// safety is a property of the pair (remediation × target workload), not of the remediation text:
// `--replicas=2` adds a pod to a 1-replica Deployment and removes three from a 5-replica one.
//
// found=false means "not known" — the Architecture this is usually built from is trimmed per
// namespace — and an unknown count may never license a safety claim.
type ReplicaLookup func(ref types.ResourceRef) (replicas int, found bool)

// scaleTarget matches `--replicas=N` and `--replicas N` in a remediation command.
var scaleTarget = regexp.MustCompile(`--replicas[= ]([0-9]+)`)

// scaleUpOnly reports whether a command is a scale that RAISES the replica count for every
// affected resource, which makes it additive: a new pod appears, the running pods are untouched,
// the blast radius is one workload, and the undo is the same command with the old number.
//
// Every branch that cannot establish that returns false. A scale whose direction is unknown, whose
// targets are not all known, or that lowers any count, is not additive.
func scaleUpOnly(f types.Finding, cmd string, replicas ReplicaLookup) bool {
	if replicas == nil || len(f.AffectedResources) == 0 {
		return false
	}
	m := scaleTarget.FindStringSubmatch(cmd)
	if m == nil {
		return false
	}
	want, err := strconv.Atoi(m[1])
	if err != nil {
		return false
	}
	for _, ref := range f.AffectedResources {
		if !scalableKinds[ref.Kind] {
			return false
		}
		current, found := replicas(ref)
		if !found || want <= current {
			return false
		}
	}
	return true
}

// conditionalMarkers appear in a finding that says of ITSELF that it may not apply — "add a
// default-deny if its CNI enforces policy". Such a finding is honest and stays in the report, but it
// cannot be what a client is told to do first, and it is never SafeNow: "safe" would be a claim
// about a change we are not sure is needed. Scanned across the finding's own prose.
var conditionalMarkers = []string{
	" if its ", " if the ", "may not ", "if applicable", "consider ", "if your ",
}

// preconditionMarkers appear in a REMEDIATION that asks a human to check something before applying
// it — "# verify the app supports >1 replica before scaling a StatefulSet". A remediation with a
// precondition is an instruction, not a mechanical fix.
//
// These are scanned ONLY in the remediation, and the distinction is load-bearing: "ensure the
// workload has two replicas" is how rules phrase a RECOMMENDATION in their description, and
// treating that as a hedge pushed ordinary findings to Manual (B-013).
var preconditionMarkers = []string{
	"verify ", "confirm ", "check that ", "make sure ", "before scaling", "ensure the app",
	// "starting point" and "before applying" were added when the LimitRange kind fix landed, and
	// they close the slip THIS comment predicted. The governance rule hands over a LimitRange whose
	// own body reads "# starting point — right-size from usage before applying": a manifest asking
	// the operator to work the numbers out first. While every LimitRange was misclassified as a
	// pod-template edit that text cost nothing, because NeedsReview caught it for the wrong reason.
	// Judging documents by kind removed that accident and would have promoted it to the safest
	// place to begin — offering as a mechanical fix the one thing the rule says not to apply blind.
	"starting point", "before applying",
	// Several rules deliberately hand over a manifest whose values are placeholders, because the
	// honesty policy forbids printing numbers the audit did not measure — the
	// missing-resource-requests rule says so in as many words: "PLACEHOLDER — DO NOT apply blind:
	// these are not measured values". Offering one of those as the safest place to begin would
	// invite the operator to apply exactly the change the rule warned them off.
	//
	// This was true already on the live testbed, but only because every placeholder remediation
	// happens to be a pod-template edit that NeedsReview catches for an unrelated reason. A future
	// rule with an additive placeholder would have slipped straight through.
	"placeholder", "do not apply", "not measured",
}

// scalableKinds are the workload kinds where raising the replica count is genuinely additive: a
// new interchangeable pod appears and the running ones are untouched.
//
// StatefulSets are excluded deliberately. Their pods are ordered and identity-bearing, and a second
// replica frequently needs quorum or peer configuration to be CORRECT — the real AKS report offered
// exactly this trap, a 1→2 scale of an Alertmanager StatefulSet whose own remediation text warned
// "verify the app supports >1 replica (replication/quorum) before scaling a StatefulSet". A
// DaemonSet has no replica count to raise at all.
var scalableKinds = map[string]bool{
	"Deployment": true,
	"ReplicaSet": true,
}

// Classify assigns a SafetyClass with no cluster context. Equivalent to ClassifyWith(f, nil):
// every scale is treated as direction-unknown and therefore not additive.
func Classify(f types.Finding) SafetyClass { return ClassifyWith(f, nil) }

// ClassifyWith assigns a SafetyClass from what the finding carries plus what the cluster's shape
// says about its targets.
//
// The order of these checks is the design: SafeNow is the last and narrowest outcome, reached only
// by positive evidence. Everything unrecognised stops at NeedsReview.
//
// What SafeNow means, precisely: the change ADDS something without touching a running pod, its
// blast radius is one bounded set of objects, and undoing it is a single step. It does not mean
// "harmless" and it does not mean "free" — a scale-up costs money — it means nothing already
// serving traffic is disturbed by applying it.
// ClassifyReason returns the class and, when the class is NeedsReview, the reason in words a person
// can act on.
//
// The reason exists because the closed loop covers reviewed changes, not only additive ones. Naming
// the disruption is the price of that: "applying this restarts every pod in the workload" is what
// makes a reviewed change reviewable, and it has to come from the same evidence that decided the
// class rather than from a sentence somebody wrote once. A SafeNow finding disturbs nothing and
// returns no reason — a handoff that invents a disruption it does not have is as misleading as one
// that hides the one it does.
func ClassifyReason(f types.Finding) (SafetyClass, string) {
	return classify(f, nil)
}

func ClassifyWith(f types.Finding, replicas ReplicaLookup) SafetyClass {
	c, _ := classify(f, replicas)
	return c
}

func classify(f types.Finding, replicas ReplicaLookup) (SafetyClass, string) {
	yaml, cmd := f.RemediationYAML, f.RemediationCommand
	if strings.TrimSpace(yaml+cmd) == "" {
		return Manual, ""
	}
	if isHedged(f) {
		return Manual, ""
	}

	// A command that removes, replaces or reroutes something can never be SafeNow. Padded with
	// spaces so a workload called "patcher" does not read as the verb `patch`; the command is
	// padded too so a verb at either end still matches.
	run := executable(cmd)
	padded := " " + strings.ToLower(strings.Join(strings.Fields(run), " ")) + " "

	// A COMMAND THAT ONLY LOOKS IS NOT A CHANGE. Checked before everything else, because a read
	// matches no mutating verb and would otherwise fall through to "unrecognised" — which the loop
	// then offers as a reviewed change whose effect "was not established". Applying a grep does
	// nothing, and describing a read as a fix is worse than declining to describe it.
	//
	// Found on the live testbed: privileged-host-access ships
	// `kubectl get daemonset … -o yaml | grep -nE 'privileged|hostNetwork'`, an investigation the
	// operator is meant to run before deciding anything.
	if isReadOnlyCommand(padded) && strings.TrimSpace(yaml) == "" {
		return Manual, ""
	}

	// A LABEL CHANGE IS CHARACTERISED rather than shrugged at. Also before the mutating verbs, since
	// `label` is not one of them and this would otherwise land in "unrecognised" too.
	if strings.TrimSpace(yaml) == "" && strings.Contains(padded, " label ") {
		return NeedsReview, labelDisruption(padded)
	}

	for _, v := range mutatingCommandVerbs {
		if strings.Contains(padded, v) {
			return NeedsReview, "the command " + thirdPerson(strings.TrimSpace(v)) + " something: applying it removes, " +
				"replaces or reroutes an object rather than adding one."
		}
	}

	// A scale-up is additive; a scale-down, or a scale whose direction cannot be established, is
	// not. Checked after the denials above so a scale bundled with a delete is judged by the delete.
	if strings.Contains(padded, " scale ") || scaleTarget.MatchString(run) {
		if scaleUpOnly(f, run, replicas) {
			return SafeNow, ""
		}
		return NeedsReview, "this changes a replica count, and the direction could not be established " +
			"as upward only — scaling down removes running pods."
	}

	// JUDGED PER DOCUMENT, BY KIND.
	//
	// The rule this keeps is the old one: a remediation that bundles a LimitRange with a container
	// resources block is judged by its disruptive half. What it drops is the way that rule was
	// implemented — a substring scan across the whole remediation — because `limits:` is a
	// LimitRange's OWN top-level spec key, so every LimitRange convicted itself of being a pod
	// template. Measured on the live testbed: 112 findings, safe-now=0, with the one rule whose
	// remediation IS a LimitRange demoted by that marker while isHedged said false. The single shape
	// the closed loop is built for was the one shape it could never reach.
	//
	// So each YAML document is judged on its own: an allowlisted kind is additive and its own
	// vocabulary is not searched for pod-template markers; anything else is searched, and one
	// disruptive document decides the whole remediation.
	docs := yamlDocuments(yaml)
	if len(docs) == 0 {
		return NeedsReview, "the remediation is not a manifest this audit recognises, so what applying it " +
			"does was not established."
	}
	additive := 0
	for _, doc := range docs {
		if isAdditiveKind(doc) {
			additive++
			continue
		}
		low := strings.ToLower(doc)
		for _, m := range podTemplateMarkers {
			if strings.Contains(low, strings.ToLower(m)) {
				return NeedsReview, podTemplateDisruption(m)
			}
		}
	}
	// Earned, not assumed: EVERY document must be a shape we have positively decided leaves running
	// pods alone. A remediation that is partly unrecognised is not safe because the rest of it is.
	if additive == len(docs) {
		return SafeNow, ""
	}
	return NeedsReview, "part of this remediation is a shape this audit has not positively decided leaves " +
		"running pods alone, so it is treated as though it does not."
}

// readOnlyVerbs are kubectl subcommands that only read. A remediation made of these is an
// investigation, not a change.
var readOnlyVerbs = []string{" get ", " describe ", " logs ", " top ", " explain ", " diff ", " api-resources ", " version "}

// isReadOnlyCommand reports whether every kubectl invocation in the command only reads. A pipeline
// is judged by ALL of its stages: `get … | grep` is a read, but `get … | kubectl apply -f -` is not,
// and treating the first stage as the whole command would wave the second one through.
func isReadOnlyCommand(padded string) bool {
	if !strings.Contains(padded, "kubectl") {
		return false
	}
	sawRead := false
	for _, stage := range strings.Split(padded, "|") {
		st := " " + strings.TrimSpace(stage) + " "
		if !strings.Contains(st, "kubectl") {
			continue // grep, jq, awk — they cannot change a cluster
		}
		read := false
		for _, v := range readOnlyVerbs {
			if strings.Contains(st, v) {
				read = true
				break
			}
		}
		if !read {
			return false
		}
		sawRead = true
	}
	return sawRead
}

// labelDisruption describes a label change in terms of what it does and does not do. The Pod
// Security levels are the case that matters: warn and audit never reject a pod, enforce does, and
// collapsing the three into one sentence would either overstate or understate every use.
func labelDisruption(padded string) string {
	base := "this changes labels on the target"
	if strings.Contains(padded, "--overwrite") {
		base += ", replacing any value already there"
	}
	switch {
	case strings.Contains(padded, "pod-security.kubernetes.io/enforce"):
		return base + ". The enforce level REJECTS pods that violate it, so a workload that cannot " +
			"meet the level will fail to start on its next rollout — nothing running stops today."
	case strings.Contains(padded, "pod-security.kubernetes.io/warn"),
		strings.Contains(padded, "pod-security.kubernetes.io/audit"):
		return base + ". The warn and audit levels only report — no pod is ever rejected by them — so " +
			"nothing running is disturbed and nothing future is blocked."
	}
	return base + ". Nothing restarts, but anything selecting on these labels — Services, " +
		"NetworkPolicies, scheduling rules — may match differently afterwards."
}

// podTemplateDisruption turns the marker that decided the class into the sentence a reviewer needs.
// Different markers mean different disruptions, and collapsing them into one line would tell a
// NetworkPolicy change that it restarts pods.
func podTemplateDisruption(marker string) string {
	m := strings.ToLower(marker)
	switch {
	case strings.Contains(m, "networkpolicy"):
		return "this changes which workloads can reach which — nothing restarts, but traffic that flows " +
			"today may stop."
	case strings.Contains(m, "poddisruptionbudget"):
		return "this changes how many pods may be unavailable at once, which changes what a node drain " +
			"is allowed to do."
	case strings.Contains(m, "replicas"):
		return "this changes the replica count, which adds or removes running pods."
	default:
		return "this edits the workload's pod template, so applying it rolls every pod in the workload — " +
			"an ordinary rolling restart, but a restart."
	}
}

// yamlDocuments splits a remediation on the document separator, dropping empties. A separator only
// counts at the start of a line, so "---" inside a string or a comment does not split anything.
func yamlDocuments(yaml string) []string {
	var out []string
	for _, d := range docSeparator.Split(yaml, -1) {
		if strings.TrimSpace(d) != "" {
			out = append(out, d)
		}
	}
	return out
}

// isAdditiveKind reports whether a single document declares one of the kinds we have positively
// decided leaves running pods alone. The KIND line is authoritative: a Deployment that merely
// mentions a LimitRange in a comment is still a Deployment.
func isAdditiveKind(doc string) bool {
	m := kindLine.FindStringSubmatch(doc)
	if m == nil {
		return false
	}
	kind := strings.TrimSpace(strings.Trim(m[1], `"'`))
	for _, a := range additiveYAMLMarkers {
		if strings.EqualFold(kind, strings.TrimSpace(strings.TrimPrefix(a, "kind:"))) {
			return true
		}
	}
	return false
}

// mayNotApply reports whether the finding's own prose says it may not apply — "add a default-deny if its CNI
// enforces policy". This is what RANKING asks: a remedy that needs a person (a placeholder, "verify first") makes a
// change unsafe to apply blind, and says nothing about whether the problem is real. The final review found the
// reading's only critical ranked below every low and info because its least-privilege manifest had a placeholder.
func mayNotApply(f types.Finding) bool {
	prose := strings.ToLower(f.Title + " " + f.Description + " " + f.WhyItMatters)
	for _, m := range conditionalMarkers {
		if strings.Contains(prose, m) {
			return true
		}
	}
	return false
}

// isHedged reports whether the finding says it may not apply, or its remediation asks the operator
// to check something first. Two different questions over two different text regions — see
// conditionalMarkers and preconditionMarkers.
func isHedged(f types.Finding) bool {
	prose := strings.ToLower(f.Title + " " + f.Description + " " + f.WhyItMatters)
	for _, m := range conditionalMarkers {
		if strings.Contains(prose, m) {
			return true
		}
	}
	remediation := strings.ToLower(f.RemediationYAML + " " + f.RemediationCommand)
	for _, m := range preconditionMarkers {
		if strings.Contains(remediation, m) {
			return true
		}
	}
	return false
}

// executable strips comment text from a remediation command, leaving only what would actually run.
//
// Operation verbs are only meaningful here. Scanning the comments for them matched " drain " inside
// the explanatory line "a minAvailable equal to the replica count deadlocks every node drain" and
// demoted a provable 1→2 scale-up — which on the real AKS report took safe-now from 14 to 0 and had
// the product announce "no mechanically safe starting point" for a cluster with 56 provable ones
// (B-013). Preconditions are the mirror image and are read from the FULL text, comments included,
// because that is where rule authors write them.
func executable(cmd string) string {
	var b strings.Builder
	for _, line := range strings.Split(cmd, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
