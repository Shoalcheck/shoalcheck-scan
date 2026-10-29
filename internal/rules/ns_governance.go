package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type NoResourceGovernance struct{}

func (NoResourceGovernance) ID() string      { return "k8s.namespace.no-resource-governance" }
func (NoResourceGovernance) Version() string { return "1.0.0" }

// containerHasRequests reports whether a container declares at least one
// explicit CPU or memory request.
func containerHasRequests(c corev1.Container) bool {
	if _, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
		return true
	}
	if _, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
		return true
	}
	return false
}

// Evaluate flags namespaces hosting more than one long-running workload
// (Deployment/StatefulSet/DaemonSet) with neither a ResourceQuota nor a
// LimitRange. The >1 bar is deliberate: a single-workload namespace gains
// little from quota machinery, but once teams co-locate workloads, nothing
// caps what the namespace can collectively claim against the cluster.
//
// This is an object-presence check. It reports the absence of in-namespace
// ResourceQuota/LimitRange objects; it cannot see governance supplied at
// admission time (mutating webhooks, Kyverno/OPA defaults) — so "no objects"
// is not the same as "ungoverned". The finding carries that caveat and only
// makes the "containers without explicit requests get no safety net" claim
// for the containers that actually omit requests.
func (r NoResourceGovernance) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: if either governance kind wasn't collected (RBAC-denied /
	// timed out), we cannot truthfully assert the objects are absent. Skip
	// rather than emit a false "0 objects" finding.
	if !observed(inv, "resourcequotas") || !observed(inv, "limitranges") {
		return nil
	}

	// Track per-namespace workload count plus the containers that omit an
	// explicit requests block, so the finding reports observed PodSpec facts
	// rather than an unverified causal claim.
	workloadCount := map[string]int{}
	noReqContainers := map[string][]string{} // ns -> ["workload/container", ...]
	for _, w := range workloads(inv, opts) { // workloads() already applies the system-namespace filter
		workloadCount[w.Namespace]++
		for _, c := range w.PodSpec.Containers {
			if !containerHasRequests(c) {
				noReqContainers[w.Namespace] = append(noReqContainers[w.Namespace],
					fmt.Sprintf("%s/%s", w.Name, c.Name))
			}
		}
	}
	quotaCount := map[string]int{}
	for _, q := range inv.ResourceQuotas {
		quotaCount[q.Namespace]++
	}
	lrCount := map[string]int{}
	for _, lr := range inv.LimitRanges {
		lrCount[lr.Namespace]++
	}

	var flagged []string
	for ns, n := range workloadCount {
		if n > 1 && quotaCount[ns] == 0 && lrCount[ns] == 0 {
			flagged = append(flagged, ns)
		}
	}
	sort.Strings(flagged) // stable finding order across runs

	var out []types.Finding
	for _, ns := range flagged {
		noReq := noReqContainers[ns]
		sort.Strings(noReq)

		// Description states only what was observed. The per-container
		// safety-net consequence is asserted conditionally and only when
		// containers actually omit requests.
		desc := fmt.Sprintf(
			"Namespace %s runs %d long-running workloads (Deployments/StatefulSets/DaemonSets) with no ResourceQuota and no LimitRange object. There is no namespace-level cap on how much CPU or memory the namespace can claim against the cluster, and no LimitRange to supply default per-container requests.",
			ns, workloadCount[ns])
		if len(noReq) > 0 {
			desc += fmt.Sprintf(
				" %s here also declare no explicit CPU/memory requests, so without a LimitRange defaultRequest they schedule as BestEffort and have no per-pod floor.", nWord(len(noReq), "container", "containers"))
		} else {
			desc += " Every observed container already sets explicit requests, so the per-pod gap is limited to the absence of a namespace cap and a default-request safety net for future workloads."
		}
		desc += " Note: this is an object-presence check — defaults injected at admission time by a mutating webhook or policy engine (Kyverno, OPA/Gatekeeper) are not visible to a read-only scan and may already govern this namespace; verify before acting."

		evidence := []string{
			fmt.Sprintf("namespace %s: %d long-running workloads counted (Deployments/StatefulSets/DaemonSets; Jobs/CronJobs/bare Pods are not counted)", ns, workloadCount[ns]),
			fmt.Sprintf("namespace %s: 0 ResourceQuota objects observed", ns),
			fmt.Sprintf("namespace %s: 0 LimitRange objects observed", ns),
		}
		if len(noReq) > 0 {
			evidence = append(evidence, fmt.Sprintf(
				"containers with no explicit requests: %s", joinCapped(noReq, 8)))
		} else {
			evidence = append(evidence, "all observed containers in this namespace declare explicit CPU/memory requests")
		}
		evidence = append(evidence, "admission/policy-engine-injected defaults (Kyverno, OPA, mutating webhooks) are not observable in a read-only scan and may already govern this namespace")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Namespace", "", ns),
			IDBasis:     &types.ResourceRef{Kind: "Namespace", Namespace: "", Name: ns},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Add resource governance to namespace %s", ns),
			Description: desc,
			// Attribute each lever to the object that actually delivers it:
			// a ResourceQuota caps the namespace's aggregate claim (blast-radius
			// across namespaces / capacity planning); a LimitRange supplies the
			// per-container default requests/limits that are the actual
			// anti-starvation control. Neither, by itself, stops one pod from
			// starving a neighbour — that is governed by per-pod requests/limits
			// and QoS class.
			WhyItMatters: "A ResourceQuota caps the namespace's total claim against the cluster (capacity planning and blast-radius across namespaces); a LimitRange supplies the per-container default requests that keep pods out of BestEffort. With neither, a co-located namespace has no aggregate ceiling and no default-request safety net.",
			Evidence:     evidence,
			// Severity (policy ladder): Config-hygiene gap with no active
			// compromise, outage, or direct cost — Low.
			Severity:          types.SeverityLow,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "Namespace", Name: ns}},
			EstimatedEffort:   types.EffortLow,
			RemediationYAML: fmt.Sprintf(
				"apiVersion: v1\nkind: LimitRange\nmetadata:\n  name: default-limits\n  namespace: %s\nspec:\n  limits:\n    - type: Container\n      defaultRequest:   # starting point — right-size from usage before applying\n        cpu: 100m\n        memory: 128Mi\n      default:          # starting point — right-size from usage before applying\n        cpu: 500m\n        memory: 512Mi\n",
				ns),
			// Confidence reflects what is genuinely certain: the ResourceQuota
			// and LimitRange OBJECTS are absent (no estimation). It is NOT a
			// claim that the namespace is definitely ungoverned — admission-time
			// defaults are invisible here — so it is held below 1.0.
			Confidence: 0.9,
			Provenance: provenance(),
		})
	}
	return out
}

// joinCapped joins items with ", ", truncating to at most n entries with a
// "(+k more)" suffix so Evidence stays readable on busy namespaces.
func joinCapped(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

// RequiredKinds — Both governance objects are the finding; either list denied and the rule reports absence it never saw.
// See deps.go for what belongs in this list.
func (r NoResourceGovernance) RequiredKinds() []string {
	return withWorkloads("limitranges", "resourcequotas")
}
