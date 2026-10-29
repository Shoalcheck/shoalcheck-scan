package collect

import (
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// policy_posture.go — projecting the policy shape the Inventory already holds onto the report.
//
// Spec: `docs/superpowers/specs/2026-08-28-fleet-divergence-design.md` §2.3. Every dimension here was
// already read by the collector and already consumed by a rule; what was missing was carrying it out of the
// run. The Inventory goes out of scope when Run returns, so anything a later surface needs has to leave
// through the report or not at all.
//
// THE READ FLAGS ARE THE POINT. Each dimension pairs its value with whether the list behind it was
// confirmed read, because an empty value has two meanings and only Meta tells them apart. This is
// collect.Observed's discipline, moved into the schema so a consumer three packages away cannot lose it —
// which is exactly what a findings-derived comparison would do.

// PSA label keys, exactly as Kubernetes defines them. Read as data, never interpreted: a value of
// "restricted" is recorded as the string the namespace carries, and whether that is the right level for
// that namespace is not a question this projection answers.
const (
	psaEnforceLabel = "pod-security.kubernetes.io/enforce"
	psaAuditLabel   = "pod-security.kubernetes.io/audit"
	psaWarnLabel    = "pod-security.kubernetes.io/warn"
)

// buildPolicyPosture projects the readable policy shape of this cluster.
func buildPolicyPosture(inv *Inventory) *types.PolicyPosture {
	nsRead := Observed(inv, "namespaces")
	npRead := Observed(inv, "networkpolicies")
	rqRead := Observed(inv, "resourcequotas")
	lrRead := Observed(inv, "limitranges")

	npByNS := map[string]int{}
	for i := range inv.NetworkPolicies {
		npByNS[inv.NetworkPolicies[i].Namespace]++
	}
	rqByNS := map[string]int{}
	for i := range inv.ResourceQuotas {
		rqByNS[inv.ResourceQuotas[i].Namespace]++
	}
	lrByNS := map[string]int{}
	for i := range inv.LimitRanges {
		lrByNS[inv.LimitRanges[i].Namespace]++
	}

	pp := &types.PolicyPosture{OperatorsRead: Observed(inv, "server-resources")}

	// A NAMESPACE LIST THAT WAS NOT READ PRODUCES NO NAMESPACE ROWS AT ALL, rather than rows with every
	// flag false. A row would assert that the namespace exists, which is the one thing a refused list
	// cannot tell us — and the divergence surface treats "exists in one cluster and not the other" as a
	// membership difference, so a fabricated row would become a fabricated membership claim.
	if nsRead {
		for i := range inv.Namespaces {
			ns := &inv.Namespaces[i]
			pp.Namespaces = append(pp.Namespaces, types.NamespacePosture{
				Name: ns.Name,
				PodSecurity: types.PodSecurityLabels{
					Enforce: ns.Labels[psaEnforceLabel],
					Audit:   ns.Labels[psaAuditLabel],
					Warn:    ns.Labels[psaWarnLabel],
				},
				// The labels ride on the Namespace object itself, so their readability IS the namespace
				// list's readability — there is no second call to be refused.
				PodSecurityRead:     true,
				NetworkPolicies:     npByNS[ns.Name],
				NetworkPoliciesRead: npRead,
				ResourceQuotas:      rqByNS[ns.Name],
				ResourceQuotasRead:  rqRead,
				LimitRanges:         lrByNS[ns.Name],
				LimitRangesRead:     lrRead,
			})
		}
		sort.Slice(pp.Namespaces, func(i, j int) bool { return pp.Namespaces[i].Name < pp.Namespaces[j].Name })
	}

	if pp.OperatorsRead {
		seen := map[string]bool{}
		for gvr := range inv.PresentGVRs {
			// GROUP ONLY, NEVER THE VERSION — a fleet mid-way through an operator upgrade serves v1 on one
			// cluster and v1beta1 on another, and calling that a policy divergence would make a routine
			// rollout look like a governance problem.
			//
			// And KUBERNETES' OWN GROUPS are excluded, from the closed list in internal/types rather than
			// from a suffix test. `""` plus `*.k8s.io` misses exactly the bare-word groups — apps, batch,
			// policy, autoscaling, extensions — and a real two-cluster fleet comparison then printed
			// "operators.installed: apps, autoscaling, batch, policy" for a docker-desktop with no operator
			// on it. A fleet row is a sentence a reader acts on; that one reported Kubernetes as somebody's
			// operator. The same list is what keeps the redactor from rewriting the word "apps".
			g := gvr.Group
			if types.KubernetesOwnGroup(g) || strings.HasSuffix(g, ".k8s.io") {
				continue
			}
			seen[g] = true
		}
		for g := range seen {
			pp.Operators = append(pp.Operators, g)
		}
		sort.Strings(pp.Operators)
	}

	// A posture with nothing readable in it is nil rather than an empty struct. An empty struct serialises
	// as a present-but-blank projection, which reads downstream as "we looked and there is no policy" — the
	// absence-as-fact defect, in the one type built to prevent it.
	if len(pp.Namespaces) == 0 && !pp.OperatorsRead {
		return nil
	}
	return pp
}
