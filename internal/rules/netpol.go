package rules

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type NoNetworkPolicy struct{}

func (NoNetworkPolicy) ID() string      { return "k8s.namespace.no-network-policy" }
func (NoNetworkPolicy) Version() string { return "1.0.0" }

// cniPosture summarises what we can infer about the cluster's NetworkPolicy
// enforcement from the DaemonSets we collected. It is deliberately a local,
// read-only heuristic (mirroring the name-prefix matching in
// collect/stack.go) so this rule owns its own reasoning without importing the
// unexported detectStack helper.
type cniPosture struct {
	name             string // human-readable CNI name, "" if unknown
	policyCapableCNI bool   // a CNI that natively enforces NetworkPolicy or ships its own policy CRDs (Cilium/Calico/Weave)
	enforcesUpstream bool   // detected CNI is known to enforce upstream networking.k8s.io NetworkPolicy without an extra add-on
	usesOwnCRDs      bool   // detected CNI commonly carries segmentation in its OWN CRDs (Cilium/Calico) that we do not read
	vpcCNINoAgent    bool   // AWS VPC CNI detected and NO separate policy agent (Calico/Cilium) present → NetworkPolicy silently ignored
}

// detectCNIPosture classifies the cluster CNI from collected DaemonSet names.
// We match on the same well-known DaemonSet name prefixes collect/stack.go
// uses (aws-node, cilium, calico-node, kube-flannel, weave-net) — these are
// the agents that ship as one pod per node, which is exactly what we have in
// inv.DaemonSets.
func detectCNIPosture(inv *collect.Inventory) cniPosture {
	has := func(prefixes ...string) bool {
		for _, ds := range inv.DaemonSets {
			n := strings.ToLower(ds.Name)
			for _, p := range prefixes {
				if strings.HasPrefix(n, p) {
					return true
				}
			}
		}
		return false
	}

	cilium := has("cilium")
	calico := has("calico-node")
	weave := has("weave-net")
	flannel := has("kube-flannel")
	awsVPC := has("aws-node")

	switch {
	case cilium:
		// Cilium enforces upstream NetworkPolicy AND adds its own CRDs; teams
		// very often write segmentation only as CiliumNetworkPolicy, which we
		// do not read.
		return cniPosture{name: "Cilium", policyCapableCNI: true, enforcesUpstream: true, usesOwnCRDs: true}
	case calico:
		return cniPosture{name: "Calico", policyCapableCNI: true, enforcesUpstream: true, usesOwnCRDs: true}
	case weave:
		// Weave Net enforces upstream NetworkPolicy; no widely-used policy CRD.
		return cniPosture{name: "Weave Net", policyCapableCNI: true, enforcesUpstream: true}
	case awsVPC:
		// AWS VPC CNI does NOT enforce NetworkPolicy on its own. If a separate
		// policy agent (Calico/Cilium) were present we'd have matched it above,
		// so reaching here means the stock VPC CNI with no policy controller
		// detectable from DaemonSets: an applied NetworkPolicy is silently
		// ignored.
		return cniPosture{name: "AWS VPC CNI", vpcCNINoAgent: true}
	case flannel:
		// Flannel has no built-in NetworkPolicy enforcement.
		return cniPosture{name: "Flannel"}
	default:
		return cniPosture{}
	}
}

// Evaluate flags namespaces that run workloads but define zero upstream
// (networking.k8s.io/v1) NetworkPolicy objects. Kubernetes' default in that
// case is allow-all pod-to-pod IF the cluster CNI enforces NetworkPolicy at
// all. One finding per namespace, not per workload: the fix (a default-deny
// policy) is namespace-scoped.
//
// Honesty guards (see docs/research/2026-06-16-rule-honesty-audit.md):
//   - DENIAL GUARD: if the NetworkPolicy LIST did not succeed, we cannot see
//     the policies and must not claim "zero". We emit one informational,
//     confidence-0 "not assessed" finding instead of one false positive per
//     namespace.
//   - CNI-AWARE: enforcement and remediation efficacy depend on the CNI.
//     Cilium/Calico may segment via their own CRDs we don't read (soften +
//     lower confidence); AWS VPC CNI with no policy agent silently ignores
//     NetworkPolicy entirely (warn loudly + lower confidence).
//   - CONDITIONAL HEADLINE: Title/WhyItMatters phrase the lateral-movement
//     risk conditionally so the executive view doesn't assert enforcement as
//     guaranteed.
func (r NoNetworkPolicy) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	workloadCount := map[string]int{}
	for _, w := range workloads(inv, opts) { // workloads() already applies the system-namespace filter
		workloadCount[w.Namespace]++
	}
	if len(workloadCount) == 0 {
		return nil
	}

	// DENIAL GUARD — never assert observed-absence on a list we couldn't read.
	if !observed(inv, "networkpolicies") {
		return []types.Finding{{
			ID:           findingID(r.ID(), "Cluster", "", "networkpolicy-not-assessed"),
			IDBasis:      &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "networkpolicy-not-assessed"},
			RuleID:       r.ID(),
			RuleVersion:  r.Version(),
			Title:        "NetworkPolicy posture not assessed — list access unavailable",
			Description:  "Shoalcheck could not list networking.k8s.io/v1 NetworkPolicy objects (the list call was denied by RBAC or timed out — see the Methodology section's collection status). Because the objects were never observed, this audit cannot say whether namespaces are segmented or run flat allow-all. No per-namespace NetworkPolicy finding is emitted; grant read access to NetworkPolicies (networking.k8s.io, verb list) and re-run to assess this.",
			WhyItMatters: "Network segmentation is a real control, but a read-only audit can only report what it observed. Asserting 'zero NetworkPolicies' from a denied list would be a fabricated finding.",
			Evidence: []string{
				"networking.k8s.io/v1 NetworkPolicy list was not collected (absent from Meta.Collected / present in Meta.Denied)",
				fmt.Sprintf("%s could not be assessed for NetworkPolicy coverage", nWord(len(workloadCount), "workload-bearing namespace", "workload-bearing namespaces")),
			},
			Severity:          types.SeverityInfo,
			Category:          types.CategorySecurity,
			AffectedResources: []types.ResourceRef{{Kind: "Cluster"}},
			EstimatedEffort:   types.EffortLow, // the "fix" is granting read access + re-running
			Confidence:        0.0,             // we observed nothing; this is a coverage gap, not a problem we are certain of
			Provenance:        provenance(),
		}}
	}

	netpolCount := map[string]int{}
	for _, np := range inv.NetworkPolicies {
		netpolCount[np.Namespace]++
	}

	var flagged []string
	for ns := range workloadCount {
		if netpolCount[ns] == 0 {
			flagged = append(flagged, ns)
		}
	}
	sort.Strings(flagged) // map iteration is random; findings must be ordered stably

	cni := detectCNIPosture(inv)
	crdPerNS, crdClusterWide, crdOK := crdPolicyCounts(inv, cni)

	var out []types.Finding
	for _, ns := range flagged {
		// CRD-aware suppression: if Cilium/Calico CRDs were actually listed and
		// this namespace (or a cluster-wide policy) segments it, the
		// upstream-netpol finding was a false positive — suppress it.
		if crdOK && (crdPerNS[ns] > 0 || crdClusterWide > 0) {
			continue
		}
		out = append(out, r.findingForCRDAware(ns, workloadCount[ns], cni, crdOK, crdPerNS[ns], crdClusterWide))
	}
	return out
}

// crdPolicyCounts returns per-namespace + cluster-wide policy counts for the
// detected own-CRD CNI (Cilium/Calico), reading inv.StackObjects directly (the
// Phase-3 dynamic reads). ok=false when the CNI's CRDs were not present or the
// list did not succeed — the caller then keeps the legacy 0.45 fallback. The
// rules package must NOT import internal/analyzers (keep the leaf shape), so the
// CRD counting lives here, version-agnostic (group+resource), mirroring
// analyzers.CiliumPolicyCounts/CalicoPolicyCounts.
func crdPolicyCounts(inv *collect.Inventory, cni cniPosture) (perNS map[string]int, clusterWide int, ok bool) {
	var group, nsRes, cwRes string
	switch cni.name {
	case "Cilium":
		group, nsRes, cwRes = "cilium.io", "ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"
	case "Calico":
		group, nsRes, cwRes = "projectcalico.org", "networkpolicies", "globalnetworkpolicies"
	default:
		return nil, 0, false
	}
	// Membership is checked group+resource (version-agnostic) against PresentGVRs.
	present := false
	for gvr := range inv.PresentGVRs {
		if gvr.Group == group && gvr.Resource == nsRes {
			present = true
			break
		}
	}
	if !present || !observedCR(inv, group, nsRes) {
		return nil, 0, false
	}
	// DENIAL GUARD: we count cluster-wide policies (CiliumClusterwide.../global)
	// below and rely on clusterWide==0 to decide a namespace is unsegmented. The
	// cluster-wide resource is cluster-scoped and often RBAC-restricted; if its
	// list was DENIED, clusterWide would read 0 SILENTLY and produce a false
	// "unsegmented" finding (a cluster-wide policy we couldn't see may segment the
	// namespace). So when the cluster-wide GVR is PRESENT, we must also confirm
	// its list succeeded before trusting the count; if it was denied, fall back to
	// ok=false (the caller keeps the honest "verify CRDs" 0.45 path). When the
	// cluster-wide GVR is absent entirely, clusterWide==0 is genuinely correct
	// (no such resource exists), so we do not require a list there.
	cwPresent := false
	for gvr := range inv.PresentGVRs {
		if gvr.Group == group && gvr.Resource == cwRes {
			cwPresent = true
			break
		}
	}
	if cwPresent && !observedCR(inv, group, cwRes) {
		return nil, 0, false
	}
	perNS = map[string]int{}
	for gvr, objs := range inv.StackObjects {
		if gvr.Group != group {
			continue
		}
		for _, o := range objs {
			ns, _, _ := unstructured.NestedString(o.Object, "metadata", "namespace")
			switch gvr.Resource {
			case nsRes:
				perNS[ns]++
			case cwRes:
				clusterWide++
			}
		}
	}
	return perNS, clusterWide, true
}

// findingFor builds a single namespace finding, calibrated to what the
// detected CNI tells us about enforcement.
func (r NoNetworkPolicy) findingFor(ns string, wc int, cni cniPosture) types.Finding {
	// Defaults for the unknown-CNI case: we can't confirm enforcement, so the
	// confidence reflects "object absence is certain; enforcement is not".
	confidence := 0.8
	severity := types.SeverityMedium

	title := fmt.Sprintf("Namespace %s has no NetworkPolicy — add a default-deny if its CNI enforces policy", ns)

	// WhyItMatters is phrased conditionally so the executive (headline-only)
	// view never asserts enforcement as guaranteed fact.
	whyItMatters := "If the cluster CNI enforces NetworkPolicy, flat pod-to-pod networking lets a single compromised container move laterally across the namespace. If the CNI does not enforce policy (or segments via its own CRDs), this gap may be theoretical — confirm enforcement before relying on it."

	// Evidence states only the observed fact: zero UPSTREAM objects. We never
	// claim "every pod accepts traffic from every other pod" as established
	// fact, because that depends on enforcement we cannot see.
	evidence := []string{
		fmt.Sprintf("namespace %s: %s, 0 networking.k8s.io/v1 NetworkPolicy objects", ns, nWord(wc, "workload", "workloads")),
	}

	descPrefix := fmt.Sprintf(
		"Namespace %s runs %s and defines zero upstream (networking.k8s.io/v1) NetworkPolicy objects. ",
		ns, nWord(wc, "workload",

			// CNI-specific calibration.
			"workloads"))

	switch {
	case cni.vpcCNINoAgent:
		// AWS VPC CNI, no policy agent: a NetworkPolicy object is accepted by
		// the API server but silently ignored. Adding default-deny here gives
		// false security, so the remediation MUST warn and confidence drops.
		confidence = 0.4
		severity = types.SeverityMedium
		title = fmt.Sprintf("Namespace %s has no NetworkPolicy — and %s does not enforce one without a policy agent", ns, cni.name)
		whyItMatters = "This cluster runs AWS VPC CNI, which does NOT enforce NetworkPolicy on its own. Applying a default-deny object alone gives a false sense of isolation: it is accepted by the API server and silently ignored until the VPC CNI network-policy controller or Calico is enabled."
		evidence = append(evidence,
			"detected CNI: AWS VPC CNI (aws-node DaemonSet) with no Calico/Cilium policy agent observed — NetworkPolicy is NOT enforced",
		)
		descPrefix += "This cluster's CNI is AWS VPC CNI; NetworkPolicy is NOT enforced unless the VPC CNI network-policy controller or Calico is enabled — applying the object alone will be silently ignored. Enable a policy enforcer first, then "

	case cni.usesOwnCRDs:
		// Cilium/Calico: segmentation is frequently expressed as the CNI's own
		// CRDs (CiliumNetworkPolicy, projectcalico.org policies) which we do
		// NOT read. The namespace may already be default-deny. Soften and lower
		// confidence so we don't assert flat allow-all.
		confidence = 0.45
		severity = types.SeverityLow
		title = fmt.Sprintf("Namespace %s has no upstream NetworkPolicy — verify its %s policy CRDs", ns, cni.name)
		whyItMatters = fmt.Sprintf("This cluster runs %s, which can enforce segmentation via its own CRDs that this read-only scan does not inspect. The namespace may already be default-deny under %s — verify before treating this as an exposure.", cni.name, cni.name)
		evidence = append(evidence,
			fmt.Sprintf("detected CNI: %s — segmentation may be defined in %s policy CRDs that shoalcheck does not read; do not assume flat allow-all", cni.name, cni.name),
		)
		descPrefix += fmt.Sprintf("This cluster runs %s, which may enforce segmentation through its own CRDs (e.g. CiliumNetworkPolicy / projectcalico.org policies) that shoalcheck does not yet read — so zero upstream objects does NOT prove the namespace is unsegmented. If it is genuinely flat, ", cni.name)

	case cni.enforcesUpstream:
		// A CNI that enforces upstream NetworkPolicy and has no separate policy
		// CRD convention (e.g. Weave). Zero objects here is a real allow-all
		// gap, so we can hold the standard medium/0.8.
		evidence = append(evidence,
			fmt.Sprintf("detected CNI: %s enforces upstream NetworkPolicy — zero objects means default allow-all applies", cni.name),
		)
		descPrefix += fmt.Sprintf("The detected CNI (%s) enforces upstream NetworkPolicy, so with zero objects the namespace is default allow-all. ", cni.name)

	default:
		// Unknown / non-enforcing (Flannel) / undetected CNI.
		evidence = append(evidence,
			"CNI enforcement of NetworkPolicy could not be confirmed from collected DaemonSets — verify the cluster CNI supports and enforces NetworkPolicy before relying on this remediation",
		)
		descPrefix += "Enforcement of NetworkPolicy depends on the cluster CNI, which could not be confirmed here (a NetworkPolicy is accepted by the API server but silently ignored without an enforcing CNI). If the CNI enforces policy, "
	}

	description := descPrefix + "start with a default-deny-ingress policy, then add explicit allows for the flows that exist."

	// The default-deny remediation is correct only on an enforcing CNI; on AWS
	// VPC CNI without an agent it is a no-op, so we lead the YAML with a comment.
	yamlHeader := ""
	if cni.vpcCNINoAgent {
		yamlHeader = fmt.Sprintf(
			"# WARNING: this cluster runs %s, which does NOT enforce NetworkPolicy on its own.\n# Enable the VPC CNI network-policy controller or Calico FIRST, or this object is silently ignored.\n",
			cni.name)
	} else if cni.usesOwnCRDs {
		yamlHeader = fmt.Sprintf(
			"# NOTE: this cluster runs %s. Verify the namespace is not already segmented via %s CRDs\n# before adding this upstream object; validate against your workload's real flows before applying.\n",
			cni.name, cni.name)
	} else {
		yamlHeader = "# Validate against your workload's real ingress flows before applying — a bare default-deny\n# will drop all ingress until you add explicit allow rules.\n"
	}

	return types.Finding{
		ID:           findingID(r.ID(), "Namespace", "", ns),
		IDBasis:      &types.ResourceRef{Kind: "Namespace", Namespace: "", Name: ns},
		RuleID:       r.ID(),
		RuleVersion:  r.Version(),
		Title:        title,
		Description:  description,
		WhyItMatters: whyItMatters,
		Evidence:     evidence,
		Severity:     severity,
		Category:     types.CategorySecurity,
		AffectedResources: []types.ResourceRef{
			{Kind: "Namespace", Name: ns},
		},
		EstimatedEffort: types.EffortMedium, // default-deny needs follow-up allow rules per real flow
		RemediationYAML: yamlHeader + fmt.Sprintf(
			"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-ingress\n  namespace: %s\nspec:\n  podSelector: {}  # empty selector = every pod in the namespace\n  policyTypes:\n    - Ingress\n",
			ns),
		Confidence: confidence,
		Provenance: provenance(),
	}
}

// findingForCRDAware refines findingFor with Phase-3 CRD evidence. When the
// own-CRD CNI's policies were actually listed and the namespace has ZERO of
// both upstream AND CRD policies, the 0.45 "we don't read your CRDs" apology is
// retired: we DID read them, the gap is real, so confidence rises to 0.8 and
// the evidence cites the CRD count. When CRDs were not listed (crdOK=false) or
// the CNI does not use its own CRDs, behavior is byte-identical to findingFor
// (the legacy 0.45 fallback stands). Segmented namespaces are already removed
// upstream by the suppression in Evaluate, so reaching here with crdOK means
// this namespace genuinely had zero of both.
func (r NoNetworkPolicy) findingForCRDAware(ns string, wc int, cni cniPosture, crdOK bool, crdNS, crdClusterWide int) types.Finding {
	f := r.findingFor(ns, wc, cni)
	if !crdOK || !cni.usesOwnCRDs {
		return f
	}
	f.Confidence = 0.8
	f.Severity = types.SeverityMedium
	f.Title = fmt.Sprintf("Namespace %s has no NetworkPolicy and no %s policy either", ns, cni.name)
	f.WhyItMatters = fmt.Sprintf("This cluster runs %s and Shoalcheck read its policy CRDs directly: the namespace has zero upstream NetworkPolicy AND zero %s policies, so pod-to-pod traffic is genuinely unsegmented.", cni.name, cni.name)
	// The CRD kind name (not the display name) is named so the evidence is
	// auditable and the literal CRD count appears verbatim.
	crdKind := "policies"
	switch cni.name {
	case "Cilium":
		crdKind = "CiliumNetworkPolicy"
	case "Calico":
		crdKind = "Calico NetworkPolicy"
	}
	f.Evidence = []string{
		fmt.Sprintf("namespace %s: %s, 0 networking.k8s.io/v1 NetworkPolicy objects", ns, nWord(wc, "workload", "workloads")),
		fmt.Sprintf("namespace %s: 0 %s and %d cluster-wide %s policies (read via CRD)", ns, crdKind, crdClusterWide, cni.name),
	}
	return f
}

// RequiredKinds — The policy list is the claim. server-resources is load-bearing too: the CNI it reveals decides whether
// a missing policy means anything at all, so a denied discovery changes what the finding asserts.
// See deps.go for what belongs in this list.
func (r NoNetworkPolicy) RequiredKinds() []string {
	return withWorkloads("networkpolicies", "server-resources")
}
