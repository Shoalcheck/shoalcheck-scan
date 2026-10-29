package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Internal-LoadBalancer annotations. A Service carrying either (truthy) is
// provisioned as an INTERNAL cloud LB — on Azure every internal Service shares
// one cluster-wide Standard LB ("kubernetes-internal"), so the per-LB base
// charge is fixed PER CLUSTER and is NOT freed by deleting one Service. Same
// shape on AWS internal NLBs. See internalLBNote.
const (
	azureInternalLBAnnotation = "service.beta.kubernetes.io/azure-load-balancer-internal"
	awsInternalLBAnnotation   = "service.beta.kubernetes.io/aws-load-balancer-internal"
)

// idleLBGraceWindow is the age below which a freshly-created LoadBalancer
// Service is treated as mid-rollout rather than an idle orphan. A Service and
// its Deployment applied moments before the snapshot can legitimately match 0
// pods because the pods haven't scheduled yet — flagging it as waste would be a
// transient false positive.
const idleLBGraceWindow = 15 * time.Minute

// IdleLoadBalancer flags type=LoadBalancer Services whose selector matches no
// pods (in any phase) — a provisioned cloud LB billed every hour with nothing
// behind it. This is the first cost rule with a real DollarImpactMonthly.
//
// We approximate "idle" from the Inventory alone: a LoadBalancer Service with a
// non-empty selector that matches zero pods in its namespace has no backend.
// An empty/nil selector — headless, or endpoints managed by something outside
// the cluster — is unknowable from here and is skipped rather than flagged;
// false positives on a load-bearing LB are the fastest way to lose trust on a
// cost report.
//
// This used to say "We deliberately do NOT collect Endpoints/EndpointSlices",
// which stopped being true: they are collected, and servicePublishesEndpoints
// below reads them as a VETO on the finding. A selectorless Service is still
// unjudgeable, for a different reason — the endpoints exist but nothing in the
// cluster says what is supposed to be behind them.
//
// The dollar figure is gated on POSITIVE evidence of a managed cloud LB. The
// node provider heuristic in node_headroom.go defaults any unrecognized node to
// "aws", which would attach an AWS NLB price to an on-prem MetalLB / kube-vip
// VIP that costs $0. So this rule prices the LB only when a node carries an
// authoritative aws:// / azure:// / gce:// providerID AND the Service does not
// pin a non-cloud spec.loadBalancerClass. Otherwise the dollar is withheld ($0)
// with an explicit "cloud LB not confirmed" note — the idle finding still ships
// (the orphan is worth surfacing) but never with a fabricated saving.
//
// One more honesty gate applies to INTERNAL LBs. An internal Service (Azure
// azure-load-balancer-internal / AWS aws-load-balancer-internal annotation, or
// a private RFC1918 ingress IP) does NOT get its own billed LB: on Azure all
// internal Services share one cluster-wide Standard LB whose base charge is
// fixed per cluster, so deleting one idle internal Service frees at most ONE
// load-balancing rule (a marginal charge), never the full per-LB base. We do
// not have a per-rule price in internal/pricing, so for an internal LB the
// dollar is set to $0 with an explicit marginal-not-base note rather than
// double-counting the per-cluster base across every internal Service.
type IdleLoadBalancer struct{}

func (IdleLoadBalancer) ID() string { return "k8s.cost.idle-loadbalancer" }

// 1.3.0 (2026-10-28): the private ingress IP that makes an LB internal is named as private, and its address is
// no longer printed.
func (IdleLoadBalancer) Version() string { return "1.3.0" }

func (r IdleLoadBalancer) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Region is read off the nodes for the price lookup. The provider used for
	// PRICING is confirmed separately below (a confirmed cloud providerID),
	// never the node_headroom "aws" default — see confirmedCloudProvider.
	region := regionFromNodes(inv.Nodes)
	cloudProvider, providerConfirmed := confirmedCloudProvider(inv.Nodes)

	// Snapshot time anchors the just-created grace window. Meta.StartedAt is set
	// at the top of Collect(); fall back to now if a caller built the inventory
	// without it (tests, fixtures).
	snapshot := inv.Meta.StartedAt
	if snapshot.IsZero() {
		snapshot = time.Now()
	}

	var out []types.Finding
	for i := range inv.Services {
		svc := inv.Services[i]
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		// Empty/nil selector: backends are managed outside the selector model
		// (headless, manual Endpoints) — we can't confirm idle, so skip.
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		if serviceHasBackingPods(inv.Pods, svc.Namespace, svc.Spec.Selector) {
			continue
		}
		// EndpointSlice VETO. The selector model is intent; a published endpoint entry is a
		// controller's record of a backend. A mesh, an operator or a manual process can publish
		// entries for a Service whose selector matches nothing, and that Service is routing
		// normally. Before slices were collected this rule could not see that and billed an
		// unqualified "nothing behind it" — the only real dollar figure in this rule set, so a
		// false positive here is expensive.
		//
		// Only NON-EMPTY entries veto: the reconciler writes a placeholder slice with no
		// endpoints for a selector Service with no eligible pods, so the existence of a slice
		// proves nothing.
		if observed(inv, "endpointslices") && servicePublishesEndpoints(inv, svc.Namespace, svc.Name) {
			continue
		}
		// Just-created grace window: a Service whose pods haven't scheduled yet
		// races the audit snapshot and reads as idle. Skip it — a transient
		// mid-rollout state is not waste.
		if age := snapshot.Sub(svc.CreationTimestamp.Time); !svc.CreationTimestamp.IsZero() && age >= 0 && age < idleLBGraceWindow {
			continue
		}

		// Only claim the endpoint half when the slices were actually read. On a cluster where the
		// list was denied, the sentence reverts to exactly what it said before slices existed.
		endpointClause := ""
		if observed(inv, "endpointslices") {
			endpointClause = " and its EndpointSlices published no endpoint entries"
		}

		evidence := []string{
			// Honest about what is actually measured: the selector matches no pod
			// OBJECTS of any phase. The code never reads p.Status.Phase, so we do
			// NOT claim "0 running pods" — a reviewer could falsify that in one
			// kubectl command.
			fmt.Sprintf("Service %s/%s type=LoadBalancer, selector %v matches 0 pods (any phase) — provisioned LB likely billed with no backend",
				svc.Namespace, svc.Name, svc.Spec.Selector),
		}

		// LB provisioning state: status.loadBalancer.ingress empty means the
		// cloud-controller never assigned an address (quota/IAM/missing class, or
		// just-created). There is nothing being billed and nothing to delete.
		provisioned := len(svc.Status.LoadBalancer.Ingress) > 0
		if !provisioned {
			evidence = append(evidence,
				"status.loadBalancer.ingress is empty — the LB has not been provisioned (pending/failed), so there is no cloud charge to reclaim yet")
		}

		// Dollar is gated on a confirmed managed cloud LB, an actually provisioned
		// LB, AND the LB being PUBLIC. Any gap → withhold/marginal, keep the finding.
		lbClass := loadBalancerClassNote(svc.Spec.LoadBalancerClass)
		internalReason := internalLBNote(svc)
		dollar := 0.0
		// DECLARED, NEVER DERIVED. Every branch below sets this, because a zero from this rule means one of
		// two different things and the derivation in pipeline.classifyPriceBasis cannot tell them apart.
		var basis types.PriceBasis
		switch {
		case lbClass != "":
			evidence = append(evidence, fmt.Sprintf(
				"spec.loadBalancerClass=%q is a non-cloud LB implementation — no managed cloud charge; dollar impact withheld", lbClass))
		case !providerConfirmed:
			// UNPRICED: a figure was WITHHELD, not chosen. Nothing here established that a cloud load
			// balancer exists at all, so there is no rate to look up.
			basis = types.PriceUnpriced
			evidence = append(evidence,
				"cloud LB not confirmed (no aws://|azure://|gce:// providerID on any node; instance-type heuristic is insufficient for a dollar figure) — base price withheld")
		case !provisioned:
			// UNPRICED for the same reason: an LB that has not been provisioned has no base charge to
			// name yet, and saying "priced at zero" about it would claim a measurement of something that
			// does not exist. Already noted in the evidence above.
			basis = types.PriceUnpriced
		case internalReason != "":
			// PRICED, AT A TRUE ZERO, ON PURPOSE — and this line is the whole reason PriceBasis exists.
			//
			// classifyPriceBasis derives the basis from the category and the sign of the figure, and its own
			// comment names this as the case it cannot see: "a cost rule that priced something at a true
			// zero, which is neither unpriced nor non-cost". Without this the derivation stamped `unpriced`,
			// whose definition is "we COULD NOT price it — no rate for the region, no rate for the instance
			// type, or no usage reading to size it from". None of that is true here: the region IS in the
			// table (pricing.LBMonthlyUSD("azure","westus3") is 18.25) and the rule chose zero because the
			// marginal cost of one idle internal Service is not a full LB base.
			//
			// Measured on a live AKS cluster: NINE findings of a 1,612-finding reading, every one an idle
			// internal LB, every one reported to the reader as "could not be priced" directly above evidence
			// explaining the deliberate zero at length.
			basis = types.PricePriced
			// Internal LBs share one cluster-wide Standard LB whose base charge is
			// fixed per cluster; deleting one idle internal Service frees at most ~1
			// load-balancing rule (marginal), not a full LB base. We have no per-rule
			// price, so the dollar is $0 — billing the full base here would
			// double-count the per-cluster charge across every internal Service.
			evidence = append(evidence, fmt.Sprintf(
				"internal LB (%s) — internal Services share one cluster Standard LB whose base charge is fixed per cluster; deleting this frees ~1 load-balancing rule (marginal), not a full LB base. No per-rule price is modelled, so dollar impact is $0 rather than the full base.",
				internalReason))
		default:
			if monthly, ok := opts.prices().LBMonthly(cloudProvider, region); ok {
				dollar = monthly
				basis = types.PricePriced
				evidence = append(evidence, fmt.Sprintf(
					"%s region %s LB base price about $%.2f/mo (the fixed per-LB base only — excludes capacity-unit / rule / data-processing charges, which are traffic-dependent and not modelled)",
					cloudProvider, region, monthly))
			} else {
				// UNPRICED, and this is the textbook case: a cost dimension with no rate for the region.
				basis = types.PriceUnpriced
				evidence = append(evidence, fmt.Sprintf(
					"region %q not in %s price table — dollar impact left at $0 (price unknown)", region, cloudProvider))
			}
		}

		evidence = append(evidence,
			"snapshot is point-in-time: a Service mid-rollout (pods not yet scheduled) can also read as idle — verify it is truly unused before deleting")

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", svc.Namespace, svc.Name),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Idle LoadBalancer: %s/%s has no backends", svc.Namespace, svc.Name),
			Description: fmt.Sprintf(
				"Service %s/%s is type=LoadBalancer but its selector matches no pods (any phase)%s, so a provisioned cloud load balancer would be billed with nothing behind it. This is read from a point-in-time snapshot, so verify it's truly unused — not mid-rollout — before deleting the Service to release the LB.",
				svc.Namespace, svc.Name, endpointClause),
			WhyItMatters:        "Orphaned cloud load balancers bill a fixed hourly charge indefinitely while serving zero traffic.",
			Evidence:            evidence,
			Severity:            types.SeverityMedium,
			Category:            types.CategoryCost,
			AffectedResources:   []types.ResourceRef{{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}},
			DollarImpactMonthly: dollar,
			PriceBasis:          basis,

			SpendKind:       types.SpendNetwork,
			EstimatedEffort: types.EffortLow,
			// Destructive: prefixed as a comment so it's documentation, not a
			// one-click copy button. The selector-based "idle" check is an
			// approximation (Endpoints aren't collected), so deleting an LB must
			// be a deliberate, verified manual step — see SafeRemediationCommand.
			RemediationCommand: fmt.Sprintf("# verify unused, then: kubectl -n %s delete service %s", svc.Namespace, svc.Name),
			// Confidence 0.8 reflects the IDLE determination only (selector
			// approximation, not Endpoints). It is NOT a statement about the
			// dollar's completeness — the dollar is a withheld-or-lower-bound
			// figure carried in Evidence, gated separately above.
			Confidence: 0.8,
			Provenance: provenance(),
		})
	}
	return out
}

// confirmedCloudProvider returns the managed-cloud provider ("aws"/"azure"/
// "gcp") ONLY when a node carries an authoritative provider-scheme providerID.
// Unlike providerFromNodes (node_headroom.go), it never falls back to the
// instance-type heuristic and never defaults to "aws": for pricing an LB we
// require positive proof a managed cloud LB exists, so an on-prem / MetalLB /
// kube-vip cluster (no cloud providerID) returns ("", false) and the dollar is
// withheld rather than fabricated.
func confirmedCloudProvider(nodes []corev1.Node) (string, bool) {
	for i := range nodes {
		switch pid := nodes[i].Spec.ProviderID; {
		case strings.HasPrefix(pid, "aws://"):
			return "aws", true
		case strings.HasPrefix(pid, "azure://"):
			return "azure", true
		case strings.HasPrefix(pid, "gce://"):
			return "gcp", true
		}
	}
	return "", false
}

// loadBalancerClassNote returns the non-empty loadBalancerClass string when the
// Service pins an explicit LB implementation, signalling the LB may not be a
// managed cloud LB (e.g. MetalLB / kube-vip / a custom controller). An empty or
// nil class means "the cluster's default cloud provider", which is the managed
// cloud case we are willing to price. Returns "" when no class is pinned.
func loadBalancerClassNote(class *string) string {
	if class == nil {
		return ""
	}
	return strings.TrimSpace(*class)
}

// internalLBNote reports whether a LoadBalancer Service is an INTERNAL cloud LB
// and, if so, returns a short human reason naming the signal. Internal LBs do
// not each get their own billed LB: on Azure all internal Services share one
// cluster-wide Standard LB ("kubernetes-internal") whose base is fixed per
// cluster, and the AWS internal-NLB story is the same shape — so deleting one
// idle internal Service frees at most a marginal per-rule charge, never a full
// per-LB base. Returns "" for a public LB (priced normally) or when nothing
// signals "internal".
//
// Signals (any one is sufficient):
//   - service.beta.kubernetes.io/azure-load-balancer-internal == "true"
//   - service.beta.kubernetes.io/aws-load-balancer-internal is truthy
//     ("true"/"0.0.0.0/0" both mean internal in the AWS in-tree/LBC convention;
//     any non-empty, non-"false" value is treated as internal)
//   - status.loadBalancer.ingress IP is RFC1918-private (10./172.16-31./192.168.)
func internalLBNote(svc corev1.Service) string {
	if v, ok := svc.Annotations[azureInternalLBAnnotation]; ok && isTruthyAnnotation(v) {
		return "annotation " + azureInternalLBAnnotation + "=" + strings.TrimSpace(v)
	}
	if v, ok := svc.Annotations[awsInternalLBAnnotation]; ok && isTruthyAnnotation(v) {
		return "annotation " + awsInternalLBAnnotation + "=" + strings.TrimSpace(v)
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		ip := strings.TrimSpace(ing.IP)
		if ip == "" {
			continue
		}
		// NEVER THE ADDRESS: it is a network's IP, and redaction tokenises names, not addresses, so a redacted
		// reading would carry it out. That it is private is the whole of what the note needs.
		if addr, err := netip.ParseAddr(ip); err == nil && addr.IsPrivate() {
			return "private (RFC1918) ingress IP"
		}
	}
	return ""
}

// isTruthyAnnotation reads a Kubernetes boolean-ish annotation. The internal-LB
// annotations are set as the string "true"; AWS's in-tree convention also
// accepts "0.0.0.0/0". We treat any non-empty value that is not an explicit
// "false"/"0" as internal — false is the only value that means "not internal".
func isTruthyAnnotation(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "0", "no":
		return false
	default:
		return true
	}
}

// serviceHasBackingPods reports whether any pod in ns carries all of selector's
// labels (a Service selector is an equality AND-match, same semantics as
// labels.Set.AsSelector). Called only with a non-empty selector. It does NOT
// filter by Pod phase — collect.go lists pods in all phases, and matching ANY
// pod object (Running/Pending/CrashLoop/Terminating) is the conservative choice
// that avoids flagging a load-bearing LB during an incident or rollout.
func serviceHasBackingPods(pods []corev1.Pod, ns string, selector map[string]string) bool {
	sel := labels.SelectorFromSet(labels.Set(selector))
	for i := range pods {
		p := pods[i]
		if p.Namespace != ns {
			continue
		}
		if sel.Matches(labels.Set(p.Labels)) {
			return true
		}
	}
	return false
}

// servicePublishesEndpoints reports whether any EndpointSlice owned by this Service carries at least
// one endpoint entry. Slices are linked to their Service by the kubernetes.io/service-name label,
// which the EndpointSlice controller sets and which is the documented join.
func servicePublishesEndpoints(inv *collect.Inventory, ns, name string) bool {
	for _, s := range inv.EndpointSlices {
		if s.Namespace != ns || s.Labels[discoveryv1.LabelServiceName] != name {
			continue
		}
		if len(s.Endpoints) > 0 {
			return true
		}
	}
	return false
}

// RequiredKinds — EndpointSlices belong here, unlike in the drain rules: here they VETO the finding. Without them a
// Service with live backends can be reported as idle, and this is the only rule carrying a dollar.
// See deps.go for what belongs in this list.
func (r IdleLoadBalancer) RequiredKinds() []string {
	return []string{"endpointslices", "nodes", "pods", "services"}
}
