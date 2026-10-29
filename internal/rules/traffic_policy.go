package rules

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// traffic_policy.go — externalTrafficPolicy, whose two settings are a TRADE and neither is a default to
// prefer.
//
// Popeye publishes both directions as separate checks and this rule reports both, because the honest claim
// is not "this value is wrong" — it is "this value has a consequence the manifest does not mention, and
// here is which one you have chosen".
//
//	Cluster on a LoadBalancer   — the source IP every backend sees is a node's, not the client's, because
//	                              kube-proxy SNATs the second hop. Load spreads evenly.
//	Local on a NodePort         — the source IP is preserved and a node with no local backend BLACKHOLES
//	                              the request rather than forwarding it.
//
// SO THE SEVERITY IS INFO AND THE WORDING IS SYMMETRIC. A rule that called either one a defect would be
// stating a preference as a finding, and this product's whole discipline is that a trade-off is disclosed
// rather than decided.
type ExternalTrafficPolicyConsequence struct{}

func (ExternalTrafficPolicyConsequence) ID() string {
	return "k8s.config.external-traffic-policy"
}
func (ExternalTrafficPolicyConsequence) Version() string { return "1.0.0" }

func (ExternalTrafficPolicyConsequence) RequiredKinds() []string {
	return sortedKinds([]string{"services"})
}

func (r ExternalTrafficPolicyConsequence) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "services") {
		return nil
	}
	var lb, np []string
	for i := range inv.Services {
		svc := &inv.Services[i]
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		// An UNSET policy is Cluster by default, and reporting the default on every Service in the cluster
		// would be reporting Kubernetes rather than this cluster. Only an EXPLICIT setting is judged.
		switch {
		case svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
			svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyCluster:
			lb = append(lb, svc.Namespace+"/"+svc.Name)
		case svc.Spec.Type == corev1.ServiceTypeNodePort &&
			svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal:
			np = append(np, svc.Namespace+"/"+svc.Name)
		}
	}
	sort.Strings(lb)
	sort.Strings(np)

	var out []types.Finding
	if len(lb) > 0 {
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", "", "loadbalancer-cluster"),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: "", Name: "loadbalancer-cluster"},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s externalTrafficPolicy: Cluster",
				nWord(len(lb), "LoadBalancer Service", "LoadBalancer Services"), pick(len(lb), "sets", "set")),
			Description: fmt.Sprintf("%s explicitly set externalTrafficPolicy to "+
				"Cluster. kube-proxy then forwards to a backend on any node and source-NATs the second hop, "+
				"so every backend sees a node address rather than the client's. Load spreads evenly, which "+
				"is what the setting buys.", nWord(len(lb), "LoadBalancer Service", "LoadBalancer Services")),
			WhyItMatters: "Anything that reasons about the client address — rate limiting, geo-routing, " +
				"allow-lists, audit logs — sees a node instead. The application is usually written before " +
				"the Service and never told.",
			Evidence: append([]string{
				snapshotNote(inv),
				"Services explicitly setting Cluster: " + joinList(lb),
				"an UNSET policy is Cluster by default and is not reported here — that would be reporting " +
					"Kubernetes rather than this cluster",
			}, "the alternative, Local, preserves the client address and blackholes requests arriving at a "+
				"node with no local backend; neither setting is a default to prefer"),
			Severity:          types.SeverityInfo,
			Category:          types.CategoryConfig,
			AffectedResources: refsFor("Service", lb),
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	if len(np) > 0 {
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", "", "nodeport-local"),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: "", Name: "nodeport-local"},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%s %s externalTrafficPolicy: Local",
				nWord(len(np), "NodePort Service", "NodePort Services"), pick(len(np), "sets", "set")),
			Description: fmt.Sprintf("%s set externalTrafficPolicy to Local. A request "+
				"arriving at a node with no local backend is dropped rather than forwarded, so reaching "+
				"the Service depends on which node the caller happens to hit. What is in front of these "+
				"NodePorts, and whether it health-checks per node, is not readable from here.", nWord(len(np), "NodePort Service", "NodePort Services")),
			WhyItMatters: "Local is the correct choice when something in front of the NodePort health-" +
				"checks each node and routes only to healthy ones. It is the wrong one when callers pick " +
				"a node themselves, and both look identical in the manifest.",
			Evidence: []string{
				snapshotNote(inv),
				"Services setting Local: " + joinList(np),
				"whether a load balancer in front of these nodes health-checks per node is outside this " +
					"reading, and it is the fact that decides whether Local is right here",
			},
			Severity:          types.SeverityInfo,
			Category:          types.CategoryConfig,
			AffectedResources: refsFor("Service", np),
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	return out
}

func joinList(xs []string) string {
	const max = 12
	if len(xs) <= max {
		return commaJoin(xs)
	}
	// A TRUNCATION IS DISCLOSED, never silent: a list rendered as complete when it is not is
	// absence-as-fact in a new hat.
	return fmt.Sprintf("%s, and %d more", commaJoin(xs[:max]), len(xs)-max)
}

func commaJoin(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func refsFor(kind string, keys []string) []types.ResourceRef {
	out := make([]types.ResourceRef, 0, len(keys))
	for _, k := range keys {
		ns, name := k, ""
		for i := 0; i < len(k); i++ {
			if k[i] == '/' {
				ns, name = k[:i], k[i+1:]
				break
			}
		}
		out = append(out, types.ResourceRef{Kind: kind, Namespace: ns, Name: name})
	}
	return out
}
