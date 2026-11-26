package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// WebhookUnbacked reports admission webhooks that fail closed with nothing, or one node, behind them (ENG-41). A
// webhook with failurePolicy Fail whose Service publishes no ready endpoint refuses every request it intercepts; one
// whose ready endpoints are all on one node refuses them for as long as that node is drained — including the
// requests the drain itself makes, when it intercepts pods.
//
// A webhook called by URL is not assessed: its backend is outside the cluster's objects.
type WebhookUnbacked struct{}

func (WebhookUnbacked) ID() string      { return "k8s.reliability.webhook-unbacked" }
func (WebhookUnbacked) Version() string { return "1.0.0" }

func (WebhookUnbacked) RequiredKinds() []string {
	return sortedKinds([]string{crKind(gvrValidatingWebhooks), crKind(gvrMutatingWebhooks), "services", "endpointslices"})
}

// webhookRef is one webhook of one configuration.
type webhookRef struct {
	config, kind, name, failure string
	svcNS, svcName              string
	byURL                       bool
	intercepts                  string
}

func readWebhooks(objs []unstructured.Unstructured, kind string) []webhookRef {
	var out []webhookRef
	for _, o := range objs {
		hooks, _, _ := unstructured.NestedSlice(o.Object, "webhooks")
		for _, h := range hooks {
			m, ok := h.(map[string]any)
			if !ok {
				continue
			}
			w := webhookRef{config: o.GetName(), kind: kind, failure: "Fail"}
			w.name, _, _ = unstructured.NestedString(m, "name")
			if f, ok, _ := unstructured.NestedString(m, "failurePolicy"); ok && f != "" {
				w.failure = f
			}
			ns, hasSvc, _ := unstructured.NestedString(m, "clientConfig", "service", "namespace")
			name, _, _ := unstructured.NestedString(m, "clientConfig", "service", "name")
			if !hasSvc || name == "" {
				w.byURL = true
			}
			w.svcNS, w.svcName = ns, name
			w.intercepts = webhookIntercepts(m)
			out = append(out, w)
		}
	}
	return out
}

// webhookIntercepts is "CREATE, UPDATE of pods, deployments": the operations and resources its rules name.
func webhookIntercepts(m map[string]any) string {
	rules, _, _ := unstructured.NestedSlice(m, "rules")
	ops, res := map[string]bool{}, map[string]bool{}
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		o, _, _ := unstructured.NestedStringSlice(rm, "operations")
		rs, _, _ := unstructured.NestedStringSlice(rm, "resources")
		for _, x := range o {
			ops[x] = true
		}
		for _, x := range rs {
			res[x] = true
		}
	}
	if len(ops) == 0 || len(res) == 0 {
		return "the requests its rules name"
	}
	keys := func(s map[string]bool) string {
		l := make([]string, 0, len(s))
		for k := range s {
			l = append(l, k)
		}
		sort.Strings(l)
		return strings.Join(l, ", ")
	}
	return keys(ops) + " of " + keys(res)
}

func (r WebhookUnbacked) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "services") || !observed(inv, "endpointslices") {
		return nil
	}
	var hooks []webhookRef
	if objs, ok := crObjects(inv, gvrValidatingWebhooks); ok {
		hooks = append(hooks, readWebhooks(objs, "ValidatingWebhookConfiguration")...)
	}
	if objs, ok := crObjects(inv, gvrMutatingWebhooks); ok {
		hooks = append(hooks, readWebhooks(objs, "MutatingWebhookConfiguration")...)
	}
	services := map[string]*corev1.Service{}
	for i := range inv.Services {
		s := &inv.Services[i]
		services[s.Namespace+"/"+s.Name] = s
	}
	var out []types.Finding
	for _, w := range hooks {
		if w.byURL || w.failure != "Fail" {
			continue
		}
		subject := w.kind + " " + w.config + ", webhook " + w.name
		var title, line string
		sev := types.SeverityHigh
		var facts []types.Fact
		svc := services[w.svcNS+"/"+w.svcName]
		switch {
		case svc == nil:
			title = fmt.Sprintf("Webhook %s fails closed on a Service that does not exist", w.name)
			line = fmt.Sprintf("%s calls Service %s/%s, which this reading does not hold", subject, w.svcNS, w.svcName)
		default:
			pub := publishedFor(inv, svc)
			facts = []types.Fact{types.NewFact("webhook.endpoints.ready", pub.ready), types.NewFact("webhook.nodes", len(pub.readyByNode))}
			switch {
			case pub.ready == 0:
				title = fmt.Sprintf("Webhook %s fails closed with no ready endpoint behind it", w.name)
				line = fmt.Sprintf("%s calls Service %s/%s, which publishes 0 ready endpoints", subject, w.svcNS, w.svcName)
			case len(pub.readyByNode) == 1:
				sev = types.SeverityMedium
				var node string
				for n := range pub.readyByNode {
					node = n
				}
				title = fmt.Sprintf("Webhook %s fails closed and every ready endpoint is on node %s", w.name, node)
				line = fmt.Sprintf("%s calls Service %s/%s, whose %s on node %s: a drain of %s takes it away for as long as the drain runs",
					subject, w.svcNS, w.svcName, nWord(int(types.FactNum(facts, "webhook.endpoints.ready")), "ready endpoint is", "ready endpoints are all"), node, node)
			default:
				continue
			}
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.kind, "", w.config+"/"+w.name),
			IDBasis:     &types.ResourceRef{Kind: w.kind, Name: w.config},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       title,
			Description: fmt.Sprintf("The webhook has failurePolicy Fail, so when its backend does not answer, the API server refuses "+
				"the request instead of letting it through. It intercepts %s.", w.intercepts),
			WhyItMatters: "A fail-closed webhook with nothing behind it turns into an outage of every write it intercepts: " +
				"deploys, scale-ups and, when it intercepts pods, the evictions a drain makes.",
			Evidence: []string{snapshotNote(inv), line, "it intercepts " + w.intercepts,
				"failurePolicy is Fail (or unset, which admissionregistration.k8s.io/v1 reads as Fail)"},
			Facts:             facts,
			Severity:          sev,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: w.kind, Name: w.config}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// APIServiceUnavailable reports aggregated APIs whose APIService is not Available (ENG-42): every request to that
// group and version fails, and every client's discovery reports the cluster's API list as partial.
type APIServiceUnavailable struct{}

func (APIServiceUnavailable) ID() string      { return "k8s.reliability.apiservice-unavailable" }
func (APIServiceUnavailable) Version() string { return "1.0.0" }
func (APIServiceUnavailable) RequiredKinds() []string {
	return []string{crKind(gvrAPIServices)}
}

func (r APIServiceUnavailable) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	objs, ok := crObjects(inv, gvrAPIServices)
	if !ok {
		return nil
	}
	var out []types.Finding
	for _, o := range objs {
		svc, aggregated, _ := unstructured.NestedString(o.Object, "spec", "service", "name")
		if !aggregated || svc == "" {
			continue // served by the API server itself
		}
		ns, _, _ := unstructured.NestedString(o.Object, "spec", "service", "namespace")
		status, reason := "Unknown", ""
		conds, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			if t, _, _ := unstructured.NestedString(cm, "type"); t == "Available" {
				status, _, _ = unstructured.NestedString(cm, "status")
				reason, _, _ = unstructured.NestedString(cm, "reason")
			}
		}
		if status == "True" {
			continue
		}
		said := "Available=" + status
		if reason != "" {
			said += " (" + reason + ")"
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "APIService", "", o.GetName()),
			IDBasis:     &types.ResourceRef{Kind: "APIService", Name: o.GetName()},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Aggregated API %s is not available", o.GetName()),
			Description: fmt.Sprintf("APIService %s is served by Service %s/%s and reports %s. Every request to that group and "+
				"version fails, and every client's discovery reports the cluster's API list as partial.", o.GetName(), ns, svc, said),
			WhyItMatters: "A broken aggregated API breaks more than its own group: kubectl, controllers and namespace deletion " +
				"all run discovery, and a namespace whose finalizer waits on an unavailable API stays Terminating.",
			Evidence:          []string{snapshotNote(inv), fmt.Sprintf("APIService %s: %s, backed by Service %s/%s", o.GetName(), said, ns, svc)},
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "APIService", Name: o.GetName()}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
