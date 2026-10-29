package collect

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// metaSelector converts a metav1.LabelSelector (matchLabels + matchExpressions)
// to a labels.Selector. An empty selector matches everything (Kubernetes
// NetworkPolicy semantics); callers gate on that where it matters.
func metaSelector(sel metav1.LabelSelector) (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(&sel)
}

// maxFlows caps the number of request-flow pipelines rendered. A real cluster
// has dozens of ingresses; the report shows the most representative few
// (deterministic: namespace then name), the rest live in the topology.
const maxFlows = 6

// buildFlows derives request-flow pipelines from the cluster's DECLARED routing
// — never observed traffic (the audit has no mesh/tracing data and never reads
// env/config). Each flow is an evidence chain where every hop is backed by a
// real API object: an Ingress route (host → backend Service) or a LoadBalancer
// Service is the entry; the Service's selector resolves the backing workload;
// a NetworkPolicy egress rule, when present, permits a downstream hop. A hop
// with no backing object ENDS the flow rather than inventing a continuation.
// The report labels these as declared wiring, not measured calls.
func buildFlows(inv *Inventory, findings []types.Finding) []types.FlowDiagram {
	wlByNS := indexWorkloads(inv)
	sevByWL := severityByResource(findings)

	svcByNS := map[string]map[string]corev1.Service{}
	for i := range inv.Services {
		s := inv.Services[i]
		if svcByNS[s.Namespace] == nil {
			svcByNS[s.Namespace] = map[string]corev1.Service{}
		}
		svcByNS[s.Namespace][s.Name] = s
	}

	// selectedWorkloads: workloads whose pod labels match a Service selector
	// (the same equality-AND semantics the topology builder uses).
	selectedWorkloads := func(ns string, sel map[string]string) []wlRef {
		if len(sel) == 0 {
			return nil
		}
		m := labels.SelectorFromSet(labels.Set(sel))
		var out []wlRef
		for _, w := range wlByNS[ns] {
			if m.Matches(labels.Set(w.podLabels)) {
				out = append(out, w)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
		return out
	}

	stepForWorkload := func(ns string, w wlRef) types.FlowStep {
		st := types.FlowStep{Label: w.name, Namespace: ns, Kind: "service", Note: w.kind}
		if looksLikeDatastore(w.name) {
			st.Kind = "datastore"
		}
		if s, ok := sevByWL[w.kind+"/"+ns+"/"+w.name]; ok {
			st.FindingID = s.findingID
		}
		return st
	}

	// downstreamSteps: services in the same namespace that a NetworkPolicy
	// EGRESS rule on the workload permits reaching. Honest "allowed by policy"
	// edge (not observed). Bounded to keep the flow legible.
	downstreamSteps := func(ns string, w wlRef) []types.FlowStep {
		targets := egressAllowedWorkloads(inv, ns, w.kind, w.name, w.podLabels)
		var out []types.FlowStep
		for _, t := range targets {
			st := stepForWorkload(ns, t)
			st.Note = "allowed by NetworkPolicy"
			if looksLikeDatastore(t.name) {
				st.Kind = "datastore"
			}
			out = append(out, st)
			if len(out) >= 2 {
				break
			}
		}
		return out
	}

	var flows []types.FlowDiagram
	seenRoot := map[string]bool{} // ns/svc already used as a flow root, to diversify

	// --- Ingress-rooted flows: the real external entry points. ---
	ings := append([]networkingv1.Ingress(nil), inv.Ingresses...)
	sort.SliceStable(ings, func(i, j int) bool {
		if ings[i].Namespace != ings[j].Namespace {
			return ings[i].Namespace < ings[j].Namespace
		}
		return ings[i].Name < ings[j].Name
	})
	for _, ing := range ings {
		if len(flows) >= maxFlows {
			break
		}
		if isSystemNamespace(ing.Namespace) {
			continue
		}
		backend := primaryBackendService(ing)
		if backend == "" {
			continue
		}
		root := ing.Namespace + "/" + backend
		if seenRoot[root] {
			continue
		}
		seenRoot[root] = true

		host := ingressHost(ing)
		steps := []types.FlowStep{
			{Label: host, Kind: "gateway", Note: "Ingress · " + ing.Namespace + "/" + ing.Name},
		}
		svcStep := types.FlowStep{Label: backend, Namespace: ing.Namespace, Kind: "service", Note: "Service"}
		var svcSelector map[string]string
		if svc, ok := svcByNS[ing.Namespace][backend]; ok {
			if svc.Spec.Type != "" {
				svcStep.Note = string(svc.Spec.Type)
			}
			svcSelector = svc.Spec.Selector
		}
		steps = append(steps, svcStep)
		if w, ok := pickWorkload(selectedWorkloads(ing.Namespace, svcSelector), sevByWL, ing.Namespace); ok {
			steps = append(steps, stepForWorkload(ing.Namespace, w))
			steps = append(steps, downstreamSteps(ing.Namespace, w)...)
		}
		flows = append(flows, types.FlowDiagram{
			ID:    "flow-ing-" + sanitizeFlowID(ing.Namespace+"-"+ing.Name),
			Title: flowTitle(host, backend),
			Steps: steps,
		})
	}

	// --- LoadBalancer-service flows: also external entries; fill remaining room. ---
	if len(flows) < maxFlows {
		var lbs []corev1.Service
		for i := range inv.Services {
			s := inv.Services[i]
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer && !isSystemNamespace(s.Namespace) {
				lbs = append(lbs, s)
			}
		}
		sort.SliceStable(lbs, func(i, j int) bool {
			if lbs[i].Namespace != lbs[j].Namespace {
				return lbs[i].Namespace < lbs[j].Namespace
			}
			return lbs[i].Name < lbs[j].Name
		})
		for _, s := range lbs {
			if len(flows) >= maxFlows {
				break
			}
			root := s.Namespace + "/" + s.Name
			if seenRoot[root] {
				continue
			}
			seenRoot[root] = true
			steps := []types.FlowStep{
				{Label: "External clients", Kind: "external", Note: "LoadBalancer · " + s.Namespace + "/" + s.Name},
				{Label: s.Name, Namespace: s.Namespace, Kind: "service", Note: "LoadBalancer"},
			}
			if w, ok := pickWorkload(selectedWorkloads(s.Namespace, s.Spec.Selector), sevByWL, s.Namespace); ok {
				steps = append(steps, stepForWorkload(s.Namespace, w))
				steps = append(steps, downstreamSteps(s.Namespace, w)...)
			}
			flows = append(flows, types.FlowDiagram{
				ID:    "flow-lb-" + sanitizeFlowID(s.Namespace+"-"+s.Name),
				Title: s.Name + " · LoadBalancer",
				Steps: steps,
			})
		}
	}

	return flows
}

// egressAllowedWorkloads returns workloads in ns that a NetworkPolicy egress
// rule on a pod with srcLabels PERMITS reaching (a declared allow, not observed
// traffic). It is deliberately conservative: only same-namespace podSelector
// peers are resolved to concrete workloads; ipBlock / cross-namespace / DNS
// peers are out of read-only reach and omitted rather than guessed.
func egressAllowedWorkloads(inv *Inventory, ns, srcKind, srcName string, srcLabels map[string]string) []wlRef {
	wlByNS := indexWorkloads(inv)
	seen := map[string]bool{}
	var out []wlRef
	for i := range inv.NetworkPolicies {
		np := &inv.NetworkPolicies[i]
		if np.Namespace != ns {
			continue
		}
		// Does this policy select the source workload's pods?
		psel, err := metaSelector(np.Spec.PodSelector)
		if err != nil || !psel.Matches(labels.Set(srcLabels)) {
			continue
		}
		// Only egress policies carry downstream allows.
		hasEgress := false
		for _, t := range np.Spec.PolicyTypes {
			if t == networkingv1.PolicyTypeEgress {
				hasEgress = true
			}
		}
		if !hasEgress && len(np.Spec.Egress) == 0 {
			continue
		}
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil || peer.NamespaceSelector != nil || peer.PodSelector == nil {
					continue // out of conservative read-only reach
				}
				tsel, err := metaSelector(*peer.PodSelector)
				if err != nil {
					continue
				}
				for _, w := range wlByNS[ns] {
					if key := w.kind + "/" + w.name; !seen[key] && tsel.Matches(labels.Set(w.podLabels)) {
						// don't point a workload at itself
						if w.kind == srcKind && w.name == srcName {
							continue
						}
						seen[key] = true
						out = append(out, w)
					}
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// --- shared helpers (used by flows.go and the topology dependency edges) ----

// wlRef is a normalized workload across Deployment/StatefulSet/DaemonSet.
type wlRef struct {
	kind, name string
	podLabels  map[string]string
}

func indexWorkloads(inv *Inventory) map[string][]wlRef {
	m := map[string][]wlRef{}
	for i := range inv.Deployments {
		d := &inv.Deployments[i]
		m[d.Namespace] = append(m[d.Namespace], wlRef{"Deployment", d.Name, d.Spec.Template.Labels})
	}
	for i := range inv.StatefulSets {
		s := &inv.StatefulSets[i]
		m[s.Namespace] = append(m[s.Namespace], wlRef{"StatefulSet", s.Name, s.Spec.Template.Labels})
	}
	for i := range inv.DaemonSets {
		d := &inv.DaemonSets[i]
		m[d.Namespace] = append(m[d.Namespace], wlRef{"DaemonSet", d.Name, d.Spec.Template.Labels})
	}
	return m
}

type resourceSeverity struct {
	severity  types.Severity
	findingID string
}

func severityByResource(findings []types.Finding) map[string]resourceSeverity {
	ranked := make([]types.Finding, len(findings))
	copy(ranked, findings)
	types.SortByPriority(ranked)
	out := map[string]resourceSeverity{}
	for _, f := range ranked {
		for _, r := range f.AffectedResources {
			key := r.Kind + "/" + r.Namespace + "/" + r.Name
			if cur, seen := out[key]; !seen || moreUrgent(f.Severity, cur.severity) {
				out[key] = resourceSeverity{f.Severity, f.ID}
			}
		}
	}
	return out
}

func pickWorkload(wls []wlRef, sev map[string]resourceSeverity, ns string) (wlRef, bool) {
	if len(wls) == 0 {
		return wlRef{}, false
	}
	for _, w := range wls { // prefer a workload that carries a finding
		if _, ok := sev[w.kind+"/"+ns+"/"+w.name]; ok {
			return w, true
		}
	}
	return wls[0], true
}

func ingressHost(ing networkingv1.Ingress) string {
	for _, r := range ing.Spec.Rules {
		if r.Host != "" {
			return r.Host
		}
	}
	return ing.Name
}

func primaryBackendService(ing networkingv1.Ingress) string {
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil && p.Backend.Service.Name != "" {
				return p.Backend.Service.Name
			}
		}
	}
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		return ing.Spec.DefaultBackend.Service.Name
	}
	return ""
}

func looksLikeDatastore(name string) bool {
	n := strings.ToLower(name)
	for _, h := range []string{
		"postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb",
		"elastic", "elasticsearch", "opensearch", "kafka", "rabbitmq", "rabbit",
		"memcached", "cassandra", "etcd", "clickhouse", "cockroach", "nats",
	} {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

func sanitizeFlowID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func flowTitle(host, backend string) string {
	if host != "" && host != backend {
		// "to", NOT an arrow. The report embeds two subsetted faces and neither carries U+2192, so an
		// arrow here is drawn by whatever the reader's machine supplies — or by nothing, as tofu. This
		// line was unreachable in the golden fixture until an Ingress was planted in it, and the glyph
		// gate caught it on the first render. charts.go:672 records the same decision for the same
		// reason: "Replacing that arrow with words — the glyph inventory forbids".
		return host + " to " + backend
	}
	return backend
}
