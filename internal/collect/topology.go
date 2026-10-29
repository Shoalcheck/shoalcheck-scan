package collect

import (
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// maxWorkloadsPerNS guards against emitting thousands of nodes for a single
// namespace. The renderer caps independently; this is a sanity ceiling so the
// JSON stays bounded. Workloads with findings are kept first, then by name.
const maxWorkloadsPerNS = 25

// buildTopologies produces a per-namespace workload graph: workloads as
// nodes, Services as nodes, and selector edges (Service → workload) resolved
// by matching Service.spec.selector against workload pod labels. Severity
// overlay comes from findings that reference each workload.
func buildTopologies(inv *Inventory, findings []types.Finding) []types.NamespaceTopology {
	// Index workloads by namespace, normalised to a kind-agnostic shape so the
	// node-building / matching loops stay uniform across deploy/sts/ds.
	type wl struct {
		kind      string
		name      string
		replicas  int
		podLabels map[string]string
	}
	wlByNS := map[string][]wl{}
	add := func(ns, kind, name string, replicas int, lbls map[string]string) {
		wlByNS[ns] = append(wlByNS[ns], wl{kind: kind, name: name, replicas: replicas, podLabels: lbls})
	}
	for i := range inv.Deployments {
		d := &inv.Deployments[i]
		add(d.Namespace, "Deployment", d.Name, replicasOf(d.Spec.Replicas), d.Spec.Template.Labels)
	}
	for i := range inv.StatefulSets {
		s := &inv.StatefulSets[i]
		add(s.Namespace, "StatefulSet", s.Name, replicasOf(s.Spec.Replicas), s.Spec.Template.Labels)
	}
	for i := range inv.DaemonSets {
		d := &inv.DaemonSets[i]
		// DaemonSets have no .spec.replicas; report desired-scheduled, which is
		// the closest "replica" notion (0 when status unset).
		add(d.Namespace, "DaemonSet", d.Name, daemonSetReplicas(d), d.Spec.Template.Labels)
	}

	// Services by namespace, preserving spec for selector + type rendering.
	svcByNS := map[string][]corev1.Service{}
	for i := range inv.Services {
		s := inv.Services[i]
		svcByNS[s.Namespace] = append(svcByNS[s.Namespace], s)
	}

	// severity overlay: best (highest-severity, then SortByPriority-first)
	// finding per workload, keyed by kind/ns/name.
	type sev struct {
		severity  types.Severity
		findingID string
	}
	sevByWL := map[string]sev{}
	{
		ranked := make([]types.Finding, len(findings))
		copy(ranked, findings)
		types.SortByPriority(ranked) // critical → info, then $ impact
		for _, f := range ranked {
			for _, r := range f.AffectedResources {
				key := r.Kind + "/" + r.Namespace + "/" + r.Name
				cur, seen := sevByWL[key]
				// Keep the most urgent; on a tie keep the first (already
				// priority-sorted, so first == highest $ impact).
				if !seen || moreUrgent(f.Severity, cur.severity) {
					sevByWL[key] = sev{severity: f.Severity, findingID: f.ID}
				}
			}
		}
	}

	// Deterministic namespace order.
	nsNames := make([]string, 0, len(wlByNS))
	for ns := range wlByNS {
		nsNames = append(nsNames, ns)
	}
	sort.Strings(nsNames)

	var out []types.NamespaceTopology
	for _, ns := range nsNames {
		if isSystemNamespace(ns) {
			continue
		}
		wls := wlByNS[ns]
		if len(wls) == 0 {
			continue
		}

		// Sort workloads: those with findings first, then by name — so the
		// top-N guard keeps the interesting ones. Tie-break by kind for total
		// determinism.
		sort.SliceStable(wls, func(i, j int) bool {
			ki := sevByWL[wls[i].kind+"/"+ns+"/"+wls[i].name].findingID != ""
			kj := sevByWL[wls[j].kind+"/"+ns+"/"+wls[j].name].findingID != ""
			if ki != kj {
				return ki // with-finding before without
			}
			if wls[i].name != wls[j].name {
				return wls[i].name < wls[j].name
			}
			return wls[i].kind < wls[j].kind
		})
		if len(wls) > maxWorkloadsPerNS {
			wls = wls[:maxWorkloadsPerNS]
		}

		tp := types.NamespaceTopology{Name: ns}

		// Workload nodes. Track ids actually emitted so edges only point at
		// surviving nodes after the top-N trim.
		emitted := map[string]bool{}
		for _, w := range wls {
			id := w.kind + "/" + w.name
			node := types.WorkloadNode{ID: id, Kind: w.kind, Name: w.name, Replicas: w.replicas}
			if s, ok := sevByWL[w.kind+"/"+ns+"/"+w.name]; ok {
				node.Severity = string(s.severity)
				node.FindingID = s.findingID
			}
			tp.Workloads = append(tp.Workloads, node)
			emitted[id] = true
		}

		// Service nodes, sorted by name.
		svcs := svcByNS[ns]
		sort.SliceStable(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
		for i := range svcs {
			s := svcs[i]
			node := types.ServiceNode{
				ID:   "svc/" + s.Name,
				Kind: "Service",
				Name: s.Name,
				Type: string(s.Spec.Type),
			}
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
				node.Note = "LoadBalancer"
			}
			tp.Services = append(tp.Services, node)

			// Selector edges: Service → each workload whose pod labels are a
			// superset of the (non-empty) selector. Same equality-AND semantics
			// the idle-LB rule uses.
			if len(s.Spec.Selector) == 0 {
				continue
			}
			sel := labels.SelectorFromSet(labels.Set(s.Spec.Selector))
			for _, w := range wls {
				to := w.kind + "/" + w.name
				if !emitted[to] {
					continue
				}
				if sel.Matches(labels.Set(w.podLabels)) {
					tp.Edges = append(tp.Edges, types.GraphEdge{
						From: "svc/" + s.Name,
						To:   to,
						Kind: "selector",
					})
				}
			}
		}

		// NetworkPolicy "allowed-connectivity" edges (DECLARED, not observed
		// traffic). For each policy in this namespace, its podSelector selects
		// the DESTINATION workloads; each ingress rule's `from` podSelector
		// selects the permitted SOURCES — emit a source→dest communication edge
		// (kind "communication", label "allowed") between emitted workloads.
		// Cross-namespace / ipBlock / namespaceSelector peers are out of
		// conservative read-only reach and omitted rather than guessed. Bounded
		// so a permissive policy can't explode the graph. A namespace with no
		// NetworkPolicy gets no such edge (honest: the absence of edges plus the
		// netpol findings report unrestricted connectivity — never a fake line).
		{
			const maxCommEdges = 24
			commEdges := 0
			commSeen := map[string]bool{}
			for i := range inv.NetworkPolicies {
				np := &inv.NetworkPolicies[i]
				if np.Namespace != ns {
					continue
				}
				dstSel, derr := metaSelector(np.Spec.PodSelector)
				if derr != nil {
					continue
				}
				for _, rule := range np.Spec.Ingress {
					for _, peer := range rule.From {
						if peer.PodSelector == nil || peer.IPBlock != nil || peer.NamespaceSelector != nil {
							continue
						}
						srcSel, serr := metaSelector(*peer.PodSelector)
						if serr != nil {
							continue
						}
						for _, src := range wls {
							if !srcSel.Matches(labels.Set(src.podLabels)) {
								continue
							}
							for _, dst := range wls {
								if !dstSel.Matches(labels.Set(dst.podLabels)) {
									continue
								}
								if src.kind == dst.kind && src.name == dst.name {
									continue
								}
								from := src.kind + "/" + src.name
								to := dst.kind + "/" + dst.name
								if !emitted[from] || !emitted[to] {
									continue
								}
								key := from + "->" + to
								if commSeen[key] {
									continue
								}
								if commEdges >= maxCommEdges {
									break
								}
								commSeen[key] = true
								tp.Edges = append(tp.Edges, types.GraphEdge{
									From: from, To: to, Kind: "communication", Label: "allowed",
								})
								commEdges++
							}
						}
					}
				}
			}
		}

		// Deterministic edge order (From, then To).
		sort.SliceStable(tp.Edges, func(i, j int) bool {
			if tp.Edges[i].From != tp.Edges[j].From {
				return tp.Edges[i].From < tp.Edges[j].From
			}
			return tp.Edges[i].To < tp.Edges[j].To
		})

		out = append(out, tp)
	}
	return out
}

// replicasOf reads a *int32 replica count, defaulting to 1 (the Kubernetes
// default when .spec.replicas is unset) rather than 0.
func replicasOf(r *int32) int {
	if r == nil {
		return 1
	}
	return int(*r)
}

// daemonSetReplicas reports a DaemonSet's effective replica count — desired
// scheduled pods, which equals the number of eligible nodes.
func daemonSetReplicas(d *appsv1.DaemonSet) int {
	return int(d.Status.DesiredNumberScheduled)
}

// moreUrgent reports whether severity a outranks b (critical is most urgent).
func moreUrgent(a, b types.Severity) bool {
	rank := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     1,
		types.SeverityMedium:   2,
		types.SeverityLow:      3,
		types.SeverityInfo:     4,
	}
	ra, oka := rank[a]
	rb, okb := rank[b]
	if !oka {
		ra = len(rank) // unknown severities sort last
	}
	if !okb {
		rb = len(rank)
	}
	return ra < rb
}
