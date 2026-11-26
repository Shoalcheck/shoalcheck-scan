package rules

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// The diagram tables' caps: the rows a reading keeps of each before it says it was cut (D2). Placement and images
// are per workload and per image; verdicts per node; the graph per binding subject.
const (
	maxPlacementRows = 5000
	maxImageRows     = 5000
	maxVerdictRows   = 10000
	maxRBACEdges     = 10000
)

// BuildTables computes the diagram tables from the inventory and the reading's findings (ENG-35, ENG-36, ENG-38).
func BuildTables(inv *collect.Inventory, findings []types.Finding, opts Options) (*types.PlacementTable, *types.ImageTable,
	*types.NodeVerdictTable, *types.RBACGraph, *types.CapacityTable) {
	return placementTable(inv, opts), imageTable(inv, opts), verdictTable(inv, findings), rbacGraph(inv, findings), capacityTable(inv, opts)
}

func placementTable(inv *collect.Inventory, opts Options) *types.PlacementTable {
	if !observed(inv, "pods") || !observed(inv, "nodes") {
		return nil
	}
	zoneOf := map[string]string{}
	zones := map[string]bool{}
	for i := range inv.Nodes {
		z := collect.ZoneOf(inv.Nodes[i])
		zoneOf[inv.Nodes[i].Name] = z
		if z != "" {
			zones[z] = true
		}
	}
	idx := derived(inv, opts).podIndex()
	t := &types.PlacementTable{}
	for _, w := range workloads(inv, opts) {
		pods := idx.podsFor(w)
		if len(pods) == 0 {
			continue
		}
		byZone := map[string]int{}
		nodes := map[string]bool{}
		for _, p := range pods {
			if p.Spec.NodeName == "" {
				continue
			}
			nodes[p.Spec.NodeName] = true
			byZone[zoneOf[p.Spec.NodeName]]++
		}
		row := types.PlacementRow{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, Replicas: len(pods), Nodes: len(nodes)}
		names := make([]string, 0, len(byZone))
		for z := range byZone {
			names = append(names, z)
		}
		sort.Strings(names)
		for _, z := range names {
			row.Zones = append(row.Zones, types.ZoneCount{Zone: z, Pods: byZone[z]})
		}
		if len(zones) > 1 {
			lo, hi := -1, 0
			for z := range zones {
				n := byZone[z]
				if n > hi {
					hi = n
				}
				if lo < 0 || n < lo {
					lo = n
				}
			}
			row.Skew = hi - lo
		}
		t.Rows = append(t.Rows, row)
	}
	sort.Slice(t.Rows, func(i, j int) bool {
		a, b := t.Rows[i], t.Rows[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Kind < b.Kind
	})
	t.Total = len(t.Rows)
	if len(t.Rows) > maxPlacementRows {
		t.Rows, t.Truncated = t.Rows[:maxPlacementRows], true
	}
	return t
}

func imageTable(inv *collect.Inventory, opts Options) *types.ImageTable {
	if !observed(inv, "pods") {
		return nil
	}
	type key struct{ registry, repo, ref string }
	type agg struct {
		pods      int
		workloads map[string]bool
		digest    bool
	}
	by := map[key]*agg{}
	owners := derived(inv, opts).ownerIndex()
	for i := range inv.Pods {
		p := &inv.Pods[i]
		if !opts.IncludeSystem && isSystemNamespace(p.Namespace) {
			continue
		}
		w := p.Namespace + "/" + p.Name
		if chain := owners.chain(*p); len(chain) > 0 {
			w = p.Namespace + "/" + chain[0].Kind + "/" + chain[0].Name
		}
		seen := map[key]bool{}
		for _, c := range append(append([]corev1.Container(nil), p.Spec.InitContainers...), p.Spec.Containers...) {
			reg, repo, ref, digest := splitImage(c.Image)
			k := key{reg, repo, ref}
			if seen[k] {
				continue
			}
			seen[k] = true
			a := by[k]
			if a == nil {
				a = &agg{workloads: map[string]bool{}, digest: digest}
				by[k] = a
			}
			a.pods++
			a.workloads[w] = true
		}
	}
	t := &types.ImageTable{}
	for k, a := range by {
		t.Rows = append(t.Rows, types.ImageRow{Registry: k.registry, Repository: k.repo, Ref: k.ref, Digest: a.digest,
			Pods: a.pods, Workloads: len(a.workloads)})
	}
	sort.Slice(t.Rows, func(i, j int) bool {
		a, b := t.Rows[i], t.Rows[j]
		if a.Registry != b.Registry {
			return a.Registry < b.Registry
		}
		if a.Repository != b.Repository {
			return a.Repository < b.Repository
		}
		return a.Ref < b.Ref
	})
	t.Total = len(t.Rows)
	if len(t.Rows) > maxImageRows {
		t.Rows, t.Truncated = t.Rows[:maxImageRows], true
	}
	return t
}

// splitImage is an image reference as registry, repository, tag-or-digest, and whether it is a digest. A
// reference with no registry host is Docker Hub's, as the container runtime resolves it.
func splitImage(ref string) (registry, repo, tag string, digest bool) {
	s := ref
	if i := strings.Index(s, "@"); i >= 0 {
		tag, digest = s[i+1:], true
		s = s[:i]
	}
	registry, repo = "docker.io", s
	if slash := strings.Index(s, "/"); slash >= 0 {
		if first := s[:slash]; strings.ContainsAny(first, ".:") || first == "localhost" {
			registry, repo = strings.ToLower(first), s[slash+1:]
		}
	}
	if c := strings.LastIndex(repo, ":"); c >= 0 && !strings.Contains(repo[c:], "/") {
		if !digest {
			tag = repo[c+1:]
		}
		repo = repo[:c]
	}
	return registry, repo, tag, digest
}

// verdictRules are the findings that say a drain of a node stops, and serializedRule the one that says it is slowed.
var verdictRules = map[string]bool{
	"k8s.reliability.node-drain-budget": true, "k8s.reliability.node-drain-unmanaged-pod": true,
	"k8s.reliability.node-pinned-volume": true, "k8s.reliability.node-loss-feasibility": true,
}

func verdictTable(inv *collect.Inventory, findings []types.Finding) *types.NodeVerdictTable {
	if !observed(inv, "nodes") || !observed(inv, "pods") {
		return nil
	}
	byNode := map[string][]string{}
	serialized := map[string]bool{}
	for _, f := range findings {
		if !verdictRules[f.RuleID] {
			continue
		}
		for _, r := range f.AffectedResources {
			if r.Kind != "Node" {
				continue
			}
			byNode[r.Name] = append(byNode[r.Name], f.ID)
			if f.RuleID == "k8s.reliability.node-drain-budget" && types.FactNum(f.Facts, "drain.rounds") > 0 {
				serialized[r.Name] = true
			}
		}
	}
	t := &types.NodeVerdictTable{}
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		row := types.NodeVerdictRow{Node: n.Name, Zone: collect.ZoneOf(*n), Pool: n.Labels[labelInstanceType], Verdict: "no blocker found"}
		if ids := byNode[n.Name]; len(ids) > 0 {
			sort.Strings(ids)
			row.Findings = ids
			row.Verdict = "blocked"
			if serialized[n.Name] && len(ids) == 1 {
				row.Verdict = "serialized"
			}
		}
		t.Rows = append(t.Rows, row)
	}
	sort.Slice(t.Rows, func(i, j int) bool { return t.Rows[i].Node < t.Rows[j].Node })
	t.Total = len(t.Rows)
	if len(t.Rows) > maxVerdictRows {
		t.Rows, t.Truncated = t.Rows[:maxVerdictRows], true
	}
	return t
}

func rbacGraph(inv *collect.Inventory, findings []types.Finding) *types.RBACGraph {
	for _, k := range []string{"clusterroles", "roles", "clusterrolebindings", "rolebindings"} {
		if !observed(inv, k) {
			return nil
		}
	}
	verbsOf := map[string][]string{}
	collectVerbs := func(key string, rules []rbacv1.PolicyRule) {
		set := map[string]bool{}
		for _, r := range rules {
			for _, v := range r.Verbs {
				set[v] = true
			}
		}
		vs := make([]string, 0, len(set))
		for v := range set {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		verbsOf[key] = vs
	}
	for _, cr := range inv.ClusterRoles {
		collectVerbs("ClusterRole//"+cr.Name, cr.Rules)
	}
	for _, ro := range inv.Roles {
		collectVerbs("Role/"+ro.Namespace+"/"+ro.Name, ro.Rules)
	}
	grantFinding := map[string]string{}
	for _, f := range findings {
		if f.RuleID == "k8s.rbac.dangerous-grant" && f.IDBasis != nil {
			kind := strings.SplitN(f.IDBasis.Kind, "/", 2)[0]
			grantFinding[kind+"/"+f.IDBasis.Namespace+"/"+f.IDBasis.Name] = f.ID
		}
	}
	g := &types.RBACGraph{}
	edge := func(bKind, bNS, bName, rKind, rName, roleNS string, subjects []rbacv1.Subject) {
		key := rKind + "/" + roleNS + "/" + rName
		for _, s := range subjects {
			ns := s.Namespace
			if s.Kind != "ServiceAccount" {
				ns = ""
			}
			g.Edges = append(g.Edges, types.RBACEdge{SubjectKind: s.Kind, SubjectNamespace: ns, SubjectName: s.Name,
				BindingKind: bKind, BindingNamespace: bNS, BindingName: bName, RoleKind: rKind, RoleName: rName,
				Verbs: verbsOf[key], Finding: grantFinding[key]})
		}
	}
	for _, b := range inv.ClusterRoleBindings {
		edge("ClusterRoleBinding", "", b.Name, b.RoleRef.Kind, b.RoleRef.Name, "", b.Subjects)
	}
	for _, b := range inv.RoleBindings {
		roleNS := ""
		if b.RoleRef.Kind == "Role" {
			roleNS = b.Namespace
		}
		edge("RoleBinding", b.Namespace, b.Name, b.RoleRef.Kind, b.RoleRef.Name, roleNS, b.Subjects)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		ka := a.SubjectKind + "/" + a.SubjectNamespace + "/" + a.SubjectName + "|" + a.BindingKind + "/" + a.BindingNamespace + "/" + a.BindingName
		kb := b.SubjectKind + "/" + b.SubjectNamespace + "/" + b.SubjectName + "|" + b.BindingKind + "/" + b.BindingNamespace + "/" + b.BindingName
		return ka < kb
	})
	g.Total = len(g.Edges)
	if len(g.Edges) > maxRBACEdges {
		g.Edges, g.Truncated = g.Edges[:maxRBACEdges], true
	}
	return g
}

func capacityTable(inv *collect.Inventory, opts Options) *types.CapacityTable {
	if !observed(inv, "nodes") || !observed(inv, "pods") {
		return nil
	}
	provider := providerFromNodes(inv.Nodes)
	poolOf := map[string]string{}
	rows := map[string]*types.CapacityRow{}
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		pool := n.Labels[labelInstanceType]
		if pool == "" {
			pool = "(no instance type)"
		}
		pool += " · " + string(collect.ClassifyCapacityType(provider, *n))
		poolOf[n.Name] = pool
		r := rows[pool]
		if r == nil {
			r = &types.CapacityRow{Pool: pool}
			rows[pool] = r
		}
		r.Nodes++
		r.AllocatableCPU += float64(n.Status.Allocatable.Cpu().MilliValue())
		r.AllocatableMem += float64(n.Status.Allocatable.Memory().Value())
	}
	used := map[string]bool{}
	for i := range inv.Pods {
		p := inv.Pods[i]
		pool := poolOf[p.Spec.NodeName]
		r := rows[pool]
		if r == nil || !holdsRoom(p) {
			continue
		}
		cpu, mem := podRequests(p)
		r.RequestedCPU += float64(cpu.MilliValue())
		r.RequestedMem += float64(mem.Value())
		for _, c := range p.Spec.Containers {
			if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				r.LimitsMem += float64(q.Value())
			}
			if u, ok := opts.Usage[p.Namespace+"/"+p.Name+"/"+c.Name]; ok {
				r.UsedCPU += u.CPUCoresP95 * 1000
				r.UsedMem += u.MemBytesP95
				used[pool] = true
			}
		}
	}
	basis := usedBasis(opts)
	t := &types.CapacityTable{}
	for pool, r := range rows {
		if r.AllocatableMem > 0 {
			r.MemoryOvercommit = r.LimitsMem / r.AllocatableMem
		}
		if used[pool] {
			r.UsedBasis = basis
		}
		t.Rows = append(t.Rows, *r)
	}
	sort.Slice(t.Rows, func(i, j int) bool { return t.Rows[i].Pool < t.Rows[j].Pool })
	return t
}

// usedBasis is what a pool's "used" figure is, by the usage source it came from (ENG-51).
func usedBasis(opts Options) string {
	switch usageStat(opts) {
	case "VPA target":
		return "the sum of the VerticalPodAutoscaler targets of the pool's containers: its estimate, not a measurement"
	case "one-moment sample":
		return "the sum of the pool's containers at one moment"
	}
	return "the sum of each container's " + usageSpan(opts) + " p95: an upper bound on the pool's own p95, since containers rarely peak together"
}
