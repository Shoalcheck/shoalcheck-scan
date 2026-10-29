// Package divergence answers one question about a fleet: what do these clusters DECLARE differently?
//
// Spec: `docs/superpowers/specs/2026-08-28-fleet-divergence-design.md`.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY THIS IS NOT internal/history's COMPARISON ENGINE, AND THAT IS A FEATURE
//
// `history.Compute` refuses to compare two readings whose ClusterUID differs — deliberately, because a
// comparison across clusters presented as a change over time would report another cluster's state as this
// cluster's regression. Every member of a fleet has a different UID, so the gate that makes history correct
// is the gate that makes it unusable here. This engine is a second one, and the refusal it inherits is
// asserted rather than assumed: see TestDivergence_CannotBeBuiltFromHistoryCompute.
//
// A SECOND, QUIETER REASON THE FINDING LAYER IS THE WRONG LAYER. findingID is
// sha256(ruleID|kind|ns|name), so a finding about namespace `payments` in staging and one in production
// carry the IDENTICAL id, while the drain rules put the NODE NAME into their composite key and therefore
// never match across clusters. An ID-keyed cross-cluster diff would silently match one family and silently
// fail to match another, with no signal distinguishing the two.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CLAIM BOUNDARY, and it is narrow on purpose
//
//	NO VERDICT. Not "misconfigured", not "wrong", not "should match". The supportable form is
//	"these clusters declare different values for X".
//
//	"DRIFT" IS NOT USABLE HERE even though internal/lexicon does not ban it globally. It asserts a shared
//	origin that moved apart, and we did not read an origin. The family's own banned-phrase test enforces it.
//
//	NO SCALE COMPARISON AT ALL. Replica counts, node counts, instance types, request values and pod counts
//	are expected to differ. The exclusion is structural: types.NamespacePosture carries no such field, so
//	this engine could not render one if it tried.
//
//	NO COST COMPARISON. Two clusters in two regions price differently for reasons that are not policy.
//
//	BELOW TWO AUDITED CLUSTERS, SILENCE. A single-cluster fleet run and a fleet run where N-1 clusters were
//	skipped are the same case and produce the same nil.
package divergence

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// dimension identifiers. Stable strings, because they are keys a surface and a later comparison both read.
const (
	DimPSSEnforce    = "pod-security.enforce"
	DimPSSAudit      = "pod-security.audit"
	DimPSSWarn       = "pod-security.warn"
	DimNetworkPolicy = "networkpolicy.present"
	DimResourceQuota = "resourcequota.present"
	DimLimitRange    = "limitrange.present"
	DimOperators     = "operators.installed"
)

// absent is how a read-but-undeclared value is spelled. A BLANK CELL READS AS "no data" and this state is
// the opposite: the namespace was read and declares nothing, which for Pod Security Admission means the
// cluster default governs it — a real and different posture from any explicit level.
const absent = "(not declared)"

// Compute builds the divergence surface for a fleet, or nil when there is nothing to compare.
//
// `unreached` is carried in rather than derived, because a cluster that could not be audited leaves no
// report to derive it from — which is precisely why it must appear here and not only in the overview.
func Compute(reports []*types.AuditReport, unreached []types.SkippedCluster) *types.FleetDivergence {
	var named []*types.AuditReport
	for _, r := range reports {
		if r != nil && r.Cluster.Name != "" {
			named = append(named, r)
		}
	}
	// TWO AUDITED CLUSTERS IS THE FLOOR, and "audited" means a report exists. A fleet of five where four
	// were skipped has one report and compares nothing, which is the same case as a single-cluster run.
	if len(named) < 2 {
		return nil
	}
	sort.Slice(named, func(i, j int) bool { return named[i].Cluster.Name < named[j].Cluster.Name })

	d := &types.FleetDivergence{Unreached: unreached}
	for _, r := range named {
		d.Clusters = append(d.Clusters, r.Cluster.Name)
	}

	posture := map[string]*types.PolicyPosture{}
	for _, r := range named {
		posture[r.Cluster.Name] = r.PolicyPosture
	}

	compareOperators(d, named, posture)
	compareNamespaces(d, named, posture)

	sort.Slice(d.Rows, func(i, j int) bool {
		if d.Rows[i].Scope != d.Rows[j].Scope {
			return d.Rows[i].Scope < d.Rows[j].Scope
		}
		return d.Rows[i].Dimension < d.Rows[j].Dimension
	})
	sort.Slice(d.NotCompared, func(i, j int) bool {
		if d.NotCompared[i].Scope != d.NotCompared[j].Scope {
			return d.NotCompared[i].Scope < d.NotCompared[j].Scope
		}
		return d.NotCompared[i].Dimension < d.NotCompared[j].Dimension
	})
	return d
}

// observation is one cluster's reading of one dimension.
type observation struct {
	cluster string
	value   string
	read    bool
}

// classify sorts a dimension's observations into the three states and records the result on d.
//
// THE ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. Unreadability is checked FIRST, before equality: if any
// cluster could not read the dimension, the dimension is not compared AT ALL, even when every cluster that
// could read it agreed. Reporting "same" from a subset would tell a reader the fleet agrees on something a
// third of it was never asked about.
func classify(d *types.FleetDivergence, scope, dim string, obs []observation) {
	var blocked []string
	for _, o := range obs {
		if !o.read {
			blocked = append(blocked, o.cluster)
		}
	}
	if len(blocked) > 0 {
		sort.Strings(blocked)
		d.NotComparedCount++
		d.NotCompared = append(d.NotCompared, types.NotComparedDimension{
			Scope: scope, Dimension: dim, Blocked: blocked})
		return
	}
	byValue := map[string][]string{}
	for _, o := range obs {
		byValue[o.value] = append(byValue[o.value], o.cluster)
	}
	if len(byValue) <= 1 {
		d.SameCount++
		return
	}
	values := make([]string, 0, len(byValue))
	for v := range byValue {
		values = append(values, v)
	}
	sort.Strings(values)
	row := types.DivergenceRow{Scope: scope, Dimension: dim}
	for _, v := range values {
		cs := byValue[v]
		sort.Strings(cs)
		row.Values = append(row.Values, types.DivergenceValue{Value: v, Clusters: cs})
	}
	d.Rows = append(d.Rows, row)
}

func compareOperators(d *types.FleetDivergence, named []*types.AuditReport, posture map[string]*types.PolicyPosture) {
	var obs []observation
	for _, r := range named {
		p := posture[r.Cluster.Name]
		if p == nil || !p.OperatorsRead {
			obs = append(obs, observation{cluster: r.Cluster.Name, read: false})
			continue
		}
		v := absent
		if len(p.Operators) > 0 {
			v = joinSorted(p.Operators)
		}
		obs = append(obs, observation{cluster: r.Cluster.Name, value: v, read: true})
	}
	classify(d, "cluster", DimOperators, obs)
}

func compareNamespaces(d *types.FleetDivergence, named []*types.AuditReport, posture map[string]*types.PolicyPosture) {
	// Which clusters saw which namespace. A cluster whose namespace list was not read contributes NOTHING
	// here — it is neither present nor absent, because a refused list cannot tell us either. Its
	// unreadability surfaces through the per-dimension observations instead.
	present := map[string]map[string]bool{}
	nsRead := map[string]bool{}
	for _, r := range named {
		p := posture[r.Cluster.Name]
		nsRead[r.Cluster.Name] = p != nil && len(p.Namespaces) > 0
		if p == nil {
			continue
		}
		for i := range p.Namespaces {
			n := p.Namespaces[i].Name
			if present[n] == nil {
				present[n] = map[string]bool{}
			}
			present[n][r.Cluster.Name] = true
		}
	}
	names := make([]string, 0, len(present))
	for n := range present {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		var have, lack []string
		for _, r := range named {
			c := r.Cluster.Name
			if !nsRead[c] {
				// Not counted as absent: a cluster whose namespace list we could not read has not been
				// shown to lack anything.
				continue
			}
			if present[n][c] {
				have = append(have, c)
			} else {
				lack = append(lack, c)
			}
		}
		if len(lack) > 0 {
			// A MEMBERSHIP DIFFERENCE, REPORTED ONCE, and the dimensions inside are NOT compared. Saying
			// "cluster B declares no Pod Security label on payments" when payments does not exist in
			// cluster B is a false sentence, not a weaker one.
			sort.Strings(have)
			sort.Strings(lack)
			d.NamespaceMembership = append(d.NamespaceMembership, types.NamespaceMembership{
				Namespace: n, Present: have, Absent: lack})
			continue
		}
		compareOneNamespace(d, n, named, posture)
	}
	sort.Slice(d.NamespaceMembership, func(i, j int) bool {
		return d.NamespaceMembership[i].Namespace < d.NamespaceMembership[j].Namespace
	})
}

func compareOneNamespace(d *types.FleetDivergence, ns string, named []*types.AuditReport,
	posture map[string]*types.PolicyPosture) {

	find := func(c string) *types.NamespacePosture {
		p := posture[c]
		if p == nil {
			return nil
		}
		for i := range p.Namespaces {
			if p.Namespaces[i].Name == ns {
				return &p.Namespaces[i]
			}
		}
		return nil
	}

	type dim struct {
		id    string
		value func(*types.NamespacePosture) string
		read  func(*types.NamespacePosture) bool
	}
	// PRESENCE, NOT COUNT, for the three object dimensions. Three NetworkPolicies in one cluster and five in
	// another is not a policy difference — it is two teams writing rules at different granularities — and a
	// row per count would fill the surface with noise the reader has to learn to ignore.
	dims := []dim{
		{DimPSSEnforce, func(p *types.NamespacePosture) string { return orAbsent(p.PodSecurity.Enforce) },
			func(p *types.NamespacePosture) bool { return p.PodSecurityRead }},
		{DimPSSAudit, func(p *types.NamespacePosture) string { return orAbsent(p.PodSecurity.Audit) },
			func(p *types.NamespacePosture) bool { return p.PodSecurityRead }},
		{DimPSSWarn, func(p *types.NamespacePosture) string { return orAbsent(p.PodSecurity.Warn) },
			func(p *types.NamespacePosture) bool { return p.PodSecurityRead }},
		{DimNetworkPolicy, func(p *types.NamespacePosture) string { return presence(p.NetworkPolicies) },
			func(p *types.NamespacePosture) bool { return p.NetworkPoliciesRead }},
		{DimResourceQuota, func(p *types.NamespacePosture) string { return presence(p.ResourceQuotas) },
			func(p *types.NamespacePosture) bool { return p.ResourceQuotasRead }},
		{DimLimitRange, func(p *types.NamespacePosture) string { return presence(p.LimitRanges) },
			func(p *types.NamespacePosture) bool { return p.LimitRangesRead }},
	}

	for _, dm := range dims {
		var obs []observation
		for _, r := range named {
			c := r.Cluster.Name
			np := find(c)
			if np == nil || !dm.read(np) {
				obs = append(obs, observation{cluster: c, read: false})
				continue
			}
			obs = append(obs, observation{cluster: c, value: dm.value(np), read: true})
		}
		classify(d, ns, dm.id, obs)
	}
}

func orAbsent(s string) string {
	if s == "" {
		return absent
	}
	return s
}

// presence renders a count as a presence statement. The count itself never leaves this function.
func presence(n int) string {
	if n > 0 {
		return "declared"
	}
	return "none declared"
}

func joinSorted(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	s := ""
	for i, v := range out {
		if i > 0 {
			s += ", "
		}
		s += v
	}
	return s
}
