// servicemap.go is the pure resolver + applier for the observed service map. It
// imports NO Prometheus client — prom.BuildObservedGraph already produced plain
// types.ObservedEdge structs; this file only maps mesh names onto the exact
// "Kind/Name" WorkloadNode IDs buildTopologies emits and upgrades the report's
// Architecture.Tier. The pipeline (which imports both prom and collect) bridges
// prom.ObservedGraph to ApplyObservedGraph's interface, so collect stays a leaf
// package and cycle-free.
package collect

import (
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ResolveWorkloadID returns a closure mapping (namespace, meshWorkloadName) to
// the "Kind/Name" WorkloadNode ID buildTopologies emits, or "" when unmapped.
// Built from the same Deployment/StatefulSet/DaemonSet inventory the declared
// topology drew, so observed edges land on the EXACT nodes already on the map.
// An unmapped name is the caller's external/unknown signal — this never invents
// an ID.
func ResolveWorkloadID(inv *Inventory) func(ns, workload string) string {
	// index[ns][name] = "Kind/Name"
	index := map[string]map[string]string{}
	put := func(ns, kind, name string) {
		if index[ns] == nil {
			index[ns] = map[string]string{}
		}
		index[ns][name] = kind + "/" + name
	}
	for i := range inv.Deployments {
		d := &inv.Deployments[i]
		put(d.Namespace, "Deployment", d.Name)
	}
	for i := range inv.StatefulSets {
		s := &inv.StatefulSets[i]
		put(s.Namespace, "StatefulSet", s.Name)
	}
	for i := range inv.DaemonSets {
		d := &inv.DaemonSets[i]
		put(d.Namespace, "DaemonSet", d.Name)
	}
	return func(ns, workload string) string {
		if m, ok := index[ns]; ok {
			return m[workload] // "" when the name isn't a known workload
		}
		return ""
	}
}

// ObservedGraphInput is the collect-local view of a prom.ObservedGraph. The
// pipeline adapts the concrete prom struct to this interface so collect never
// imports prom (cycle-free). It is exported (and its methods are exported)
// because Go requires both for a type in another package to satisfy it.
type ObservedGraphInput interface {
	GraphSource() string
	GraphWindow() string
	GraphAsOf() time.Time
	GraphNote() string
	GraphEdges() []types.ObservedEdge
}

// ApplyObservedGraph upgrades arch from its assembly-time TierDeclared to
// TierObserved and copies the observed data. A detected-but-empty graph (Note
// set, zero edges) still upgrades to observed with the Note — it is a state, not
// a downgrade. Nil arch or nil graph is a no-op (degrade-gracefully). A zero
// as-of time leaves ObservedAsOf nil so the field stays omitted on serialize.
func ApplyObservedGraph(arch *types.Architecture, g ObservedGraphInput) {
	if arch == nil || g == nil {
		return
	}
	arch.Tier = types.TierObserved
	arch.ObservedEdges = g.GraphEdges()
	arch.ObservedSource = g.GraphSource()
	arch.ObservedWindow = g.GraphWindow()
	if t := g.GraphAsOf(); !t.IsZero() {
		tt := t
		arch.ObservedAsOf = &tt
	}
	arch.ObservedNote = g.GraphNote()
}
