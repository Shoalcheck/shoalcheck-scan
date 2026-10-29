package pipeline

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
	"github.com/Shoalcheck/shoalcheck-scan/internal/rules"
)

// PriorReadings summarises the newest `limit` readings of a cluster in the history store as the node pools each
// one recorded — the read-only view of the time axis a rule may consult (rules.Options.PriorReadings). Snapshots
// that fail to load are skipped rather than failing the audit: history is the caller's convenience, never a
// dependency of the reading. Returned oldest-first; nil when the store holds nothing for the cluster.
func PriorReadings(store *history.Store, cluster string, limit int) []rules.PriorReading {
	if store == nil || limit <= 0 {
		return nil
	}
	snaps, err := store.List(cluster)
	if err != nil || len(snaps) == 0 {
		return nil
	}
	if len(snaps) > limit {
		snaps = snaps[:limit]
	}
	var out []rules.PriorReading
	for _, sn := range snaps {
		ar, err := store.Load(sn.Path)
		if err != nil || ar.Architecture == nil {
			continue
		}
		r := rules.PriorReading{At: sn.At}
		for _, p := range ar.Architecture.NodePools {
			r.Pools = append(r.Pools, rules.PriorPool{Type: p.Type, Capacity: p.Capacity, Count: p.Count})
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
