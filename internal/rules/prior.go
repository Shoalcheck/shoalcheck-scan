package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// PriorReading is what an earlier reading of the same cluster said about its node pools — the one thing a rule
// may learn from history today. It is a list of observed states with their timestamps, never a rate: readings
// happen when the operator runs them, and three of them may span three days or three months.
type PriorReading struct {
	At    time.Time
	Pools []PriorPool
}

// PriorPool is one node pool as an earlier reading summarised it.
type PriorPool struct {
	Type     string
	Capacity types.CapacityType
	Count    int
}

// steadinessLine states in how many of the earlier readings kept on this machine a pool of exactly this type,
// capacity and size was present. It is the first engine consumer of the time axis, and it stays evidence: the
// commitment rule's figure remains unbanked because whether a plan already covers the pool is a billing-account
// fact no reading carries. ok is false when there are no earlier readings — a line reading "0 of 0" would be a
// claim about an absence of history, not about the pool.
func steadinessLine(opts Options, itype string, capacity types.CapacityType, count int) (string, bool) {
	if len(opts.PriorReadings) == 0 {
		return "", false
	}
	readings := append([]PriorReading(nil), opts.PriorReadings...)
	sort.Slice(readings, func(i, j int) bool { return readings[i].At.Before(readings[j].At) })
	seen := 0
	for _, r := range readings {
		for _, p := range r.Pools {
			if p.Type == itype && p.Capacity == capacity && p.Count == count {
				seen++
				break
			}
		}
	}
	first, last := readings[0].At.UTC().Format("Jan 2, 2006"), readings[len(readings)-1].At.UTC().Format("Jan 2, 2006")
	span := first
	if last != first {
		span = first + " – " + last
	}
	return fmt.Sprintf("a pool of %d %s %s %s was present in %d of the %s kept on this machine (%s) — "+
		"observed states, not a rate; whether it holds next month is in no reading", count, itype, capacity,
		pick(count, "node", "nodes"), seen, nWord(len(readings), "earlier reading", "earlier readings"), span), true
}
