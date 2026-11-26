package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// reconcileSpend counts each node's bill once across the findings that price it (ENG-08).
//
// THE HEADLINE ADDED TWO PRICES OF ONE MACHINE. A workload rightsized on a node reclaims a share of that node at
// its current price; the pool's instance-generation lag claims the difference between the current price and a
// newer type's on the same node. Rightsize and remove capacity, and the lag on the capacity removed is no longer
// paid by anyone — the two were added as if both applied in full. So on each node:
//
//	f = min(Σ rightsizing shares ÷ node price, 1)   the share of the node the rightsizing reclaims
//	each generation share g becomes g × (1 − f)      the lag is saved only on the capacity that stays
//
// and then, for anything still overlapping, the shares on one node are scaled down to the node's price, so no
// node's findings ever add up to more than the node costs. A finding whose dollar moves says so in its evidence,
// with the figure before. Shares are at list, before any discount (BuildReport applies it after), as the prices are.
func reconcileSpend(findings []types.Finding, price map[string]float64) {
	type ref struct{ f, s int }
	byNode := map[string][]ref{}
	for i := range findings {
		for j, s := range findings[i].SpendNodes {
			byNode[s.Node] = append(byNode[s.Node], ref{i, j})
		}
	}
	nodes := make([]string, 0, len(byNode))
	for n, rs := range byNode {
		if len(rs) > 1 {
			nodes = append(nodes, n)
		}
	}
	sort.Strings(nodes)
	before := map[int]float64{}
	counted := map[int]map[string]bool{} // finding → the other findings' titles it overlapped
	note := func(i int, other string) {
		if _, ok := before[i]; !ok {
			before[i] = findings[i].DollarImpactMonthly
		}
		if counted[i] == nil {
			counted[i] = map[string]bool{}
		}
		counted[i][other] = true
	}
	for _, n := range nodes {
		p := price[n]
		if p <= 0 {
			continue
		}
		rs := byNode[n]
		reclaimed, rightsizers := 0.0, []string{}
		for _, r := range rs {
			if findings[r.f].RuleID == rightsizingRule {
				reclaimed += findings[r.f].SpendNodes[r.s].USD
				rightsizers = append(rightsizers, findings[r.f].Title)
			}
		}
		if f := min(reclaimed/p, 1); f > 0 {
			for _, r := range rs {
				if findings[r.f].RuleID == rightsizingRule {
					continue
				}
				for _, t := range rightsizers {
					note(r.f, t)
				}
				findings[r.f].SpendNodes[r.s].USD *= 1 - f
			}
		}
		total := 0.0
		for _, r := range rs {
			total += findings[r.f].SpendNodes[r.s].USD
		}
		if total > p {
			for _, r := range rs {
				for _, o := range rs {
					if o.f != r.f {
						note(r.f, findings[o.f].Title)
					}
				}
				findings[r.f].SpendNodes[r.s].USD *= p / total
			}
		}
	}
	idx := make([]int, 0, len(before))
	for i := range before {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		sum := 0.0
		for _, s := range findings[i].SpendNodes {
			sum += s.USD
		}
		findings[i].DollarImpactMonthly = sum
		others := make([]string, 0, len(counted[i]))
		for t := range counted[i] {
			others = append(others, "\""+t+"\"")
		}
		sort.Strings(others)
		findings[i].Evidence = append(append([]string(nil), findings[i].Evidence...), fmt.Sprintf(
			"counted once: $%.2f/mo of this figure prices the same nodes as %s, and the headline counts $%.2f/mo of it "+
				"— on each node the findings together never add up to more than the node costs", before[i]-sum,
			strings.Join(others, ", "), sum))
	}
}

// rightsizingRule is the rule whose shares are capacity reclaimed, not a price difference.
const rightsizingRule = "k8s.cost.overprovisioned-resources"
