package rules

import (
	"fmt"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// CommitmentCandidate states what an on-demand node pool WOULD cost under a Compute Savings Plan, and
// refuses to count it.
//
// THE REFUSAL IS THE DESIGN. A reservation is a one- or three-year promise, and this reading is a snapshot:
// it cannot see whether the footprint it counted this morning existed last month or will exist next week.
// A figure banked on that evidence would be the product recommending a bet and calling it a saving. So the
// number is in the evidence, with the two conditions a reader must satisfy before it means anything — the
// footprint holds across readings (the app's history is where that is checked), and no plan already covers
// it (a billing-account fact this reading cannot see) — and DollarImpactMonthly is zero. node_headroom
// does the same for a requests-only figure; instance-generation-lag does it for Graviton.
//
// The rate is the flexible Compute plan, No Upfront: the least-discounting plan AWS sells, so the would-be
// figure is an upper bound in the same direction as every other figure in the report.
type CommitmentCandidate struct{}

func (CommitmentCandidate) ID() string      { return "k8s.cost.commitment-candidate" }
func (CommitmentCandidate) Version() string { return "1.0.0" }

func (CommitmentCandidate) RequiredKinds() []string { return []string{"nodes"} }

type commitPool struct {
	itype  string
	region string
	nodes  []string
}

func (r CommitmentCandidate) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if providerFromNodes(inv.Nodes) != "aws" {
		return nil // the rate table is AWS-only; saying nothing beats saying something unguarded
	}
	pools := map[string]*commitPool{}
	for i := range inv.Nodes {
		n := inv.Nodes[i]
		itype := n.Labels[labelInstanceType]
		// ONLY ON-DEMAND. A spot pool is already discounted and a commitment on it is a different question;
		// an unknown capacity is not evidence of anything.
		if itype == "" || collect.ClassifyCapacityType("aws", n) != types.CapacityOnDemand {
			continue
		}
		region := collect.RegionOf(n)
		k := itype + "|" + region
		p := pools[k]
		if p == nil {
			p = &commitPool{itype: itype, region: region}
			pools[k] = p
		}
		p.nodes = append(p.nodes, n.Name)
	}
	var out []types.Finding
	for _, p := range pools {
		list, ok := opts.nodeMonthly("aws", p.region, p.itype, types.CapacityOnDemand)
		if !ok {
			continue
		}
		one, ok1 := opts.prices().SavingsPlanHourly(p.region, "1yr", p.itype)
		three, ok3 := opts.prices().SavingsPlanHourly(p.region, "3yr", p.itype)
		if !ok1 && !ok3 {
			continue
		}
		n := float64(len(p.nodes))
		line := func(term string, hourly float64, ok bool) string {
			if !ok {
				return fmt.Sprintf("%s: no published Compute Savings Plan rate for %s in %s", term, p.itype, p.region)
			}
			monthly := hourly * 730 * n
			return fmt.Sprintf("%s No Upfront: $%.4f/h per node — %s/mo for the pool against %s at list, %.0f%% less",
				term, hourly, types.USD(monthly), types.USD(list*n), (1-monthly/(list*n))*100)
		}
		sort.Strings(p.nodes)
		shown := p.nodes
		if len(shown) > 8 {
			shown = shown[:8]
		}
		evidence := []string{
			snapshotNote(inv),
			fmt.Sprintf("%s of %s in %s, list %s/mo each (%s/mo for the pool)", nWord(len(p.nodes), "on-demand node", "on-demand nodes"), p.itype, p.region, types.USD(list), types.USD(list*n)),
			line("1yr", one, ok1),
			line("3yr", three, ok3),
			"NOT BANKED, AND NOT BECAUSE IT COULD NOT BE PRICED. This reading is one moment; a commitment is one or " +
				"three years. Whether this footprint held last month or will hold next month is not in the snapshot — " +
				"the app's past readings are where that is checked — and whether a plan already covers these nodes is " +
				"a billing-account fact no cluster object carries. Both must be true before the difference above is a " +
				"saving; until then it is the price of a decision, stated so you can make it.",
			"rate: Compute Savings Plan, the flexible and least-discounting plan AWS sells; an EC2 Instance Savings " +
				"Plan on this family would discount more and commit harder. Linux, shared tenancy, list prices in this region.",
		}
		// The time axis, where it exists: earlier readings say whether this footprint was there before. Stated,
		// and still not banked — the other condition (no plan already covers it) is in no reading at all.
		if line, ok := steadinessLine(opts, p.itype, types.CapacityOnDemand, len(p.nodes)); ok {
			evidence = append(evidence, line)
		}
		refs := make([]types.ResourceRef, 0, len(shown))
		for _, name := range shown {
			refs = append(refs, types.ResourceRef{Kind: "Node", Name: name})
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "NodePool", p.region, p.itype),
			IDBasis:     &types.ResourceRef{Kind: "NodePool", Namespace: p.region, Name: p.itype},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("%d %s %s on-demand where a Savings Plan is published", len(p.nodes), p.itype,
				pick(len(p.nodes), "node runs", "nodes run")),
			Description: fmt.Sprintf("The %s pool (%s) is billed at on-demand list. AWS publishes a Compute Savings Plan rate "+
				"for this type in this region; the evidence states what the pool would cost under it and the two conditions "+
				"under which that figure is real. Nothing is counted toward the headline.", p.itype, nWord(len(p.nodes), "node", "nodes")),
			WhyItMatters: "On-demand is the price of not having decided. A pool that has run unchanged for a year has paid " +
				"the list premium for a year; a pool created last week has not, and the snapshot cannot tell the two apart — " +
				"which is why this states the difference and declines to sum it.",
			Evidence:            evidence,
			Severity:            types.SeverityInfo,
			Category:            types.CategoryCost,
			DollarImpactMonthly: 0,
			PriceBasis:          types.PriceUnpriced, // the same filing as generation-lag's Graviton case: stated, not summed
			SpendKind:           types.SpendCompute,
			EstimatedEffort:     types.EffortHigh,
			Confidence:          1.0,
			AffectedResources:   refs,
			Provenance:          provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
