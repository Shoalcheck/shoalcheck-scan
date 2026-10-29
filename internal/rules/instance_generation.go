package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// InstanceGenerationLag reports node pools running an instance type for which the same provider lists an
// EQUIVALENT type — same vCPU, at least the memory, same size label, same family line — at a lower price.
//
// THE MEASUREMENT THAT SHAPED THIS RULE, taken across every AWS region and type in the table on 2026-09-02:
//
//	same processor class, newer generation, strictly cheaper    6.4% of (type, region) pairs
//	AMD ("a") or Graviton ("g") variant, same size, cheaper     60.8%, median 23% lower
//
// So "a newer generation is cheaper" is mostly FALSE on AWS — m5 and m6i list at parity, m7i above both —
// and a rule built on that hypothesis alone would fire on t2/m4/r4/c4 fleets and nowhere else. The money
// is in the processor-class change, and that is where the honesty problem is, so the rule is tiered:
//
//	A  same class, newer generation     the same machine, later. Bankable.
//	B  AMD variant, same architecture   x86-64 either way, so every image runs. Bankable, and disclosed.
//	C  Graviton variant                 arm64. Whether the workloads' images run there is a REGISTRY fact
//	                                    this reading cannot see, so the figure goes in the evidence and
//	                                    NEVER in DollarImpactMonthly — node_headroom's precedent for a
//	                                    would-be figure that is not bankable.
//
// WHAT IT REFUSES TO COMPARE, because vCPU and memory are not the whole shape there: accelerator families
// (g, p, inf, trn, dl, f, vt), storage-optimised families and any type with local NVMe (a "d" in the
// suffix), metal and specialty families (mac, u-, hpc), and the burst-limited "-flex" variants as a
// target. The family allowlist is m, c, r, t, x, z — the families where the published shape IS the machine.
type InstanceGenerationLag struct{}

func (InstanceGenerationLag) ID() string      { return "k8s.cost.instance-generation-lag" }
func (InstanceGenerationLag) Version() string { return "1.0.0" }

func (InstanceGenerationLag) RequiredKinds() []string { return []string{"nodes"} }

// awsType is one AWS instance type name taken apart. m6idn.2xlarge -> family m, gen 6, vendor i,
// extras dn, dash "", size 2xlarge. c7i-flex.large -> c, 7, i, "", "-flex", large.
type awsType struct {
	family string
	gen    int
	vendor string // "" | "i" | "a" | "g"
	extras string
	dash   string
	size   string
}

var awsTypeRe = regexp.MustCompile(`^([a-z]+)(\d+)([a-z]*)((?:-[a-z]+)*)\.([a-z0-9]+)$`)

// comparableFamilies are the ones where vCPU + memory describe the machine. Everything else carries a
// component the shape table does not: a GPU, local NVMe, a bare-metal host, a Mac.
var comparableFamilies = map[string]bool{"m": true, "c": true, "r": true, "t": true, "x": true, "z": true}

func parseAWSType(s string) (awsType, bool) {
	m := awsTypeRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return awsType{}, false
	}
	gen, err := strconv.Atoi(m[2])
	if err != nil {
		return awsType{}, false
	}
	t := awsType{family: m[1], gen: gen, dash: m[4], size: m[5]}
	letters := m[3]
	if letters != "" && strings.ContainsRune("iag", rune(letters[0])) {
		t.vendor, t.extras = letters[:1], letters[1:]
	} else {
		t.extras = letters
	}
	return t, true
}

// comparable says whether a type is one this rule will reason about at all — as a source OR a target.
func (t awsType) comparable() bool {
	return comparableFamilies[t.family] && !strings.Contains(t.extras, "d")
}

// sameLine: same family, same extras, same dash suffix, same size — everything but generation and vendor.
func (t awsType) sameLine(o awsType) bool {
	return t.family == o.family && t.extras == o.extras && t.dash == o.dash && t.size == o.size
}

// equivalentShape is the guard: a target must have the SAME vCPU count and AT LEAST the memory. Names
// alone are not enough — a size label is a convention, and this is what makes "equivalent" a fact.
func equivalentShape(cur, cand pricing.Shape) bool {
	return cand.VCPU == cur.VCPU && cand.MemGiB >= cur.MemGiB
}

type genPool struct {
	itype    string
	capacity types.CapacityType
	region   string
	nodes    []string
	arch     string
}

type genCandidate struct {
	itype   string
	monthly float64
	shape   pricing.Shape
}

func (r InstanceGenerationLag) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	provider := providerFromNodes(inv.Nodes)
	if provider != "aws" {
		// The shape table is AWS-only today, and without a published shape for BOTH ends of a comparison
		// "equivalent" is a guess. Azure and GCP say nothing here rather than something unguarded.
		return nil
	}

	type key struct {
		itype    string
		capacity types.CapacityType
		region   string
	}
	pools := map[key]*genPool{}
	for i := range inv.Nodes {
		n := inv.Nodes[i]
		itype := n.Labels[labelInstanceType]
		if itype == "" {
			continue
		}
		k := key{itype, collect.ClassifyCapacityType(provider, n), collect.RegionOf(n)}
		p := pools[k]
		if p == nil {
			p = &genPool{itype: itype, capacity: k.capacity, region: k.region, arch: n.Status.NodeInfo.Architecture}
			pools[k] = p
		}
		p.nodes = append(p.nodes, n.Name)
	}

	var out []types.Finding
	for _, p := range pools {
		if f, ok := r.evaluatePool(inv, opts, p); ok {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r InstanceGenerationLag) evaluatePool(inv *collect.Inventory, opts Options, p *genPool) (types.Finding, bool) {
	cur, ok := parseAWSType(p.itype)
	if !ok || !cur.comparable() {
		return types.Finding{}, false
	}
	curShape, ok := opts.prices().NodeShape("aws", p.itype)
	if !ok {
		return types.Finding{}, false
	}
	curMonthly, ok := opts.nodeMonthly("aws", p.region, p.itype, p.capacity)
	if !ok {
		return types.Finding{}, false
	}

	var tierA, tierB, tierC *genCandidate
	consider := func(slot **genCandidate, c genCandidate) {
		if *slot == nil || c.monthly < (*slot).monthly {
			cc := c
			*slot = &cc
		}
	}
	for _, name := range opts.prices().TypesInRegion("aws", p.region) {
		if name == p.itype {
			continue
		}
		cand, ok := parseAWSType(name)
		if !ok || !cand.comparable() || !cand.sameLine(cur) {
			continue
		}
		shape, ok := opts.prices().NodeShape("aws", name)
		if !ok || !equivalentShape(curShape, shape) {
			continue
		}
		monthly, ok := opts.nodeMonthly("aws", p.region, name, p.capacity)
		if !ok || monthly >= curMonthly {
			continue
		}
		c := genCandidate{itype: name, monthly: monthly, shape: shape}
		switch {
		case cand.vendor == cur.vendor && cand.gen > cur.gen:
			consider(&tierA, c)
		case cand.vendor == "a" && (cur.vendor == "" || cur.vendor == "i") && cand.gen >= cur.gen:
			consider(&tierB, c)
		case cand.vendor == "g" && cur.vendor != "g" && cand.gen >= cur.gen:
			consider(&tierC, c)
		}
	}
	if tierA == nil && tierB == nil && tierC == nil {
		return types.Finding{}, false
	}

	n := float64(len(p.nodes))
	// Precedence is the switch below: A over B, and C never. Spelled once, there, so a reader and
	// staticcheck agree on where the decision lives.

	evidence := []string{
		snapshotNote(inv),
		fmt.Sprintf("%s of %s in %s (%s), %.0f vCPU · %.0f GiB each, list at $%.2f/mo per node%s", nWord(len(p.nodes), "node", "nodes"), p.itype, emptyAs(p.region, "(unknown region)"), p.capacity, curShape.VCPU, curShape.MemGiB,
			curMonthly, archClause(p.arch)),
	}
	var dollar float64
	var basis types.PriceBasis
	title := ""
	switch {
	case tierA != nil:
		dollar = (curMonthly - tierA.monthly) * n
		basis = types.PricePriced
		title = fmt.Sprintf("%d %s %s %.0f%% above %s, the same machine a generation later",
			len(p.nodes), p.itype, pick(len(p.nodes), "node lists", "nodes list"), (curMonthly-tierA.monthly)/curMonthly*100, tierA.itype)
		evidence = append(evidence, fmt.Sprintf(
			"SAME CLASS, NEWER GENERATION: %s lists at $%.2f/mo per node — %.0f vCPU · %.0f GiB, same processor "+
				"vendor, same family line, same size label. Across %s that is about $%.2f/mo at list. The "+
				"figure is the DIFFERENCE between two list prices; the nodes are still billed after the change, at the "+
				"lower rate.", tierA.itype, tierA.monthly, tierA.shape.VCPU, tierA.shape.MemGiB, nWord(len(p.nodes), "node", "nodes"), dollar))
	case tierB != nil:
		dollar = (curMonthly - tierB.monthly) * n
		basis = types.PricePriced
		title = fmt.Sprintf("%d %s %s %.0f%% above %s, an equivalent x86 shape",
			len(p.nodes), p.itype, pick(len(p.nodes), "node lists", "nodes list"), (curMonthly-tierB.monthly)/curMonthly*100, tierB.itype)
		evidence = append(evidence, fmt.Sprintf(
			"SAME ARCHITECTURE, DIFFERENT VENDOR: %s lists at $%.2f/mo per node — %.0f vCPU · %.0f GiB on AMD "+
				"EPYC rather than Intel Xeon, both x86-64, so every image that runs today runs there. Across %s "+
				"that is about $%.2f/mo at list. What this does NOT compare is per-vCPU performance: the "+
				"vCPU counts match, the cores are not the same silicon, and a workload with a vendor-specific "+
				"dependency (an Intel-only instruction set, a licensed-per-socket product) is the exception this "+
				"reading cannot see.", tierB.itype, tierB.monthly, tierB.shape.VCPU, tierB.shape.MemGiB,
			nWord(len(p.nodes), "node", "nodes"), dollar))
	default:
		// Only a Graviton option exists. There is no bankable dollar; the finding is structural and the
		// figure is disclosed as conditional below.
		dollar = 0
		basis = types.PriceUnpriced
		title = fmt.Sprintf("%d %s %s an arm64 equivalent at %.0f%% less, if the images run there",
			len(p.nodes), p.itype, pick(len(p.nodes), "node has", "nodes have"), (curMonthly-tierC.monthly)/curMonthly*100)
	}
	if tierC != nil {
		evidence = append(evidence, fmt.Sprintf(
			"NOT BANKED: %s (arm64 Graviton) lists at $%.2f/mo per node — %.0f vCPU · %.0f GiB — which across %s "+
				"WOULD be about $%.2f/mo less than today at list. It is not in the figure above because "+
				"whether this cluster's container images are built for arm64 is a registry fact, and this reading "+
				"does not touch a registry. If every image is multi-arch, this is the larger saving; if one is not, "+
				"that workload cannot move. The number is here so you can check; it is not a claim.",
			tierC.itype, tierC.monthly, tierC.shape.VCPU, tierC.shape.MemGiB, nWord(len(p.nodes), "node", "nodes"),
			(curMonthly-tierC.monthly)*n))
	}
	evidence = append(evidence,
		"compared within the same family line only: same extras, same size label, no crossing into local-NVMe "+
			"(\"d\"), accelerator (g/p/inf/trn), metal or burst-limited (-flex) variants, because vCPU and memory "+
			"do not describe those machines",
		"both sides are on-demand LIST prices in the same region; a reservation or Savings Plan on the current type "+
			"is invisible from the cluster and would shrink or erase this difference — that is what --discount models. "+
			"Whether the proposed type has capacity in your availability zones is not readable here either.",
	)

	return types.Finding{
		ID:          findingID(r.ID(), "NodePool", p.region, p.itype+"/"+string(p.capacity)),
		IDBasis:     &types.ResourceRef{Kind: "NodePool", Namespace: p.region, Name: p.itype + "/" + string(p.capacity)},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       title,
		Description: fmt.Sprintf("The %s pool (%s) is priced above at least one instance type of identical vCPU and "+
			"memory in the same family line. The comparison is between two list prices for the same shape; "+
			"nothing about the workloads on these nodes is assumed beyond what the tiers below state.", p.itype, nWord(len(p.nodes), "node", "nodes")),
		WhyItMatters: "Instance types accumulate: a pool created three years ago is still on the type someone chose " +
			"then, and the catalogue has moved under it. The same machine — same vCPU, same memory, same family — " +
			"is often listed under a newer name at a lower price, and nothing in the cluster points that out.",
		Evidence:            evidence,
		Severity:            types.SeverityLow,
		Category:            types.CategoryCost,
		DollarImpactMonthly: dollar,
		PriceBasis:          basis,
		SpendKind:           types.SpendCompute,
		EstimatedEffort:     types.EffortMedium,
		Confidence:          1.0,
		AffectedResources:   nodeRefs(p.nodes),
		Provenance:          provenance(),
	}, true
}

func archClause(arch string) string {
	if arch == "" {
		return "; the kubelet reports no architecture"
	}
	return fmt.Sprintf("; the kubelet reports %s", arch)
}

func nodeRefs(names []string) []types.ResourceRef {
	sort.Strings(names)
	if len(names) > 12 {
		names = names[:12]
	}
	out := make([]types.ResourceRef, 0, len(names))
	for _, n := range names {
		out = append(out, types.ResourceRef{Kind: "Node", Name: n})
	}
	return out
}

var _ = corev1.Node{} // keep the import honest for readers grepping node handling
