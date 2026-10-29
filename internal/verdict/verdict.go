// Package verdict turns a complete finding list into an opinion: the few things worth
// doing first, in order, with an evidence-grounded reason for each.
//
// It exists because enumeration is not judgement. A thirty-pod test cluster produces 96
// findings and a real 478-pod cluster produces 2110, and on the first live run of the
// theater the visible cards were led by three variants of one hedged "namespace has no
// NetworkPolicy" observation while the single finding carrying every dollar on the page sat
// among them undistinguished. See docs/qa/peak-review-2026-08.md.
//
// Three properties are load-bearing and each is enforced by a test rather than by care:
//
//   - This is a LENS, not a filter. Every finding stays in the report. Selection carries
//     TotalDollars so the caller can assert on screen that the cluster headline did not move.
//   - Nothing here edits a finding. Findings are carried through unmodified.
//   - No prose is generated. Rationales are assembled from fields the finding already
//     carries; a fabricated explanation is the same class of defect as a fabricated dollar.
package verdict

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Ranked is one finding with the judgement attached.
type Ranked struct {
	// Finding is carried unmodified. When several findings of the same rule collapsed into
	// this one, it is the highest-scoring of them with AffectedResources unioned and
	// DollarImpactMonthly summed — see Select.
	Finding types.Finding

	// Score is the priority function's output. It is deliberately NOT surfaced to users: an
	// invented number invites an argument about the number instead of about the finding.
	Score float64

	// Safety is how safe the remediation would be to apply. Derived from the remediation
	// itself, never from Finding.Confidence — confidence means problem-certainty, and
	// conflating the two is the honesty defect this field exists to prevent.
	Safety SafetyClass

	// Rationale is why this one leads, assembled only from the finding's own fields.
	Rationale string

	// CollapsedFrom is how many findings folded into this one (1 when none did). Three
	// "namespace has no NetworkPolicy" findings are one observation about three namespaces.
	CollapsedFrom int

	// Tier is the band this finding was ranked in — its RULE's band, computed on the collapsed group, and
	// carried by every finding of the rule so a list never shows one rule's findings under two bands.
	Tier Tier

	// Folded is true for a finding that follows the leaders in RankAll's order: its rule's leader is above,
	// and a surface marks it so the place where severity starts again reads as a section, not a broken sort.
	Folded bool
}

// Selection is the lens: the leaders, plus an honest account of everything it does not show.
type Selection struct {
	Top         []Ranked
	RestCount   int     // findings not shown, after collapsing
	RestDollars float64 // their summed monthly impact

	// TotalDollars sums ALL findings, uncollapsed. It must equal the report headline; it is
	// carried here so callers assert that rather than trust it.
	TotalDollars float64

	// StartHere is the highest-ranked finding whose remediation is actually SafeNow — nil when
	// nothing qualifies.
	//
	// It is deliberately SEPARATE from Top, and the first real-data run is why. On the AKS dev
	// cluster the podium is led by "219 containers do not assert non-root" and "an Argo CD
	// Application is Degraded" — both genuinely the most important things on the cluster, and
	// both Manual: there is no mechanical fix to hand anyone. Restricting the podium to SafeNow
	// would have hidden them, which is the wrong trade; letting the podium imply "start with
	// this" would promise a fix that does not exist.
	//
	// So the product says two things at once: these matter most, and of everything found this
	// is the safest place to start. StartHere is also EPIC 2's entry point — the closed loop
	// may only ever act on a SafeNow finding.
	StartHere *Ranked
}

// Select ranks findings and returns the top n as a lens over the full list.
//
// Order of operations matters: collapse first, then rank, then take n. Ranking before
// collapsing would let one repeated observation occupy the whole podium.
func Select(findings []types.Finding, n int) Selection {
	return SelectWith(findings, n, nil)
}

// SelectWith is Select with cluster context. The ReplicaLookup lets the safety classifier tell a
// scale-up (additive) from a scale-down (not), which is invisible in the remediation text — see
// ClassifyWith. Passing nil is safe and simply keeps every scale out of SafeNow.
func SelectWith(findings []types.Finding, n int, replicas ReplicaLookup) Selection {
	return selectWith(findings, n, replicas, true)
}

// selectWith is SelectWith with the podium's one-object rule switchable: RankAll asks for every group in order
// and must get the full triage order unchanged, while a podium of a few cards names each object once.
func selectWith(findings []types.Finding, n int, replicas ReplicaLookup, oneCardPerObject bool) Selection {
	sel := Selection{}
	for _, f := range findings {
		sel.TotalDollars += f.DollarImpactMonthly
	}
	if len(findings) == 0 {
		return sel
	}

	ranked := rankAll(collapseByRule(findings), replicas)

	// n is clamped rather than short-circuited. An earlier version returned early on n <= 0 with
	// the remainder still at zero, so a caller asking for no podium was told there was nothing
	// below it while the dollars were sitting in TotalDollars — the accounting invariant broke on
	// the one path nobody looks at. Found by the adversarial gate (B-010).
	if n < 0 {
		n = 0
	}
	if n > len(ranked) {
		n = len(ranked)
	}
	top := ranked[:n]
	if oneCardPerObject {
		top = podium(ranked, n)
	}
	sel.Top = top
	onPodium := map[string]bool{}
	for _, r := range top {
		onPodium[r.Finding.ID] = true
	}
	for _, r := range ranked {
		if onPodium[r.Finding.ID] {
			continue
		}
		sel.RestCount += r.CollapsedFrom
		sel.RestDollars += r.Finding.DollarImpactMonthly
	}

	sel.StartHere = startHere(findings, replicas)
	return sel
}

// podium takes the first n groups in rank order that each name something no higher card names.
//
// THE PODIUM NAMES AN OBJECT ONCE. Two of three cards on the kind testbed were one PodDisruptionBudget — "blocks
// node drains" and "the drain of a node is blocked by" it — so the third thing worth doing never reached the
// screen (the final review, 2026-10-18). A repeat gives its place to the next group and stays in the queue; when
// fewer than n distinct groups exist, repeats fill the rest rather than leaving a card empty. Nodes and
// Namespaces are too broad to count as "the same object": half the findings in a cluster touch one.
func podium(ranked []Ranked, n int) []Ranked {
	taken := map[string]bool{}
	var top, repeats []Ranked
	for _, r := range ranked {
		if len(top) == n {
			break
		}
		repeat := false
		for _, ref := range r.Finding.AffectedResources {
			if k := objectKey(ref); k != "" && taken[k] {
				repeat = true
				break
			}
		}
		if repeat {
			repeats = append(repeats, r)
			continue
		}
		top = append(top, r)
		for _, ref := range r.Finding.AffectedResources {
			if k := objectKey(ref); k != "" {
				taken[k] = true
			}
		}
	}
	for _, r := range repeats {
		if len(top) == n {
			break
		}
		top = append(top, r)
	}
	return top
}

func objectKey(ref types.ResourceRef) string {
	switch ref.Kind {
	case "", "Node", "Namespace":
		return ""
	}
	return ref.Kind + "/" + ref.Namespace + "/" + ref.Name
}

// startHere picks the single best concrete action: the highest-scoring INDIVIDUAL finding whose
// remediation is SafeNow, or nil when none is.
//
// Individual, not collapsed, and the real AKS report is why. Collapsing unions every member's
// AffectedResources, so the single-replica rule's representative carried 102 targets and the safety
// check refused it — correctly, since applying one change to 102 workloads at once is not additive,
// and uselessly, since twelve of those workloads were individually a provable 1→2 scale-up.
// "Where do I start" is one action on one target; collapsing is a presentation device for the
// podium and has no business here.
func startHere(findings []types.Finding, replicas ReplicaLookup) *Ranked {
	// NEVER MULTIPLY A RISK. "Scale deployment/privileged-pod to 2 replicas" was offered as the safest place to
	// begin: additive, and it doubles a workload carrying its own high host-access finding. An object a high or
	// critical security finding names is not where to start adding.
	risky := map[string]bool{}
	for _, f := range findings {
		if f.Category != types.CategorySecurity {
			continue
		}
		if f.Severity != types.SeverityHigh && f.Severity != types.SeverityCritical {
			continue
		}
		for _, ref := range f.AffectedResources {
			if k := objectKey(ref); k != "" {
				risky[k] = true
			}
		}
	}
	var best *Ranked
	for i := range findings {
		safety := ClassifyWith(findings[i], replicas)
		if safety != SafeNow {
			continue
		}
		multiplies := false
		for _, ref := range findings[i].AffectedResources {
			if risky[objectKey(ref)] {
				multiplies = true
			}
		}
		if multiplies {
			continue
		}
		cand := Ranked{Finding: findings[i], Safety: safety, CollapsedFrom: 1, Tier: TierOf(findings[i])}
		cand.Score = Priority(cand.Finding, safety, 1)
		cand.Rationale = Rationale(cand)
		if best == nil || cand.Score > best.Score ||
			(cand.Score == best.Score && cand.Finding.ID < best.Finding.ID) {
			c := cand
			best = &c
		}
	}
	return best
}

// collapsed is a group of findings sharing a RuleID, before it becomes a Ranked.
type collapsed struct {
	rep    types.Finding // representative: the most severe, then most expensive member
	count  int
	dollar float64
	refs   []types.ResourceRef
}

// collapseByRule folds findings of the same rule into one group. This is presentation only —
// the report still lists every finding individually.
func collapseByRule(findings []types.Finding) []collapsed {
	order := []string{}
	groups := map[string]*collapsed{}
	for _, f := range findings {
		g := groups[f.RuleID]
		if g == nil {
			g = &collapsed{rep: f}
			groups[f.RuleID] = g
			order = append(order, f.RuleID)
		} else if moreImportant(f, g.rep) {
			g.rep = f
		}
		g.count++
		g.dollar += f.DollarImpactMonthly
		g.refs = append(g.refs, f.AffectedResources...)
	}

	out := make([]collapsed, 0, len(order))
	for _, id := range order {
		g := groups[id]
		// The representative speaks for the group: it carries the group's total dollars and
		// the union of everything affected, so a collapsed card never understates its reach.
		g.rep.DollarImpactMonthly = g.dollar
		g.rep.AffectedResources = g.refs
		out = append(out, *g)
	}
	return out
}

// moreImportant breaks representative ties within a rule group: severity first, then money.
func moreImportant(a, b types.Finding) bool {
	if sa, sb := severityRank(a.Severity), severityRank(b.Severity); sa != sb {
		return sa > sb
	}
	return a.DollarImpactMonthly > b.DollarImpactMonthly
}

// rankAll scores every group and returns them best first, with a total tie-break so the same
// report always yields the same podium. A run that disagrees with itself about the top three
// costs more credibility than a wrong number.
func rankAll(groups []collapsed, replicas ReplicaLookup) []Ranked {
	out := make([]Ranked, 0, len(groups))
	for _, g := range groups {
		r := Ranked{
			Finding:       g.rep,
			Safety:        ClassifyWith(g.rep, replicas),
			CollapsedFrom: g.count,
		}
		r.Score = Priority(g.rep, r.Safety, g.count)
		r.Tier = TierOf(g.rep)
		r.Rationale = Rationale(r)
		out = append(out, r)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Finding.DollarImpactMonthly != out[j].Finding.DollarImpactMonthly {
			return out[i].Finding.DollarImpactMonthly > out[j].Finding.DollarImpactMonthly
		}
		// Total order, so ties can never reorder between runs.
		if out[i].Finding.RuleID != out[j].Finding.RuleID {
			return out[i].Finding.RuleID < out[j].Finding.RuleID
		}
		return out[i].Finding.ID < out[j].Finding.ID
	})
	return out
}

// severityRank maps severity to a comparable number. Info ranks below Low deliberately: an
// informational note is never the thing a client should do first.
func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	}
	return 0
}

// ReplicasFromArchitecture builds a ReplicaLookup over an audit's topology.
//
// It reports found=false for anything the topology does not contain, which matters: the topology is
// trimmed per namespace, so absence means "not known", never "zero". A missing entry therefore
// keeps a scale out of SafeNow rather than licensing it.
func ReplicasFromArchitecture(arch *types.Architecture) ReplicaLookup {
	if arch == nil {
		return nil
	}
	byKey := map[string]int{}
	for _, tp := range arch.Topologies {
		for _, w := range tp.Workloads {
			byKey[w.Kind+"/"+tp.Name+"/"+w.Name] = w.Replicas
		}
	}
	if len(byKey) == 0 {
		return nil
	}
	return func(ref types.ResourceRef) (int, bool) {
		n, ok := byKey[ref.Kind+"/"+ref.Namespace+"/"+ref.Name]
		return n, ok
	}
}
