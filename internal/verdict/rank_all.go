package verdict

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// RankAll is every finding, once, in the order the product ranks them everywhere: one leader per rule, in the
// order SelectWith ranks the rules — a collapsed group's leader carries its class and rationale — and then the
// rules' other findings, RULE BY RULE IN THAT SAME ORDER, each by its own priority within its rule and each
// carrying its rule's band and Folded.
//
// LEADERS FIRST, because the full order is read as a triage queue: the most important instance of every rule
// before the seventieth instance of one. Tried contiguous-by-rule on 2026-10-16 and it put thirty
// system:controller roles in a row at the top of the terminal's list. What changed from before is the TAIL:
// it was report order, so its severity restarted at random; it now follows the leaders' order, and Folded
// lets a surface mark where it starts. See TestRankAll_TheFoldedFindingsFollowTheLeadersRuleByRule.
//
// ONE PLACE, because three surfaces printed this order and two of them had copied the expansion by hand
// (cmd/shoalcheck-app/queue.go, internal/tui/session.go). A ranking that differs by one row between the app and
// the terminal is the kind of defect nobody reports and everybody notices.
func RankAll(findings []types.Finding, replicas ReplicaLookup) []Ranked {
	if len(findings) == 0 {
		return nil
	}
	sel := selectWith(findings, len(findings), replicas, false)
	// THE ORIGINAL FINDING, NOT THE COLLAPSED LEADER. SelectWith unions every member's AffectedResources
	// into the group's leader and sums their dollars — the right presentation for a podium card that stands
	// for a group, and a lie about the individual finding whose id the leader carries.
	//
	// Measured on the 839-finding AKS reading: `shoalcheck findings -o md` printed f-05aeb1166a71 with 110
	// affected resources; that id in the reading's own JSON has one. It reached all five of that command's
	// formats — including SARIF, where an alert fingerprinted on the id carried 109 resources the finding
	// never named — plus the app's queue and the terminal session, because all three read this order from
	// here. The safety class was computed over the union too, which is why applying it was refused.
	//
	// The collapse is not thrown away: CollapsedFrom still says how many findings share the rule, which is
	// what the queue and the terminal print beside the row. A ranking function returns an ORDER.
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	seen := make(map[string]bool, len(findings))
	out := make([]Ranked, 0, len(findings))
	for _, r := range sel.Top {
		if seen[r.Finding.ID] {
			continue
		}
		seen[r.Finding.ID] = true
		if orig, ok := byID[r.Finding.ID]; ok {
			r.Finding = orig
			// Safety and the rationale were derived from the union; both are re-derived for the finding
			// this row now IS, or the row would carry a verdict about a change nobody is proposing.
			r.Safety = ClassifyWith(orig, replicas)
			r.Rationale = Rationale(r)
		}
		out = append(out, r)
	}
	// The rule's other findings, each scored on itself and placed after its own leader.
	rest := map[string][]Ranked{}
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		safety := ClassifyWith(f, replicas)
		rest[f.RuleID] = append(rest[f.RuleID], Ranked{Finding: f, Safety: safety, CollapsedFrom: 1,
			Score: Priority(f, safety, 1)})
	}
	grouped := make([]Ranked, 0, len(findings))
	grouped = append(grouped, out...)
	for _, lead := range out {
		members := rest[lead.Finding.RuleID]
		sort.SliceStable(members, func(i, j int) bool {
			if members[i].Score != members[j].Score {
				return members[i].Score > members[j].Score
			}
			return members[i].Finding.ID < members[j].Finding.ID
		})
		for _, m := range members {
			m.Tier, m.Folded = lead.Tier, true
			grouped = append(grouped, m)
		}
		delete(rest, lead.Finding.RuleID)
	}
	// A rule with no leader cannot happen — every rule has a group — but a finding is never dropped for it,
	// and the order stays total: map iteration is not an order.
	var orphanRules []string
	for rule := range rest {
		orphanRules = append(orphanRules, rule)
	}
	sort.Strings(orphanRules)
	for _, rule := range orphanRules {
		for _, m := range rest[rule] {
			m.Folded = true
			grouped = append(grouped, m)
		}
	}
	return grouped
}

// MostSevereLeftOut is the reading's most severe finding when no finding in top is as severe — the first of that
// severity in ranked, which is RankAll's order — and nil when top already holds one.
//
// RANKED IN BANDS, A PODIUM CAN LEAVE OUT THE WORST THING IN A READING. A finding whose own text says it may not
// apply ranks after everything that certainly does, a hedged critical included (TierOf), so a three-card podium
// can be two mediums and a high over a reading with a critical in it. That order is right for "what to do
// first" and wrong as the only thing a reader sees; a surface that shows top shows this beside it.
func MostSevereLeftOut(top, ranked []Ranked) *Ranked {
	worst := 0
	for _, r := range ranked {
		if n := severityRank(r.Finding.Severity); n > worst {
			worst = n
		}
	}
	if worst == 0 {
		return nil
	}
	for _, r := range top {
		if severityRank(r.Finding.Severity) >= worst {
			return nil
		}
	}
	for i := range ranked {
		if severityRank(ranked[i].Finding.Severity) == worst {
			r := ranked[i]
			return &r
		}
	}
	return nil
}
