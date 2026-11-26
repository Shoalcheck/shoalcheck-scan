package rules

import (
	"fmt"
	"math"
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// VOLUME FILL (ENG-50) and AUTOSCALER BEHAVIOUR (ENG-54), from a week of Prometheus proven to be this cluster's.
// A claim or an autoscaler absent from the series is not assessed, never "fine".

const (
	fillDaysHorizon = 30   // a volume that fills inside this many days at its window's rate is reported
	fillFullShare   = 0.85 // or one already this full
	oversizedShare  = 0.2  // a volume whose window maximum stayed under this share of its size …
	oversizedFloor  = 50 << 30
)

// VolumeFilling reports claims whose volume is nearly full or fills within a month at its window's rate.
type VolumeFilling struct{}

func (VolumeFilling) ID() string              { return "k8s.observed.volume-filling" }
func (VolumeFilling) Version() string         { return "1.0.0" }
func (VolumeFilling) RequiredKinds() []string { return []string{"persistentvolumeclaims"} }
func (VolumeFilling) RequiresUsage() bool     { return true }

func (r VolumeFilling) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	if t == nil || len(t.Volumes) == 0 || !observed(inv, "persistentvolumeclaims") {
		return nil
	}
	var out []types.Finding
	for _, v := range claimsIn(inv, opts, t.Volumes) {
		share := v.UsedNowBytes / v.CapacityBytes
		days := math.Inf(1)
		if v.GrowthPerDay > 0 {
			days = (v.CapacityBytes - v.UsedNowBytes) / v.GrowthPerDay
		}
		if share < fillFullShare && days > fillDaysHorizon {
			continue
		}
		sev := types.SeverityLow
		switch {
		case days <= 7:
			sev = types.SeverityHigh
		case days <= fillDaysHorizon, share >= 0.95:
			sev = types.SeverityMedium
		}
		facts := []types.Fact{types.NewFact("volume.capacity", v.CapacityBytes), types.NewFact("volume.used", v.UsedNowBytes),
			types.NewFact("volume.growth.day", math.Max(v.GrowthPerDay, 0))}
		if !math.IsInf(days, 1) {
			facts = append(facts, types.NewFact("volume.days.full", math.Floor(days)))
		}
		title := fmt.Sprintf("Volume of %s/%s is %.0f%% full", v.Namespace, v.Claim, 100*share)
		if !math.IsInf(days, 1) && days <= fillDaysHorizon {
			title = fmt.Sprintf("Volume of %s/%s fills in about %s at its recent rate", v.Namespace, v.Claim, nWord(int(math.Max(days, 0)), "day", "days"))
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolumeClaim", v.Namespace, v.Claim),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: v.Namespace, Name: v.Claim},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       title,
			Description: "The kubelet's volume stats show this claim's volume nearly full, or growing at a rate that fills it " +
				"within a month. A full volume stops the writes of whatever runs on it.",
			WhyItMatters: "A database, a queue or a log volume that fills does not degrade: it stops accepting writes. " +
				"Growing a volume in place needs a StorageClass that allows expansion, and some filesystems need the pod restarted.",
			Evidence:          volumeFillLines(inv, t, facts),
			Facts:             facts,
			Severity:          sev,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "PersistentVolumeClaim", Namespace: v.Namespace, Name: v.Claim}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.9,
			Provenance:        provenance(),
		})
	}
	return out
}

func volumeFillLines(inv *collect.Inventory, t *prom.Temporal, fs []types.Fact) []string {
	cpty, used, growth := types.FactNum(fs, "volume.capacity"), types.FactNum(fs, "volume.used"), types.FactNum(fs, "volume.growth.day")
	lines := []string{snapshotNote(inv),
		fmt.Sprintf("kubelet_volume_stats: %s used of %s (%.0f%%)", humanBytes(used), humanBytes(cpty), 100*used/cpty)}
	if d, ok := types.FactValue(fs, "volume.days.full"); ok {
		lines = append(lines, fmt.Sprintf("it grew by %s a day over the %s (a straight line through it); at that rate the rest fills in about %s",
			humanBytes(growth), t.WindowText(), nWord(int(d.(float64)), "day", "days")))
	} else {
		lines = append(lines, fmt.Sprintf("it did not grow over the %s", t.WindowText()))
	}
	return append(lines, "a volume that grows in steps — a batch, a backup, a compaction — fills on its own schedule, not on this line's")
}

// VolumeOversized reports large volumes whose window maximum stayed under a fifth of their size. Never banked: most
// volumes cannot shrink in place, so a smaller one means a new volume and a copy.
type VolumeOversized struct{}

func (VolumeOversized) ID() string              { return "k8s.cost.volume-oversized" }
func (VolumeOversized) Version() string         { return "1.0.0" }
func (VolumeOversized) RequiredKinds() []string { return []string{"persistentvolumeclaims"} }
func (VolumeOversized) RequiresUsage() bool     { return true }

func (r VolumeOversized) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	t := opts.Temporal
	if t == nil || len(t.Volumes) == 0 || !observed(inv, "persistentvolumeclaims") {
		return nil
	}
	var out []types.Finding
	for _, v := range claimsIn(inv, opts, t.Volumes) {
		if v.CapacityBytes < oversizedFloor || v.UsedMaxBytes <= 0 || v.UsedMaxBytes >= v.CapacityBytes*oversizedShare || v.GrowthPerDay > 0 &&
			(v.CapacityBytes*oversizedShare-v.UsedMaxBytes)/v.GrowthPerDay < 90 {
			continue
		}
		facts := []types.Fact{types.NewFact("volume.capacity", v.CapacityBytes), types.NewFact("volume.used.max", v.UsedMaxBytes)}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolumeClaim", v.Namespace, v.Claim),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolumeClaim", Namespace: v.Namespace, Name: v.Claim},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title: fmt.Sprintf("Volume of %s/%s never held more than %.0f%% of its %s", v.Namespace, v.Claim,
				100*v.UsedMaxBytes/v.CapacityBytes, humanBytes(v.CapacityBytes)),
			Description: "Over the window the volume's most was well under a fifth of its size. A volume is billed by its size, " +
				"not by what it holds.",
			WhyItMatters: "Most volumes cannot be shrunk in place: a smaller one means a new volume and a copy of the data, " +
				"so this is a lead for the next migration, not a change to make today.",
			Evidence: []string{snapshotNote(inv),
				fmt.Sprintf("kubelet_volume_stats: at most %s used of %s over the %s", humanBytes(types.FactNum(facts, "volume.used.max")),
					humanBytes(types.FactNum(facts, "volume.capacity")), t.WindowText()),
				"no dollar is banked: a volume that cannot shrink in place saves nothing until it is replaced"},
			Facts:             facts,
			Severity:          types.SeverityInfo,
			Category:          types.CategoryCost,
			PriceBasis:        types.PriceUnpriced,
			SpendKind:         types.SpendStorage,
			AffectedResources: []types.ResourceRef{{Kind: "PersistentVolumeClaim", Namespace: v.Namespace, Name: v.Claim}},
			EstimatedEffort:   types.EffortHigh,
			Confidence:        0.8,
			Provenance:        provenance(),
		})
	}
	return out
}

// claimsIn is the volumes of claims this reading holds, in name order; system namespaces only when asked.
func claimsIn(inv *collect.Inventory, opts Options, vols map[string]prom.VolumeFill) []prom.VolumeFill {
	var out []prom.VolumeFill
	for i := range inv.PVCs {
		c := &inv.PVCs[i]
		if !opts.IncludeSystem && isSystemNamespace(c.Namespace) {
			continue
		}
		if v, ok := vols[c.Namespace+"/"+c.Name]; ok && v.CapacityBytes > 0 {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Claim < out[j].Claim
	})
	return out
}

// humanBytes is a size in the binary unit a reader thinks in.
func humanBytes(b float64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.1f TiB", b/(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", b/(1<<20))
	}
	return fmt.Sprintf("%.0f KiB", b/(1<<10))
}
