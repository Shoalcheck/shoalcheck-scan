package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// gp2BaselineIOPSPerGiB is AWS's gp2 rule: three IOPS per provisioned GiB.
// gp3FreeBaselineIOPS is what a gp3 volume gets at no extra charge.
//
// Their ratio is the ONE place this rule can mislead. Below the crossover a gp2 volume has fewer
// baseline IOPS than a gp3 volume gets for free, so the move is cheaper AND faster with nothing given
// up. At or above it, gp2's baseline exceeds gp3's free tier, and matching it costs money that this
// rule does not model — so those volumes carry the catch in their own evidence line rather than
// riding a blanket "no trade-off" sentence that would be false exactly where the money is largest.
const (
	gp2BaselineIOPSPerGiB = 3
	gp3FreeBaselineIOPS   = 3000
	gp2IOPSCrossoverGiB   = gp3FreeBaselineIOPS / gp2BaselineIOPSPerGiB // 1000 GiB
)

// Gp2WhereGp3IsCheaper reports AWS EBS volumes still on gp2 when gp3 is both cheaper and faster.
//
// WHY THIS IS ONE FINDING AND NOT ONE PER VOLUME. gp2 was the EKS default StorageClass for years, so
// a cluster that never chose has ALL of its volumes on it. One card per volume would put dozens into
// a document that already carries over a hundred findings, every one naming the same action against
// the same class. The volumes are listed as evidence; the finding is the cluster's.
//
// WHY THE FIGURE IS A DIFFERENCE. A gp2 volume does not stop costing money when it becomes gp3 — it
// costs the gp3 rate instead. Only the gap between the two rates is recoverable, and reporting the
// volume's whole monthly cost as the saving would over-claim it about fivefold.
type Gp2WhereGp3IsCheaper struct{}

func (Gp2WhereGp3IsCheaper) ID() string      { return "k8s.cost.ebs-gp2-where-gp3-is-cheaper" }
func (Gp2WhereGp3IsCheaper) Version() string { return "1.0.0" }

func (Gp2WhereGp3IsCheaper) RequiredKinds() []string {
	return []string{"nodes", "persistentvolumes", "storageclasses"}
}

type gp2Volume struct {
	name string
	gib  float64
}

func (r Gp2WhereGp3IsCheaper) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	region := regionFromNodes(inv.Nodes)

	var vols []gp2Volume
	var totalGiB float64
	for i := range inv.PVs {
		pv := inv.PVs[i]
		// A gp2 TYPE is an AWS EBS concept. Reading the disk type without first establishing that the
		// volume is an AWS disk would let a same-named class on another provider through.
		if provider, isCloud := cloudVolumeProvider(&pv); !isCloud || provider != "aws" {
			continue
		}
		// THE CLASS OBJECT, NOT ITS NAME. A class called "gp3" may carry `type: gp2`, and trusting the
		// name there produces a confident wrong answer instead of an honest one.
		if dt, ok := collect.StorageDiskTypeFor(inv.StorageClasses, pv.Spec.StorageClassName); !ok || dt != "gp2" {
			continue
		}
		q := pv.Spec.Capacity[corev1.ResourceStorage]
		gib := float64(q.Value()) / float64(1024*1024*1024)
		if gib <= 0 {
			continue
		}
		vols = append(vols, gp2Volume{name: pv.Name, gib: gib})
		totalGiB += gib
	}
	if len(vols) == 0 {
		return nil
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].gib > vols[j].gib })

	gp2Rate, okGp2 := opts.prices().StorageMonthlyPerGB("aws", region, "gp2")
	gp3Rate, okGp3 := opts.prices().StorageMonthlyPerGB("aws", region, "gp3")

	var dollar float64
	var basis types.PriceBasis
	var priceNote string
	switch {
	case !okGp2 || !okGp3:
		// One rate without the other cannot produce a difference, and a difference is the only figure
		// this rule has. Unpriced, never approximated.
		basis, priceNote = types.PriceUnpriced, fmt.Sprintf(
			"this build has no gp2/gp3 rate pair for region %s, so the monthly difference is withheld "+
				"rather than estimated — the volumes below are still on gp2",
			emptyAs(region, "(unknown)"))
	case gp2Rate <= gp3Rate:
		// Defensive: the generator refuses to emit a region where this holds. If a bundle ever carries
		// one, say nothing about money rather than a negative saving.
		basis, priceNote = types.PriceUnpriced, fmt.Sprintf(
			"in region %s this build's gp2 rate ($%.4f) is not above its gp3 rate ($%.4f), so there is no "+
				"saving to state here", region, gp2Rate, gp3Rate)
	default:
		dollar = totalGiB * (gp2Rate - gp3Rate)
		basis = types.PricePriced
		priceNote = fmt.Sprintf(
			"gp2 lists at $%.4f per GB-month in %s and gp3 at $%.4f — a difference of $%.4f. Across %.0f GiB "+
				"provisioned that is about $%.2f/mo. The figure is the DIFFERENCE between the two rates, not "+
				"the cost of the volumes: the storage is still billed after the change, at the lower rate.",
			gp2Rate, region, gp3Rate, gp2Rate-gp3Rate, totalGiB, dollar)
	}

	evidence := []string{snapshotNote(inv), priceNote}

	shown := vols
	if len(shown) > 12 {
		shown = shown[:12]
	}
	for _, v := range shown {
		evidence = append(evidence, fmt.Sprintf("PersistentVolume %s: %.0f GiB on a gp2 StorageClass", v.name, v.gib))
	}
	if len(vols) > len(shown) {
		evidence = append(evidence, fmt.Sprintf("… and %s, included in the total above", nWord(len(vols)-len(shown), "more gp2 volume",

			// The IOPS catch, stated only when it applies and naming the volumes it applies to.
			"more gp2 volumes")))
	}

	var big []string
	for _, v := range vols {
		if v.gib >= gp2IOPSCrossoverGiB {
			big = append(big, fmt.Sprintf("%s (%.0f GiB carrying %.0f baseline IOPS)", v.name, v.gib, v.gib*gp2BaselineIOPSPerGiB))
		}
	}
	if len(big) > 0 {
		evidence = append(evidence, fmt.Sprintf(
			"NOT A FREE MOVE FOR %d OF THESE. gp2 grants %d IOPS per provisioned GiB, so at or above %d GiB it "+
				"carries more baseline IOPS than gp3's free %d: %s. Matching that on gp3 means paying for "+
				"provisioned IOPS, which is NOT modelled in the figure above — for these volumes the saving "+
				"stated is an upper bound and the performance is not like-for-like.",
			len(big), gp2BaselineIOPSPerGiB, gp2IOPSCrossoverGiB, gp3FreeBaselineIOPS, strings.Join(big, ", ")))
	} else {
		evidence = append(evidence, fmt.Sprintf(
			"Every volume here is below %d GiB, so its gp2 baseline (%d IOPS per GiB) is under gp3's free %d "+
				"— the move is cheaper and not slower.",
			gp2IOPSCrossoverGiB, gp2BaselineIOPSPerGiB, gp3FreeBaselineIOPS))
	}
	evidence = append(evidence,
		"changing an EBS volume's type is an online ModifyVolume operation; this reading does not tell you "+
			"whether your StorageClass is referenced by manifests that would recreate volumes as gp2 again")

	affected := make([]types.ResourceRef, 0, len(shown))
	for _, v := range shown {
		affected = append(affected, types.ResourceRef{Kind: "PersistentVolume", Name: v.name})
	}

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "gp2"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "gp2"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s totalling %.0f GiB %s on gp2, which costs more than gp3 for the same storage",
			nWord(len(vols), "EBS volume", "EBS volumes"), totalGiB, pick(len(vols), "is", "are")),
		Description: fmt.Sprintf(
			"%s resolve to the gp2 EBS type. gp3 is priced below gp2 per GB-month in every "+
				"region this build carries, and its free baseline is 3000 IOPS and 125 MB/s. This is a rate "+
				"difference on storage that is already provisioned — the volumes, their sizes and their data "+
				"are unchanged by it.", nWord(len(vols), "PersistentVolume", "PersistentVolumes")),
		WhyItMatters: "gp2 was the default EBS type for EKS for years, so a cluster carries it by not having " +
			"chosen rather than by deciding. It is the one storage change with a price difference and no " +
			"capacity trade-off below the IOPS crossover, which makes it unusually easy to justify.",
		Evidence: evidence,
		Severity: types.SeverityLow,
		Category: types.CategoryCost,
		// MEDIUM, not low. Changing the StorageClass's default is minutes; migrating the volumes that
		// already exist is an online ModifyVolume per volume plus whatever references the old class in
		// manifests, and above the IOPS crossover it needs a performance decision first.
		EstimatedEffort:     types.EffortMedium,
		DollarImpactMonthly: dollar,
		PriceBasis:          basis,

		SpendKind:  types.SpendStorage,
		Confidence: 1.0,
		// The volumes themselves, even though the finding is the cluster's. A reader filtering by
		// resource must still reach this card from any one of them, and the cap keeps a cluster with
		// three hundred gp2 volumes from putting three hundred rows into one finding's header.
		AffectedResources: affected,
		Provenance:        provenance(),
	}}
}
