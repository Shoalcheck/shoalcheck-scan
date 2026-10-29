package rules

// unattached_volumes.go — a PersistentVolume whose published phase says nothing is using it.
//
// internal/collect/storage_spend.go prices every PersistentVolume's spec.capacity into the cluster
// total regardless of phase, which is correct for a spend total and says nothing about whether
// anything is attached. So a disk whose workload was deleted months ago is already inside the
// monthly figure with nothing anywhere saying it belongs to nobody. This rule reads the one field
// that says so: status.phase, written by the volume's own controller.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS RULE DELIBERATELY DOES NOT SAY, AND WHY
//
//	NO VERDICT ABOUT INTENT. status.phase says WHAT a volume is, never WHY. A Released volume under
//	`persistentVolumeReclaimPolicy: Retain` is the policy working exactly as written — somebody
//	chose to keep the data — and an Available one may be a pre-provisioned pool. So the words
//	"orphan", "abandoned", "unused", "waste", "leaked" and "stale" are banned by
//	unattached_volumes_test.go, and the rule's own vocabulary is UNATTACHED, which is the
//	mechanical word for what the phase reports.
//
//	NO RECOMMENDATION TO DELETE, AND NO REMEDIATION YAML AT ALL. `delete` is in destructiveVerbs
//	(safety.go), and deleting a PersistentVolume can destroy the only copy of the data a Retain
//	policy exists to preserve. The remediation is a commented inspection step. This is the one rule
//	in the tree where the obvious action is also the one that can lose data irreversibly.
//
//	NO CLAIM ABOUT WHAT IS ON THE VOLUME. We never read a volume's contents and could not. Whether
//	a Released disk holds something irreplaceable is exactly the question the operator has to
//	answer, and the finding says so instead of guessing.
//
//	NO SAVINGS CLAIM. The figure is what the volume COSTS at list price. What deleting it would
//	save is a different sentence, and whether it can be deleted is not ours to say. ("verified
//	savings" and "realized savings" are already banned globally in lexicon.Banned().)
//
//	NO CLAIM THAT A NAMED CLAIM WAS DELETED. A Released volume's spec.claimRef names a
//	PersistentVolumeClaim. The rule says that name is not in THIS READING's claim list, and when
//	the claim list was refused it omits the sentence entirely rather than asserting an absence from
//	a list it never read.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY THE DOLLAR GATE IS THE VOLUME'S OWN SOURCE AND NOT A CLOUD providerID ON SOME NODE
//
// idle_loadbalancer.go gates its dollar on confirmedCloudProvider — a cloud providerID on any node
// — which is right for a load balancer, because an LB is a cluster-level object. A PersistentVolume
// is not. A cluster whose nodes carry aws:// can hold `local` and `hostPath` volumes that cost
// nothing at all, and kind's local-path-provisioner produces exactly those. Pricing one of them
// against an EBS table would invent money on the cheapest possible cluster, which is the failure
// providerFromNodes' own comment (node_headroom.go:397) records as already made once and fixed.
//
// So the dollar requires a cloud volume source ON THE VOLUME: a known cloud CSI driver, or one of
// the legacy in-tree cloud sources. Everything else gets the finding with the dollar withheld and
// the source named — and the two withheld cases are DIFFERENT, which is what PriceBasis is for: a
// directory on a node is PriceNotCost (there is no bill), while an unrecognised CSI driver is
// PriceUnpriced (it may well be a billed cloud disk from a driver we have no table for).

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// cloudCSIDrivers are the CSI drivers whose volumes are managed cloud disks the pricing tables
// cover. A driver absent from this map is NOT assumed to be free — see unpricedDriverNote.
var cloudCSIDrivers = map[string]string{
	"ebs.csi.aws.com":       "aws",
	"disk.csi.azure.com":    "azure",
	"pd.csi.storage.gke.io": "gcp",
}

// TEST COVERAGE, STATED PER PHASE. Available and Released are live-verified on the kind testbed.
// THE Failed BRANCH IS UNIT-TESTED ONLY, and the reason is recorded here rather than only in the bug
// ledger because that is where the next person will look before re-litigating it:
//
//	Patching status.phase=Failed onto a PersistentVolume is ACCEPTED by the API server and does not
//	persist. The PV controller owns the phase and recomputes it on every sync, so the value reads back
//	as Available seconds later. That is the per-field correction to the CronJob lesson (bug ledger
//	B-104): `kubectl patch --subresource=status` really is writable, but writability is not
//	persistence when a controller actively reconciles the field — a status field written on an EVENT
//	can be fabricated, one recomputed on every sync cannot.
//
//	Reaching it honestly means a reclaim that fails. Attempted with `persistentVolumeReclaimPolicy:
//	Recycle` on a hostPath volume, expecting kind to have no recycler: kind's controller-manager
//	recycled it successfully (Released -> Available). A reclaim that fails on demand means breaking
//	the volume controller, and a testbed with a broken controller verifies nothing else.
type UnattachedVolume struct{}

func (UnattachedVolume) ID() string      { return "k8s.cost.unattached-volume" }
func (UnattachedVolume) Version() string { return "1.0.0" }

// RequiredKinds — `persistentvolumes` because the phase IS the claim, and
// `persistentvolumeclaims` because the claimRef sentence is an absence claim over that list: with
// it refused, every Released volume would appear to name a vanished claim. The guard degrades the
// sentence rather than the finding, which is why the list belongs here and the rule still fires
// without it.
//
// `nodes` IS DELIBERATELY OMITTED, and it is the interesting call. The only thing nodes supply is
// the region string for the price lookup, and an unknown region yields PriceUnpriced — a change in
// VALUE, not in PRESENCE. The reference-data decision drew exactly this line: pricing coverage
// never changes which findings appear, but it absolutely changes the sum. Declaring `nodes` would
// make a comparison report this rule unevaluated on a run that emitted identical findings.
// See deps.go for what belongs in this list.
func (UnattachedVolume) RequiredKinds() []string {
	return sortedKinds([]string{"persistentvolumeclaims", "persistentvolumes"})
}

func (r UnattachedVolume) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// DENIAL GUARD: a refused volume list read as "no volumes" is the fabrication every rule in
	// this package guards against, and here it would silently remove money from the report.
	if !observed(inv, "persistentvolumes") {
		return nil
	}
	claimsObserved := observed(inv, "persistentvolumeclaims")
	region := regionFromNodes(inv.Nodes)

	// A PersistentVolume is cluster-scoped and has no namespace, so opts.IncludeSystem is not
	// consulted. Stated rather than left implicit: a volume whose claimRef points into kube-system
	// is still a billed disk, and suppressing it would remove real money from the report.
	_ = opts

	idx := make([]int, 0, len(inv.PVs))
	for i := range inv.PVs {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool { return inv.PVs[idx[a]].Name < inv.PVs[idx[b]].Name })

	var out []types.Finding
	for _, i := range idx {
		pv := &inv.PVs[i]
		phaseNote, ok := unattachedPhaseNote(pv.Status.Phase)
		if !ok {
			continue
		}
		q := pv.Spec.Capacity[corev1.ResourceStorage]
		gib := float64(q.Value()) / float64(1024*1024*1024)
		class := emptyAs(pv.Spec.StorageClassName, "(no storageClass)")
		reclaim := string(pv.Spec.PersistentVolumeReclaimPolicy)
		if reclaim == "" {
			reclaim = "not set"
		}

		evidence := []string{
			fmt.Sprintf("PersistentVolume %s: status.phase=%s, spec.persistentVolumeReclaimPolicy=%s",
				pv.Name, pv.Status.Phase, reclaim),
			fmt.Sprintf("spec.capacity.storage=%s (%.1f GiB provisioned), spec.storageClassName=%s",
				q.String(), gib, class),
			phaseNote,
		}
		if s := volumeSourceNote(pv); s != "" {
			evidence = append(evidence, s)
		}
		evidence = append(evidence, claimRefNote(inv, pv, claimsObserved)...)

		dollar, basis, priceNote := priceVolume(pv, region, gib, opts)
		evidence = append(evidence, priceNote)
		evidence = append(evidence,
			"the contents of a volume are never read by this tool, so whether this one holds the only copy "+
				"of anything is not readable here",
			fmt.Sprintf("reading taken %s", stamp(readingTime(inv))))

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "PersistentVolume", "", pv.Name),
			IDBasis:     &types.ResourceRef{Kind: "PersistentVolume", Namespace: "", Name: pv.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			// The phase verbatim, and "no claim bound" rather than any word about use: all three
			// reported phases are non-Bound, so the absence of a binding is arithmetic, while
			// "unused" would be a claim about whether anybody wants the disk.
			Title: fmt.Sprintf("Volume %s is %s with no claim bound to it", pv.Name, pv.Status.Phase),
			Description: fmt.Sprintf(
				"PersistentVolume %s reports status.phase=%s with persistentVolumeReclaimPolicy=%s, and "+
					"%s provisioned on storageClass %s. %s The phase is the volume controller's own; why the "+
					"volume is in it is not readable from this snapshot.",
				pv.Name, pv.Status.Phase, reclaim, q.String(), class, phaseNote),
			WhyItMatters: "A provisioned disk is billed for its provisioned size whether or not anything " +
				"is mounting it, and no workload's status mentions a volume that belongs to nobody.",
			Evidence:            evidence,
			Severity:            types.SeverityLow,
			Category:            types.CategoryCost,
			AffectedResources:   []types.ResourceRef{{Kind: "PersistentVolume", Name: pv.Name}},
			DollarImpactMonthly: dollar,
			PriceBasis:          basis,

			SpendKind:       types.SpendStorage,
			EstimatedEffort: types.EffortLow,
			// COMMENTED, AND THERE IS NO RemediationYAML. Deleting a PersistentVolume can destroy
			// the only copy of the data a Retain policy exists to preserve, so the command is an
			// inspection step and nothing here suggests what to do with the answer.
			RemediationCommand: fmt.Sprintf(
				"# read it before deciding anything — the phase says nothing about the data:\n"+
					"kubectl get pv %s -o yaml", pv.Name),
			// The phase is a published field copied verbatim. Per types/finding.go this is
			// problem-certainty and explicitly NOT a statement about the dollar's completeness,
			// which is what PriceBasis carries.
			Confidence: 1.0,
			Provenance: provenance(),
		})
	}
	return out
}

// unattachedPhaseNote returns the sentence for a phase that means nothing is using the volume, and
// false for a phase this rule does not report.
//
// THREE PHASES, THREE SENTENCES, AND THEY MUST NOT READ ALIKE. A rule that rendered them
// identically would have described at most one of the three clusters they describe — the same
// defect as rendering a nil lastSuccessfulTime as an old success (silent_failures.go:23).
func unattachedPhaseNote(p corev1.PersistentVolumePhase) (string, bool) {
	switch p {
	case corev1.VolumeAvailable:
		return "Available means the volume is provisioned and no claim has ever bound to it: either nothing " +
			"has asked for it yet, or it is one of a pool somebody pre-provisioned on purpose.", true
	case corev1.VolumeReleased:
		return "Released means a claim was bound to this volume and that claim is gone, and the volume was " +
			"not reclaimed afterwards — which under a Retain policy is the policy doing exactly what it says.", true
	case corev1.VolumeFailed:
		return "Failed means the volume's automatic reclamation was attempted and did not complete. Of the " +
			"three phases this rule reports, it is the only one where something did not work, and nothing " +
			"else in the cluster reports it.", true
	default:
		// Bound is a volume doing its job; Pending is a provisioner mid-flight.
		return "", false
	}
}

// volumeSourceNote names the volume source that was read, so a reader can see which of the four
// pricing outcomes below applied and why.
func volumeSourceNote(pv *corev1.PersistentVolume) string {
	s := pv.Spec
	switch {
	case s.CSI != nil:
		return fmt.Sprintf("spec.csi.driver=%q", s.CSI.Driver)
	case s.AWSElasticBlockStore != nil:
		return "spec.awsElasticBlockStore (legacy in-tree source)"
	case s.AzureDisk != nil:
		return "spec.azureDisk (legacy in-tree source)"
	case s.GCEPersistentDisk != nil:
		return "spec.gcePersistentDisk (legacy in-tree source)"
	case s.Local != nil:
		return "spec.local — a path on a node, not a provisioned cloud disk"
	case s.HostPath != nil:
		return "spec.hostPath — a path on a node, not a provisioned cloud disk"
	case s.NFS != nil:
		return "spec.nfs — a share on a server outside this cluster's billing, whatever that server costs"
	default:
		return "the volume source is one this rule does not classify"
	}
}

// claimRefNote reports what the volume's claimRef names, and whether that claim is in this reading.
// It returns nothing when there is no claimRef, and says the list was not read when it was refused —
// never that a claim is absent from a list nobody looked at.
func claimRefNote(inv *collect.Inventory, pv *corev1.PersistentVolume, claimsObserved bool) []string {
	ref := pv.Spec.ClaimRef
	if ref == nil {
		return []string{"spec.claimRef is absent: no claim has been bound to this volume"}
	}
	named := fmt.Sprintf("spec.claimRef names PersistentVolumeClaim %s/%s", ref.Namespace, ref.Name)
	if !claimsObserved {
		return []string{named + ", and the claim list was not read on this run, so whether that claim still " +
			"exists is not stated here"}
	}
	for i := range inv.PVCs {
		c := &inv.PVCs[i]
		if c.Namespace == ref.Namespace && c.Name == ref.Name {
			return []string{named + ", and a claim of that name is present in this reading"}
		}
	}
	return []string{named + ", and a claim of that name is not in this reading's claim list"}
}

// priceVolume returns the monthly figure, its basis, and the evidence sentence that must accompany
// it. Every non-zero dollar names the rate it came from, which is both the honest thing and what
// validate.go's evidence invariant enforces.
func priceVolume(pv *corev1.PersistentVolume, region string, gib float64, opts Options) (float64, types.PriceBasis, string) {
	provider, isCloud := cloudVolumeProvider(pv)
	if !isCloud {
		if pv.Spec.CSI != nil {
			// An unrecognised CSI driver is NOT free. It may be a billed cloud disk from a driver
			// we have no table for, and PriceUnpriced is the field that says exactly that.
			return 0, types.PriceUnpriced, fmt.Sprintf(
				"spec.csi.driver=%q is not in this build's cloud-disk table, so no rate applies to it and the "+
					"monthly figure is withheld rather than assumed — an unrecognised driver may still be a "+
					"billed cloud disk", pv.Spec.CSI.Driver)
		}
		return 0, types.PriceNotCost, "this volume is not a provisioned cloud disk (see the source above), " +
			"so there is no per-GB bill to state — which is a different thing from a bill we could not price"
	}
	class := pv.Spec.StorageClassName
	diskType, ok := collect.StorageDiskType(class)
	if !ok {
		return 0, types.PriceUnpriced, fmt.Sprintf(
			"storageClass %q maps to no disk type in this build's table, so the monthly figure is withheld — "+
				"an unmapped class is never priced as the cheapest tier",
			emptyAs(class, "(no storageClass)"))
	}
	// THE SAME CALL THE STORAGE HEADLINE MAKES, so this finding's dollar is a slice of that total and not a
	// second opinion about it. It also knows that Azure bills a TIER: a 100 GiB Premium disk is a P10 at the
	// P10 price, and saying "100 GiB at $x per GB" about it would be a sentence about a bill that does not exist.
	monthly, basis, ok := opts.prices().VolumeMonthly(provider, region, diskType, gib)
	if !ok {
		return 0, types.PriceUnpriced, fmt.Sprintf(
			"no %s storage rate for region %q and disk type %q in this build's table, so the monthly figure "+
				"is withheld", provider, emptyAs(region, "(unknown)"), diskType)
	}
	return monthly, types.PricePriced, fmt.Sprintf(
		"%s %s in region %s: %.1f GiB provisioned is about $%.2f/mo at list, priced %s (the cloud bills "+
			"provisioned capacity, not used bytes; snapshots, provisioned IOPS and throughput above baseline "+
			"are billed separately and are not modelled)", provider, diskType, region, gib, monthly, basis)
}

// cloudVolumeProvider returns the pricing provider for a volume that is provably a managed cloud
// disk, and false for everything else — including an unrecognised CSI driver, which is unpriced
// rather than free.
func cloudVolumeProvider(pv *corev1.PersistentVolume) (string, bool) {
	s := pv.Spec
	if s.CSI != nil {
		p, ok := cloudCSIDrivers[s.CSI.Driver]
		return p, ok
	}
	switch {
	case s.AWSElasticBlockStore != nil:
		return "aws", true
	case s.AzureDisk != nil:
		return "azure", true
	case s.GCEPersistentDisk != nil:
		return "gcp", true
	}
	return "", false
}
