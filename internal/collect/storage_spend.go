package collect

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
)

// gibBytes is one GiB; storage tables are per-GB-month but Kubernetes capacity
// is reported in binary GiB. We price per reported GiB of provisioned capacity
// (the cloud bills the provisioned size, so GiB is the honest unit here).
const gibBytes = 1024 * 1024 * 1024

// StorageDiskType maps a Kubernetes StorageClass NAME to the pricing table's
// diskType key. It is a heuristic on the conventional class names; an UNMAPPED
// class is returned as ("", false) so the caller records it in
// UnpricedStorageClasses rather than pricing it as the cheapest tier.
//
// EXPORTED SO THERE IS ONE MAPPING AND NOT TWO. internal/rules' unattached-volume
// rule prices a single PersistentVolume and must produce a figure the cluster
// total was built from; a private copy of this switch would drift, which is the
// defect class this project has already paid for five times (five spellings of
// "cr:", two banned-word lists, three hand-maintained control tables). See
// TestStorageDiskType_IsTheSameMappingTheSpendTotalUses.
func StorageDiskType(class string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case "gp3", "ebs-gp3":
		return "gp3", true
	case "gp2", "ebs-gp2":
		// gp2 was the EKS default for years, so it is the type a cluster HAS when nobody chose one.
		// It was unmapped here until 2026-08-31, which meant every gp2 volume landed in
		// UnpricedStorageClasses and the storage headline silently omitted it.
		return "gp2", true
	case "managed-premium", "premium_lrs", "managed-csi-premium":
		return "Premium_LRS", true
	case "managed-csi", "standardssd_lrs", "default":
		return "StandardSSD_LRS", true
	case "standard_lrs", "azurefile":
		return "Standard_LRS", true
	}
	return "", false
}

// StorageDiskTypeFor resolves a StorageClass to the pricing table's diskType key, PREFERRING THE
// CLASS OBJECT OVER ITS NAME.
//
// A name is a convention; `parameters` is what the provisioner actually acts on. A cluster whose
// class is called "fast" or "default" while carrying `type: gp2` is priced correctly by this and was
// not priced at all by the name switch alone — and, worse for a rule that recommends a change, a
// class NAMED gp3 may carry `type: gp2`, in which case the name would produce a confident wrong
// answer rather than an honest absence.
//
// Falls back to the name when the class object is absent, which is the ordinary case for a PV whose
// StorageClass has since been deleted — the PV keeps the name, and the name is all there is.
//
// ONE MAPPING, NOT TWO: this is the single entry point for both the spend total and any rule that
// prices one volume. See TestStorageDiskType_IsTheSameMappingTheSpendTotalUses.
func StorageDiskTypeFor(classes []storagev1.StorageClass, name string) (string, bool) {
	for i := range classes {
		if classes[i].Name != name || name == "" {
			continue
		}
		if dt, ok := diskTypeFromParameters(classes[i]); ok {
			return dt, true
		}
		break // the class exists and its parameters say nothing we price — the name will not know better
	}
	return StorageDiskType(name)
}

// diskTypeFromParameters reads the provisioner's own key. Only types the pricing tables carry are
// returned; anything else is ("", false) so it is RECORDED as unpriced rather than approximated to a
// neighbouring tier — the same posture as an unknown instance type.
func diskTypeFromParameters(sc storagev1.StorageClass) (string, bool) {
	get := func(keys ...string) string {
		for _, k := range keys {
			for pk, pv := range sc.Parameters {
				if strings.EqualFold(pk, k) {
					return strings.TrimSpace(pv)
				}
			}
		}
		return ""
	}
	switch {
	case strings.Contains(sc.Provisioner, "aws"):
		switch strings.ToLower(get("type")) {
		case "gp2":
			return "gp2", true
		case "gp3":
			return "gp3", true
		}
	case strings.Contains(sc.Provisioner, "azure"):
		switch strings.ToLower(get("skuName", "storageaccounttype", "skuname")) {
		case "premium_lrs":
			return "Premium_LRS", true
		case "premium_zrs":
			return "Premium_ZRS", true
		case "standardssd_lrs":
			return "StandardSSD_LRS", true
		case "standardssd_zrs":
			return "StandardSSD_ZRS", true
		case "standard_lrs":
			return "Standard_LRS", true
		}
	}
	return "", false
}

// estimateStorageSpend sums provisioned PV capacity (authoritative) plus
// UNBOUND PVC requests (fallback), priced at list per GB-month for the
// (provider, region, storageClass→diskType). A bound PVC is NEVER double-counted
// with its PV (dedup by pv name / pvc.Spec.VolumeName). An unpriced class is
// recorded in the returned slice and NOT summed — same posture as
// UnpricedNodeTypes. Returns (monthlyUSD, sorted unique unpriced class names).
func estimateStorageSpend(inv *Inventory, region, provider string, pp pricing.PriceProvider) (float64, []string) {
	var total float64
	unpricedSet := map[string]bool{}

	price := func(class string, bytes int64) {
		if bytes <= 0 {
			return
		}
		diskType, ok := StorageDiskTypeFor(inv.StorageClasses, class)
		if !ok {
			if class == "" {
				class = "(no storageClass)"
			}
			unpricedSet[class] = true
			return
		}
		// ONE ENTRY POINT FOR A VOLUME'S PRICE. pricing.VolumeMonthly knows that AWS bills per GB-month and
		// Azure bills a fixed TIER (a 100 GiB Premium claim is a P10, 128 GiB, at the P10 price). Until
		// 2026-09-02 this multiplied Azure GiB by a per-GB approximation, which under-reported every small
		// disk and mis-shaped every large one. The unattached-volume rule prices through the same call, so
		// the headline and a finding about one disk can never disagree.
		gib := float64(bytes) / float64(gibBytes)
		usd, _, ok := pp.VolumeMonthly(provider, region, diskType, gib)
		if !ok {
			if class == "" {
				class = "(no storageClass)"
			}
			unpricedSet[class] = true
			return
		}
		total += usd
	}

	// PVs are authoritative for bound capacity.
	for i := range inv.PVs {
		pv := inv.PVs[i]
		q := pv.Spec.Capacity[corev1.ResourceStorage]
		price(pv.Spec.StorageClassName, q.Value())
	}
	// Unbound/Pending PVCs (no VolumeName) are priced off requests.storage — a
	// bound PVC's capacity already counted via its PV, so it is skipped.
	for i := range inv.PVCs {
		pvc := inv.PVCs[i]
		if pvc.Spec.VolumeName != "" {
			continue // bound — counted via the PV
		}
		class := ""
		if pvc.Spec.StorageClassName != nil {
			class = *pvc.Spec.StorageClassName
		}
		req := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
		price(class, req.Value())
	}

	if len(unpricedSet) == 0 {
		return total, nil
	}
	unpriced := make([]string, 0, len(unpricedSet))
	for c := range unpricedSet {
		unpriced = append(unpriced, c)
	}
	sort.Strings(unpriced)
	return total, unpriced
}
