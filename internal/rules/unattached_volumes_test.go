package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// ---------------------------------------------------------------------------------------------
// UNATTACHED VOLUMES — the guard for what this rule may not say.
//
// This is one of only three rules in the tree that carries a real dollar, so the bans here are
// about the two ways a cost finding loses trust: inventing the money, and recommending the
// destructive action that would "save" it.
//
//	NO VERDICT ABOUT INTENT. "orphan", "abandoned", "unused", "waste", "leaked", "stale" are all
//	claims about why a volume is in the phase it is in. status.phase says what it is, never why: a
//	Released volume under a Retain policy is the policy working exactly as written, and an
//	Available one may be a pre-provisioned pool.
//
//	NO RECOMMENDATION TO DELETE. `delete` is in destructiveVerbs (safety.go) and deleting a
//	PersistentVolume can destroy the only copy of the data a Retain policy exists to preserve. The
//	remediation is a commented inspection step, never an action, and there is no RemediationYAML.
//
//	NO CLAIM ABOUT WHAT IS ON THE VOLUME. We never read a volume's contents and could not.
//
//	NO SAVINGS CLAIM. The figure is what the volume COSTS. What deleting it would save is a
//	different sentence, and whether it can be deleted is not ours to say. ("verified savings" and
//	"realized savings" are already global in lexicon.Banned().)
// ---------------------------------------------------------------------------------------------

var unattachedBannedPhrases = []string{
	"orphan", "abandoned", "unused", "waste", "wasted", "leaked", "stale",
	"safe to delete", "no longer needed", "can be deleted", "should be deleted",
	"nobody is using", "not in use",
	"savings", "reclaimable", "recover the cost",
}

func TestUnattachedVolumes_EmitNoUnsupportableClaim(t *testing.T) {
	fs := (UnattachedVolume{}).Evaluate(pvInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings on the volume fixture — the guard would be vacuous")
	}
	for _, f := range fs {
		blob := strings.ToLower(strings.Join([]string{
			f.Title, f.Description, f.WhyItMatters,
			strings.Join(f.Evidence, " "), f.RemediationYAML, f.RemediationCommand,
		}, " "))
		for _, banned := range unattachedBannedPhrases {
			if strings.Contains(blob, banned) {
				t.Errorf("emits the banned phrase %q — status.phase says what a volume is, never why.\n  finding: %s",
					banned, f.Title)
			}
		}
	}
}

// TestUnattachedVolumes_ThreePhasesReadDifferently — Available, Released and Failed are three
// different statements about three different clusters. A rule that renders them alike has described
// at most one of them.
//
// IT ASSERTS THE EXPLANATION, NOT THE WHOLE DESCRIPTION, AND A PROBE IS WHY. The first version of
// this test compared Finding.Description strings and passed even when all three phase explanations
// were collapsed into one sentence — because the Description also interpolates the phase name and
// the volume's size, so three descriptions differ whatever the explanation says. That is the
// "a test whose name claimed more than it measured" defect, caught before it shipped this time.
// unattachedPhaseNote is now asserted directly, and each finding is checked for the concept that
// makes its phase distinct.
func TestUnattachedVolumes_ThreePhasesReadDifferently(t *testing.T) {
	notes := map[corev1.PersistentVolumePhase]string{}
	for _, p := range []corev1.PersistentVolumePhase{
		corev1.VolumeAvailable, corev1.VolumeReleased, corev1.VolumeFailed,
	} {
		note, ok := unattachedPhaseNote(p)
		if !ok || strings.TrimSpace(note) == "" {
			t.Fatalf("phase %s has no explanation — nothing to compare", p)
		}
		for other, seen := range notes {
			if seen == note {
				t.Errorf("phases %s and %s share one explanation — it is false for at least one of them", p, other)
			}
		}
		notes[p] = note
	}
	// Bound is a volume doing its job; Pending is a provisioner mid-flight. Neither is reportable,
	// and this is the non-vacuity guard for the whole rule: without it the test above passes on a
	// rule that fires on every volume it sees.
	for _, p := range []corev1.PersistentVolumePhase{corev1.VolumeBound, corev1.VolumePending} {
		if _, ok := unattachedPhaseNote(p); ok {
			t.Errorf("phase %s is reportable — it must not be", p)
		}
	}

	byPV := map[string]types.Finding{}
	for _, f := range (UnattachedVolume{}).Evaluate(pvInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "PersistentVolume" {
				byPV[ref.Name] = f
			}
		}
	}
	if _, fired := byPV["pv-bound"]; fired {
		t.Error("pv-bound is a volume doing its job — it must be silent")
	}
	if _, fired := byPV["pv-pending"]; fired {
		t.Error("pv-pending is a provisioner mid-flight, not a volume nothing is using")
	}
	// The concept that makes each phase its own statement, asserted in the rendered finding.
	for pv, want := range map[string]string{
		"pv-available": "no claim has ever bound",
		"pv-released":  "that claim is gone",
		"pv-failed":    "reclamation",
	} {
		f, ok := byPV[pv]
		if !ok {
			t.Fatalf("no finding for %s — nothing to compare", pv)
		}
		blob := f.Description + " " + strings.Join(f.Evidence, " ")
		if !strings.Contains(blob, want) {
			t.Errorf("%s never says %q — its phase reads like one of the other two", pv, want)
		}
	}
}

// TestUnattachedVolumes_PricesOnlyACloudSource — the gate is the volume's OWN source, not a cloud
// providerID on some node. A cluster with aws:// nodes can hold local and hostPath volumes that cost
// nothing at all, and kind's local-path-provisioner produces exactly those. Pricing one against an
// EBS table invents money on the cheapest possible cluster.
func TestUnattachedVolumes_PricesOnlyACloudSource(t *testing.T) {
	byPV := map[string]types.Finding{}
	for _, f := range (UnattachedVolume{}).Evaluate(pvInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "PersistentVolume" {
				byPV[ref.Name] = f
			}
		}
	}
	cloud, ok := byPV["pv-available"]
	if !ok {
		t.Fatal("no finding for pv-available (csi ebs.csi.aws.com, gp3, priced region)")
	}
	if cloud.DollarImpactMonthly <= 0 {
		t.Fatalf("a gp3 CSI volume in a priced region carries $%.2f — if this is 0 the rest of this test proves nothing",
			cloud.DollarImpactMonthly)
	}
	if cloud.PriceBasis != types.PricePriced {
		t.Errorf("a priced volume has priceBasis=%q, want %q", cloud.PriceBasis, types.PricePriced)
	}
	local, ok := byPV["pv-local"]
	if !ok {
		t.Fatal("no finding for pv-local — the withheld-dollar path is not exercised")
	}
	if local.DollarImpactMonthly != 0 {
		t.Errorf("a local volume carries $%.2f — there is no bill for a directory on a node",
			local.DollarImpactMonthly)
	}
	if local.PriceBasis != types.PriceNotCost {
		t.Errorf("a local volume has priceBasis=%q, want %q: there is no price to miss, which is a "+
			"different statement from a price we could not find", local.PriceBasis, types.PriceNotCost)
	}
}

// TestUnattachedVolumes_UnmappedClassIsUnpricedNotZero — the two zeros mean different things and
// PriceBasis is the field that says which. An unrecognised class on a real cloud disk is `unpriced`;
// a directory on a node is `not-cost`. Asserted beside a volume that IS priced, so the test cannot
// pass on a rule that never prices anything.
func TestUnattachedVolumes_UnmappedClassIsUnpricedNotZero(t *testing.T) {
	byPV := map[string]types.Finding{}
	for _, f := range (UnattachedVolume{}).Evaluate(pvInventory(), Options{}) {
		for _, ref := range f.AffectedResources {
			if ref.Kind == "PersistentVolume" {
				byPV[ref.Name] = f
			}
		}
	}
	if p := byPV["pv-available"].PriceBasis; p != types.PricePriced {
		t.Fatalf("the priced control volume has basis %q — every assertion below would be vacuous", p)
	}
	weird, ok := byPV["pv-weird-class"]
	if !ok {
		t.Fatal("no finding for pv-weird-class")
	}
	if weird.DollarImpactMonthly != 0 {
		t.Errorf("an unmapped class was priced at $%.2f — an unmapped class must never be priced as a tier",
			weird.DollarImpactMonthly)
	}
	if weird.PriceBasis != types.PriceUnpriced {
		t.Errorf("unmapped class has priceBasis=%q, want %q", weird.PriceBasis, types.PriceUnpriced)
	}
	drv, ok := byPV["pv-unknown-driver"]
	if !ok {
		t.Fatal("no finding for pv-unknown-driver")
	}
	if drv.PriceBasis != types.PriceUnpriced {
		t.Errorf("an unrecognised CSI driver has priceBasis=%q, want %q — it may well be a billed cloud "+
			"disk from a driver we have no table for, which is not the same as no bill",
			drv.PriceBasis, types.PriceUnpriced)
	}
}

// TestUnattachedVolumes_EveryDollarCitesItsBasis — validate.go rejects a non-zero dollar with empty
// evidence. Asserted here too, per the checklist, and with the price rate named rather than merely
// present.
func TestUnattachedVolumes_EveryDollarCitesItsBasis(t *testing.T) {
	priced := 0
	for _, f := range (UnattachedVolume{}).Evaluate(pvInventory(), Options{}) {
		if f.DollarImpactMonthly == 0 {
			continue
		}
		priced++
		if len(f.Evidence) == 0 {
			t.Errorf("%q bills $%.2f with no evidence", f.Title, f.DollarImpactMonthly)
		}
		if !strings.Contains(strings.ToLower(strings.Join(f.Evidence, " ")), "per gb-month") {
			t.Errorf("%q bills $%.2f without naming the rate it came from", f.Title, f.DollarImpactMonthly)
		}
	}
	if priced == 0 {
		t.Fatal("nothing was priced — this test proves nothing")
	}
}

// TestUnattachedVolumes_NeverRecommendsDeletion — deleting a PersistentVolume can destroy the only
// copy of the data a Retain policy was written to preserve.
func TestUnattachedVolumes_NeverRecommendsDeletion(t *testing.T) {
	fs := (UnattachedVolume{}).Evaluate(pvInventory(), Options{})
	if len(fs) == 0 {
		t.Fatal("no findings — the safety guard would be vacuous")
	}
	for _, f := range fs {
		if f.RemediationYAML != "" {
			t.Errorf("%q carries remediation YAML; there is no patch that is safe here", f.Title)
		}
		cmd := strings.TrimSpace(f.RemediationCommand)
		if cmd == "" {
			continue
		}
		if !strings.HasPrefix(cmd, "#") {
			t.Errorf("%q offers an uncommented command %q — this must be documentation, not a copy button",
				f.Title, cmd)
		}
		if strings.Contains(strings.ToLower(cmd), "delete") {
			t.Errorf("%q names delete in its remediation: %q", f.Title, cmd)
		}
	}
}

// TestUnattachedVolumes_ClaimRefSentenceNeedsThePVCList — a Released volume's claimRef names a claim
// that was deleted, and "not present in this reading" is an absence claim over the PVC list. Both
// halves are asserted: the finding must survive the denial, and the sentence must not.
func TestUnattachedVolumes_ClaimRefSentenceNeedsThePVCList(t *testing.T) {
	const marker = "is not in this reading"

	withPVCs := (UnattachedVolume{}).Evaluate(pvInventory(), Options{})
	found := false
	for _, f := range withPVCs {
		if strings.Contains(strings.Join(f.Evidence, " "), marker) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no finding says %q with the claim list read — the denial half below would be vacuous", marker)
	}

	inv := pvInventory()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "persistentvolumeclaims")
	inv.Meta.Denied = append(inv.Meta.Denied, "persistentvolumeclaims: forbidden")
	degraded := (UnattachedVolume{}).Evaluate(inv, Options{})
	if len(degraded) != len(withPVCs) {
		t.Errorf("a refused claim list changed the finding count from %d to %d — the phase reading does not "+
			"depend on the claim list", len(withPVCs), len(degraded))
	}
	// Only the volume that HAS a claimRef makes a claim about the claim list. A volume with none
	// says "spec.claimRef is absent", which needs no caveat and must not gain one — demanding the
	// caveat everywhere would be demanding a sentence about a list the finding never consults.
	checked := 0
	for _, f := range degraded {
		blob := strings.Join(f.Evidence, " ")
		if strings.Contains(blob, marker) {
			t.Errorf("%q asserts a claim is absent from a refused list", f.Title)
		}
		if !strings.Contains(blob, "spec.claimRef names") {
			continue
		}
		checked++
		if !strings.Contains(strings.ToLower(blob), "was not read") {
			t.Errorf("%q names a claimRef and never says the claim list was not read", f.Title)
		}
	}
	if checked == 0 {
		t.Fatal("no finding in the degraded run names a claimRef — the caveat assertion would be vacuous")
	}
}

// TestUnattachedVolumes_SkipWhenTheInputWasDenied — a refused volume list read as "no volumes" is
// the same fabrication every other rule in this package guards against.
func TestUnattachedVolumes_SkipWhenTheInputWasDenied(t *testing.T) {
	if len((UnattachedVolume{}).Evaluate(pvInventory(), Options{})) == 0 {
		t.Fatal("the rule fires on nothing in the fixture — the denial guard test would be vacuous")
	}
	inv := pvInventory()
	inv.Meta.Collected = withoutKind(inv.Meta.Collected, "persistentvolumes")
	inv.Meta.Denied = append(inv.Meta.Denied, "persistentvolumes: forbidden")
	if got := (UnattachedVolume{}).Evaluate(inv, Options{}); len(got) != 0 {
		t.Errorf("emitted %d finding(s) with the volume list denied", len(got))
	}
}

// ---------------------------------------------------------------------------------------------
// The fixture. Nodes in eu-central-1 (a region the gp3 table covers) so the priced path is real
// arithmetic rather than a stub.
// ---------------------------------------------------------------------------------------------

func pvInventory() *collect.Inventory {
	return &collect.Inventory{
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-a",
				Labels: map[string]string{
					"topology.kubernetes.io/region":    "eu-central-1",
					"node.kubernetes.io/instance-type": "m6i.large",
				},
			},
			Spec: corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/i-0abc"},
		}},
		PVs: []corev1.PersistentVolume{
			pv("pv-available", corev1.VolumeAvailable, corev1.PersistentVolumeReclaimDelete, "100Gi", "gp3", csiSource("ebs.csi.aws.com"), nil),
			pv("pv-released", corev1.VolumeReleased, corev1.PersistentVolumeReclaimRetain, "500Gi", "gp3", csiSource("ebs.csi.aws.com"),
				&corev1.ObjectReference{Kind: "PersistentVolumeClaim", Namespace: "app", Name: "gone-claim"}),
			pv("pv-failed", corev1.VolumeFailed, corev1.PersistentVolumeReclaimDelete, "20Gi", "gp3", csiSource("ebs.csi.aws.com"), nil),
			pv("pv-bound", corev1.VolumeBound, corev1.PersistentVolumeReclaimDelete, "50Gi", "gp3", csiSource("ebs.csi.aws.com"),
				&corev1.ObjectReference{Kind: "PersistentVolumeClaim", Namespace: "app", Name: "live-claim"}),
			pv("pv-pending", corev1.VolumePending, corev1.PersistentVolumeReclaimDelete, "10Gi", "gp3", csiSource("ebs.csi.aws.com"), nil),
			// Same size and class as pv-available, different source: a directory on a node.
			pv("pv-local", corev1.VolumeAvailable, corev1.PersistentVolumeReclaimDelete, "100Gi", "gp3",
				corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: "/mnt/disks/a"}}, nil),
			pv("pv-weird-class", corev1.VolumeAvailable, corev1.PersistentVolumeReclaimDelete, "100Gi", "weird-tier", csiSource("ebs.csi.aws.com"), nil),
			pv("pv-unknown-driver", corev1.VolumeAvailable, corev1.PersistentVolumeReclaimDelete, "100Gi", "gp3", csiSource("some.vendor.csi"), nil),
		},
		PVCs: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Name: "live-claim", Namespace: "app"},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-bound"},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}},
		Meta: collect.Meta{
			Collected: []string{"nodes", "persistentvolumeclaims", "persistentvolumes"},
			StartedAt: rotNow,
		},
	}
}

func csiSource(driver string) corev1.PersistentVolumeSource {
	return corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{
		Driver: driver, VolumeHandle: "vol-0abc",
	}}
}

func pv(name string, phase corev1.PersistentVolumePhase, reclaim corev1.PersistentVolumeReclaimPolicy,
	size, class string, src corev1.PersistentVolumeSource, claimRef *corev1.ObjectReference) corev1.PersistentVolume {
	return corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)},
			StorageClassName:              class,
			PersistentVolumeReclaimPolicy: reclaim,
			PersistentVolumeSource:        src,
			ClaimRef:                      claimRef,
		},
		Status: corev1.PersistentVolumeStatus{Phase: phase},
	}
}
