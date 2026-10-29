package collect

import corev1 "k8s.io/api/core/v1"

// zonelabels.go — WHERE A NODE'S ZONE AND REGION COME FROM, AND THE ONE PLACE THAT DECIDES.
//
// THE DEFECT THIS FIXES. Zone was read from `topology.kubernetes.io/zone` alone, in four places. A cluster
// labelled only with the beta key therefore resolved to "unzoned" — an ABSENCE RENDERED AS A FACT, which is
// this project's cardinal defect, and it was silent: nothing in the report said the zone could not be
// determined, because as far as the code was concerned it had been determined.
//
// The consequence scales badly. A zone-loss engine reading one zone that contains every node concludes that
// losing that zone leaves the entire cluster with nowhere to go — a spectacular false positive built on a
// label lookup. Which is why this lands BEFORE the reasoning that stands on it rather than beside it.
//
// WHY THE BETA KEY IS NOT DEAD. `failure-domain.beta.kubernetes.io/zone` was the original key;
// `topology.kubernetes.io/zone` became GA in Kubernetes 1.17 and the kubelet stopped setting the beta one in
// 1.21. THE KUBELET STOPPING IS NOT THE SAME AS NOBODY HAVING IT: an older cluster, an on-prem cluster whose
// operator labels nodes by hand, and several cloud-controller-manager configurations still carry it. Shoalcheck
// audits the cluster in front of it, not the one the release notes describe.
//
// ONE READER, ENFORCED. TestTopologyLabels_HaveExactlyOneReader asserts no other non-test file in
// internal/{collect,rules,report,pipeline,analyzers} names these strings. A fallback present in some readers
// and absent in others is worse than one present in none: the same cluster would be zoned for one rule and
// unzoned for another, and no single output would look wrong.
const (
	gaZoneLabel     = "topology.kubernetes.io/zone"
	betaZoneLabel   = "failure-domain.beta.kubernetes.io/zone"
	gaRegionLabel   = "topology.kubernetes.io/region"
	betaRegionLabel = "failure-domain.beta.kubernetes.io/region"
)

// GAZoneLabel and BetaZoneLabel are exported for callers that need to say WHICH key a cluster carries, rather
// than merely read a zone through the fallback above. A rule reporting that a reading rests on the retired key
// has to name it, and a second copy of a label string in another package is how two packages come to disagree
// about what a zone is.
const (
	GAZoneLabel   = gaZoneLabel
	BetaZoneLabel = betaZoneLabel
)

// ZoneOf is the node's availability zone, or "" when neither label carries one.
//
// EMPTY MEANS UNKNOWN, and it is deliberately not "unzoned": a caller that needs a display string can choose
// one, and a caller that needs to REFUSE — as the zone-loss reasoning does — needs to tell "no zone label"
// apart from "a zone whose name happens to be unzoned".
//
// The GA key wins when both are present and disagree. A cluster carrying both was migrated at some point, and
// the beta value is the one that can be stale.
func ZoneOf(n corev1.Node) string { return firstLabel(n, gaZoneLabel, betaZoneLabel) }

// RegionOf is the node's region, or "". Same GA-then-beta order, same reason.
func RegionOf(n corev1.Node) string { return firstLabel(n, gaRegionLabel, betaRegionLabel) }

// ZoneLabelSource names which key the cluster's zones actually came from, or "" when no node carries either.
//
// It exists so a surface can DISCLOSE that a cluster is zoned only by a deprecated label, rather than
// presenting the derived zone as though it came from the current one. Prefers the GA key when any node has it:
// a mixed cluster is mid-migration, and the modern label is the one to name.
func ZoneLabelSource(nodes []corev1.Node) string {
	beta := false
	for _, n := range nodes {
		if v := n.Labels[gaZoneLabel]; v != "" {
			return gaZoneLabel
		}
		if v := n.Labels[betaZoneLabel]; v != "" {
			beta = true
		}
	}
	if beta {
		return betaZoneLabel
	}
	return ""
}

// firstLabel returns the first non-empty label value among keys.
//
// A PRESENT-BUT-EMPTY LABEL IS NOT A VALUE. Checking presence rather than emptiness would let a node carrying
// `topology.kubernetes.io/zone: ""` shadow a real beta label — and an empty GA key is exactly what a
// half-finished migration or a templating bug leaves behind.
func firstLabel(n corev1.Node, keys ...string) string {
	for _, k := range keys {
		if v := n.Labels[k]; v != "" {
			return v
		}
	}
	return ""
}

// IsZoneLabel reports whether a label key is one of the two zone keys.
//
// Exported for the one caller that must match a key rather than read a node: a PersistentVolume's
// nodeAffinity names the key itself, and a rule comparing it to a literal would miss the beta form — making a
// beta-labelled zonal disk read as unpinned, which is the same class of silent absence this file exists to
// close.
func IsZoneLabel(key string) bool { return key == gaZoneLabel || key == betaZoneLabel }

// volumeZoneKeys are the keys a CSI driver writes a disk's zone in: on the PersistentVolume's nodeAffinity, and
// on every node its node plugin runs on. The values are the same zone names the GA key carries on that
// provider, so a volume pinned in one of them is as zonal as one pinned in the GA key.
//
// THE PLACEMENT MODEL DOES NOT NEED THIS LIST. It evaluates a volume's nodeAffinity against node labels as the
// scheduler does, whatever the key. This list is for the one question a key's NAME answers and an evaluation
// does not: whether the constraint a volume declares is a zone, so a rule can say "this disk ties the pod to
// zone X" rather than only "this pod could not move".
var volumeZoneKeys = map[string]bool{
	"topology.disk.csi.azure.com/zone": true, // Azure Disk
	"topology.ebs.csi.aws.com/zone":    true, // Amazon EBS
	"topology.gke.io/zone":             true, // Compute Engine persistent disk
}

// IsVolumeZoneKey reports whether a key in a PersistentVolume's nodeAffinity names a zone: one of the two node
// keys, or a CSI driver's own.
func IsVolumeZoneKey(key string) bool { return IsZoneLabel(key) || volumeZoneKeys[key] }
