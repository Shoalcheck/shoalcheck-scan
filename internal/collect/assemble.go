package collect

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/buildinfo"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/refdata"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Version is stamped into Provenance and Methodology. It is the release internal/buildinfo was stamped with
// (-ldflags "-X shoalcheck/internal/buildinfo.Version=v0.2.0"), "dev" in a local build — the stamp moved there so a
// binary that does not link the collector, the MCP server, carries it too. A variable, so a test can set it.
var Version = buildinfo.Release()

// BuildReport assembles a schema-v1 AuditReport from a collected Inventory
// and the findings the rules produced. Summary is ALWAYS derived — never
// trusted from anywhere else.
//
// discount is a fractional list-price reduction in [0, 0.9] (e.g. 0.3 = 30%
// off, for RI/Savings-Plan-adjusted numbers). It scales the COMPUTE part of
// EstimatedMonthlySpend and every compute-denominated finding's dollar
// and is documented in the Methodology. Out-of-range values are clamped.
func BuildReport(inv *Inventory, findings []types.Finding, clusterName string, discount float64, pp pricing.PriceProvider) *types.AuditReport {
	discount = clampDiscount(discount)
	// A NIL PROVIDER IS THE EMBEDDED SNAPSHOT, decided once here. Callers that predate the provider seam
	// pass nil; every helper below prices through pp directly, so the default has to be made before the
	// first of them runs rather than inside whichever one happens to check.
	if pp == nil {
		pp = pricing.Embedded()
	}
	// THE DISCOUNT REACHES THE FINDINGS' DOLLARS, BEFORE THE SUMMARY IS DERIVED FROM THEM.
	//
	// Until 2026-09-02 it did not. `spend` below was scaled and Summary.EstimatedSavingsUSD — the sum of
	// per-finding DollarImpactMonthly, computed in the rules at list — was not, so --discount 0.5 halved
	// the stated spend and left the savings whole: savings grew as a share of spend the larger the discount,
	// and at the 0.9 clamp could exceed the entire stated bill. validate.go re-derives the summary from the
	// findings, which is exactly why the scaling has to happen HERE, on the findings, and not on the total.
	//
	// AND IT REACHES ONLY COMPUTE. A Savings Plan or Reserved Instance covers instance hours. Storage, load
	// balancers and the control-plane fee are billed at list whatever the commitment, and so are the
	// savings a rule states about them. A finding that declares no kind is left at list — the discount is
	// withheld from it, never applied to it — and TestGolden_EveryDollarSaysWhatItIsADollarOf names the rule.
	applyComputeDiscount(findings, discount)
	// NONE IS AN EMPTY LIST. A reading with no finding was written as "findings": null — the encoding for "no
	// answer" standing in for the answer "none", and a field that read two ways depending on what was found.
	if findings == nil {
		findings = []types.Finding{}
	}
	types.SortByPriority(findings)

	ar := &types.AuditReport{
		SchemaVersion: "v1",
		// UTC, AND TO THE SECOND. `time.Now()` keeps the operator's zone, and a redacted reading — cluster,
		// namespaces and workloads all replaced by tokens — then printed "2026-09-11 02:28 EEST" on every
		// section of the document it was built to let somebody share. The microseconds were the second half:
		// a stamp precise enough to tie two supposedly independent documents to one installation and one run.
		// internal/evidence already wrote opts.Now().UTC() and was right. See
		// TestRender_StatesTheMomentInUTCWhateverZoneTheReadingCarries.
		// AND IT IS THE READING'S OWN CLOCK, not a second one. GeneratedAt is rendered as a DATE into the
		// methodology — "read via dynamic discovery … as of 2026-09-15" — and a date in prose is not an
		// RFC3339 instant, so the golden gate's instant-normalisation cannot see it: both reference readings
		// drifted at midnight UTC through this line after the durations had already been pinned. One fact,
		// one clock. A real audit sets StartedAt to time.Now() at the top of Collect, so this moves the
		// stamp from "when assembly finished" to "when the reading was taken", seconds apart and the more
		// defensible of the two.
		GeneratedAt: readingStamp(inv),
		Findings:    findings,
		Summary:     types.DeriveSummary(findings),
	}

	region := regionFrom(inv.Nodes)
	provider := providerFrom(inv.Nodes)
	ar.Architecture = buildArchitecture(inv, findings, region, provider, pp)
	ar.Highlights = deriveHighlights(findings)
	// Transient fingerprint for genuine cross-cluster link detection in fleet
	// mode (never serialized). Single-cluster reports compute but ignore it.
	ar.FleetLinkage = buildFleetLinkage(inv)

	// Compute is what a commitment discounts. It is scaled on its own, BEFORE storage is added — the
	// previous order added storage first and then scaled the sum, which applied a compute commitment to
	// GB-months that no Savings Plan has ever covered.
	//
	// AND ONLY COMPUTE: the control-plane fee and the load-balancer base were summed in with the nodes and then
	// discounted with them, so `--discount 0.3` cut the EKS fee by 30% while the help and the methodology note beside
	// the figure both said it stays at list.
	nodes, fees := estimateMonthlySpendParts(inv, ar.Architecture, region, provider, pp)
	spend := nodes*(1-discount) + fees
	// Storage spend from Phase-0-collected PV/PVC capacity, priced at list per
	// GB-month through the resolved provider. An unpriced class is recorded (not
	// summed) so storage is honestly undercounted rather than silently wrong.
	// AT LIST: storage is not compute and the discount does not reach it.
	storage, unpricedStorage := estimateStorageSpend(inv, region, provider, pp)
	spend += storage
	if ar.Architecture != nil {
		ar.Architecture.UnpricedStorageClasses = unpricedStorage
	}

	// Region-coverage suppression — the single biggest credibility guard.
	// When the provider is a recognized cloud but its REGION isn't in the node
	// pricing tables (e.g. aks/francecentral, gke/europe-west3), every node
	// priced to $0 and `spend` is only the LB/control-plane residue — a
	// misleadingly low headline in front of a paying buyer. Suppress it to the
	// existing honest $0/unpriced empty state rather than show a fabricated
	// near-zero number. (A covered region with a single UNKNOWN instance type is
	// NOT suppressed: that is the per-type UnpricedNodeTypes path, which honestly
	// undercounts; only a wholly-uncovered region zeroes the headline.)
	suppressed := regionUnpriced(provider, region, pp)
	if suppressed {
		spend = 0
	}

	// Storage headline breakout: 0 when the region is wholly suppressed, else the
	// storage component at list (it is already folded into `spend` above, also at list).
	storageHeadline := storage
	if suppressed {
		storageHeadline = 0 // region wholly unpriced ⇒ no storage headline either
	}

	ar.Cluster = types.ClusterInfo{
		Name:                  clusterName,
		KubernetesVersion:     strings.TrimPrefix(inv.Meta.ServerVersion, "v"),
		Provider:              provider,
		Region:                region,
		NodeCount:             len(inv.Nodes),
		PodCount:              len(inv.Pods),
		NamespaceCount:        len(inv.Namespaces),
		EstimatedMonthlySpend: spend,
		StorageMonthlyUSD:     storageHeadline,
		SpendSource:           spendSource(ar.Architecture),
	}

	// A VERSION THAT WAS NOT READ IS NAMED AS NOT READ. This printed "Kubernetes API (server )" whenever
	// discovery did not answer — an empty slot where a version goes, on the methodology line of exactly the
	// reading a customer sends back when something went wrong. The smallest form of the rule this project
	// keeps applying: a value nobody read is never printed as though it were read and happened to be nothing.
	apiSource := "Kubernetes API (server version not read)"
	if v := strings.TrimSpace(inv.Meta.ServerVersion); v != "" {
		apiSource = fmt.Sprintf("Kubernetes API (server %s)", v)
	}
	sources := []string{apiSource}
	if len(inv.Meta.Denied) > 0 {
		sources = append(sources, deniedSourceNote(inv.Meta.Denied))
	}
	sources = append(sources, pricingMethodologyNote(provider, discount, pvPVCListed(inv), pp))
	if len(unpricedStorage) > 0 {
		sources = append(sources, fmt.Sprintf(
			"%s excluded from storage spend: %s", nWord(len(unpricedStorage), "unpriced storage class", "unpriced storage classes"), strings.Join(unpricedStorage, ", ")))
	}
	if suppressed {
		sources = append(sources, uncoveredRegionNote(provider, region))
	}
	ar.Methodology = types.Methodology{
		CollectorsRun:      []string{"kubernetes"},
		RunDurationSeconds: int(inv.Meta.Duration.Seconds()),
		DataSources:        sources,
		CollectedKinds:     append([]string(nil), inv.Meta.Collected...),
		DeniedKinds:        deniedKindNames(inv.Meta.Denied),
		// THE CAUSES AS A FIELD, not only inside the prose note. This function already classifies every
		// failure to build that sentence; carrying the pairs costs nothing and stops a rephrased sentence
		// from silently emptying the causes of every saved reading.
		Unread: unreadPairs(inv.Meta.Denied),
		// What it read, in units another reader would need. Pairs is filled by the pipeline, which knows
		// which rules ran over which kinds; this package does not import the registry.
		Volume: readVolume(inv),
	}
	// THE RUN BASIS IS ALWAYS BUILT, not only when a cluster UID was readable.
	//
	// It used to be created only inside `if uid != ""`, which coupled two unrelated facts: whether we could
	// read kube-system's UID, and which version of OUR price table produced the figures. The second is true
	// regardless of the first, and a report with no UID still needs its data stamped — otherwise a comparison
	// against it withholds the dollar delta for the wrong reason and says so in the wrong words.
	//
	// An empty ClusterUID inside a present RunBasis is already a documented state: "no comparison may claim
	// identity" (see the field's own comment), and Gate 0 reads the string, not the pointer.
	ar.Methodology.RunBasis = &types.RunBasis{
		ClusterUID:   clusterUID(inv),
		DataVersions: refdata.Stamp(pp),
	}
	// The policy-shape projection. Built from the Inventory here because this is the last point at which
	// anything holds it — see policy_posture.go, and the fleet-divergence spec §2.3 for why deriving the
	// same shape from findings later is not an option.
	ar.PolicyPosture = buildPolicyPosture(inv)
	return ar
}

// applyComputeDiscount scales the DollarImpactMonthly of every COMPUTE-denominated finding by (1-discount),
// in place, so the summary derived from them carries the same commitment the spend headline does. Storage,
// network and control-plane figures are untouched: a compute commitment is not a discount on the bill, it is
// a discount on instance hours. A finding with no SpendKind is untouched too — withholding a discount is
// recoverable, applying one to the wrong meter is not.
func applyComputeDiscount(findings []types.Finding, discount float64) {
	if discount <= 0 {
		return
	}
	for i := range findings {
		if findings[i].SpendKind == types.SpendCompute && findings[i].DollarImpactMonthly > 0 {
			list := findings[i].DollarImpactMonthly
			findings[i].DollarImpactMonthly *= (1 - discount)
			// THE EVIDENCE RECONCILES THE FIGURE. The rules price at list, so the arithmetic above this line ends in
			// the list figure — "-> memory-bound up to $48.34/mo" — while the finding carries the discounted one.
			// Two figures for one finding with nothing joining them reads as an error in one of them.
			findings[i].Evidence = append(append([]string(nil), findings[i].Evidence...), fmt.Sprintf(
				"after the %.0f%% compute discount this reading was given, this is $%.2f/mo; the arithmetic above is "+
					"at list ($%.2f/mo)", discount*100, findings[i].DollarImpactMonthly, list))
		}
	}
}

// clampDiscount bounds a discount fraction to [0, 0.9] — guards against a
// negative discount (which would inflate spend) or an implausible >90% off.
func clampDiscount(d float64) float64 {
	switch {
	case d < 0:
		return 0
	case d > 0.9:
		return 0.9
	}
	return d
}

// estimateMonthlySpendParts sums priced compute plus best-effort managed
// control-plane and load-balancer charges for the cluster's cloud provider
// (EKS/AKS/GKE). It does NOT fabricate EBS/PV/managed-disk storage (PVs aren't
// collected). Pool CostMo is expected to already be set by buildArchitecture.
//
// The control-plane fee and LB base are added for any recognized cloud
// provider (pricing normalizes eks/aks/gke → aws/azure/gcp). Providers with no
// modelled fee — AKS free tier ($0), or kind/onprem/unknown (no LB price) —
// contribute nothing, which is the honest default rather than a fabricated 0.
//
// IN THE TWO PARTS A COMPUTE COMMITMENT TREATS DIFFERENTLY: the node hours it discounts, and the fees — control
// plane, load-balancer base — it does not. One sum was discounted whole, fees included.
func estimateMonthlySpendParts(inv *Inventory, arch *types.Architecture, region, provider string, pp pricing.PriceProvider) (nodes, fees float64) {
	for _, p := range arch.NodePools {
		nodes += float64(p.Count) * p.CostMo
	}
	// Managed control-plane fee (0 for AKS free tier and non-cloud providers).
	fees += pp.ControlPlaneMonthly(provider)
	// Best-effort LB base: one per LoadBalancer Service. Excludes capacity/
	// rule/data overage. ok=false for providers/regions without an LB price.
	if lb, ok := pp.LBMonthly(provider, region); ok {
		for _, s := range inv.Services {
			if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
				fees += lb
			}
		}
	}
	return nodes, fees
}

// spendSource derives the basis of EstimatedMonthlySpend from the assembled
// pools' CostSource. It is deliberately CONSERVATIVE about emitting a value so a
// cluster with NO capacity labels stays byte-identical to the pre-Layer-1
// output:
//
//   - any spot pool present  ⇒ CostSourceSpotCeiling (the total includes at
//     least one upper-bound pool — honest provenance for the whole number).
//   - no spot, but at least one pool with KNOWN capacity (on-demand) ⇒
//     CostSourceListEstimate (capacity was affirmatively observed).
//   - every pool is unknown capacity (no labels anywhere — a self-managed node
//     group's case; the golden persona carried no label until 2026-09-02) ⇒ ""
//     (zero value, omitempty) so nothing new is stamped and the report
//     serializes byte-identically.
//
// The MATH behind EstimatedMonthlySpend is unchanged in all three cases; only
// the provenance label differs.
func spendSource(arch *types.Architecture) types.CostSource {
	if arch == nil {
		return ""
	}
	anyKnown := false
	for _, p := range arch.NodePools {
		switch p.Capacity {
		case types.CapacitySpot:
			return types.CostSourceSpotCeiling
		case types.CapacityOnDemand:
			anyKnown = true
		}
	}
	if anyKnown {
		return types.CostSourceListEstimate
	}
	return ""
}

// pvPVCListed reports whether BOTH the cluster-scoped PV list and the PVC list
// were collected (not denied). PV is cluster-scoped and is often RBAC-restricted,
// so this can be false even on a healthy run — in which case the methodology note
// must NOT claim storage was "summed", to avoid asserting a $0 storage figure off
// a denied list (denial-guard standard).
func pvPVCListed(inv *Inventory) bool {
	return collected(inv, "persistentvolumes") && collected(inv, "persistentvolumeclaims")
}

// collected is this package's name for Observed. Kept as a name rather than replaced at each call site so
// the reading inside internal/collect stays local, while the RULE it implements lives in one place.
func collected(inv *Inventory, kind string) bool { return Observed(inv, kind) }

// Observed reports whether the collector confirmed a successful list of this step kind.
//
// THE ONE IMPLEMENTATION OF THE DENIAL GUARD. It used to be three — this function, rules.observed and
// analyzers.listSucceeded — each a hand-written copy of the same eight lines, and the project has already
// paid for that shape twice: three of the four copies once carried an escape hatch treating "mentioned by
// neither slice" as success, which waved through exactly the fabricated-absence claim the guard exists to
// stop. A rule you must remember to apply identically in three files is not a rule.
//
// The semantics, unchanged and load-bearing in all three callers:
//
//   - DENIED IS CHECKED FIRST. A well-formed Meta names a kind in exactly one slice; if it somehow appears
//     in both, the refusal is the safe reading. The prefix match is because the collector records a denial
//     as "<kind>: <error>".
//   - A KIND IN NEITHER SLICE IS FALSE. The run has no record of having looked, and an empty slice in the
//     Inventory means either "the cluster has none of these" or "we were never allowed to look". Only Meta
//     tells them apart. A fixture that means "I observed an empty list" says so in Meta.
//
// Note that internal/prom/portforward.go deliberately treats a nil readiness condition as ready, which is
// correct for choosing a pod to dial and wrong for any published figure — the two must not be harmonised.
func Observed(inv *Inventory, kind string) bool {
	if inv == nil {
		return false
	}
	for _, d := range inv.Meta.Denied {
		if d == kind || strings.HasPrefix(d, kind+":") {
			return false
		}
	}
	for _, c := range inv.Meta.Collected {
		if c == kind {
			return true
		}
	}
	return false
}

// pricingMethodologyNote documents pricing provenance: the cloud-specific
// list-price source, the as-of date, the applied discount, and the
// storage-excluded caveat. For cloud providers we now price (EKS/AKS/GKE) it
// names the source; for kind/onprem/unknown it says prices aren't modelled.
//
// pvPVCListed gates the storage clause: it asserts storage was "summed from
// PV/PVC capacity" ONLY when both lists actually succeeded. PV is cluster-scoped
// and frequently RBAC-denied; claiming a "summed" $0 off a denied list would be
// a denial-blind overclaim, so a denied list flips the note to an honest
// "could not be enumerated" instead.
func pricingMethodologyNote(provider string, discount float64, pvPVCListed bool, pp pricing.PriceProvider) string {
	// THE PROVIDER IS ASKED, not the package. This function called the package-level pricing.AsOf() four
	// times, so a report printed the embedded table's date and never its source — and would have kept
	// printing the embedded date with a bundle-backed provider injected. The seam existed
	// (PriceProvider.AsOf returns date AND source); nothing used it.
	//
	// A nil provider falls back to the embedded table rather than printing an empty date: a report is
	// assembled on paths that predate this parameter, and a blank "as of" would be worse than a correct
	// default.
	if pp == nil {
		pp = pricing.Embedded()
	}
	asOf, src := pp.AsOf()
	var b strings.Builder
	switch provider {
	case "eks":
		fmt.Fprintf(&b, "Pricing: AWS on-demand list (as of %s, %s)", asOf, src)
	case "aks":
		fmt.Fprintf(&b, "Pricing: Azure on-demand list (as of %s, %s); managed disks are priced as the TIER Azure "+
			"bills — the smallest published size that holds each claim (a 100 GiB Premium claim is a P10, 128 GiB) — "+
			"not per GiB requested", asOf, src)
	case "gke":
		fmt.Fprintf(&b, "Pricing: GCP on-demand list (as of %s, %s)", asOf, src)
	default:
		fmt.Fprintf(&b, "Pricing: on-demand list (as of %s, %s)", asOf, src)
	}
	if discount > 0 {
		fmt.Fprintf(&b, "; discount applied: %.0f%% to compute — node hours and compute-denominated savings; "+
			"storage, load balancers and control-plane fees stay at list, as no compute commitment covers them",
			discount*100)
	} else {
		b.WriteString("; no discount applied — confirm against your RI/Savings-Plan rates (a commitment covers " +
			"compute hours only; storage, load balancers and control-plane fees are list either way)")
	}
	switch provider {
	case "eks", "aks":
		if pvPVCListed {
			b.WriteString(". Persistent-volume storage summed from PV/PVC capacity at list per GB-month")
		} else {
			b.WriteString(". Persistent-volume storage NOT included — PV/PVC list was denied (PV is cluster-scoped, often RBAC-restricted), so storage could not be enumerated")
		}
	case "gke":
		b.WriteString(". GCP managed-disk storage not modelled — excluded from spend")
	default:
		// kind/onprem/unknown: no cloud price table applies.
		fmt.Fprintf(&b, ". Provider %q: instance prices not modelled — spend is compute-incomplete", provider)
	}
	return b.String()
}

// isCloudProvider reports whether the k8s provider tag is one of the managed
// clouds whose REGION coverage we can meaningfully check (EKS/AKS/GKE). kind/
// onprem/unknown have no cloud region semantics and their own "not modelled"
// note — they are never region-suppressed.
func isCloudProvider(provider string) bool {
	switch provider {
	case "eks", "aks", "gke":
		return true
	}
	return false
}

// regionUnpriced reports whether the cluster's spend headline must be suppressed
// because the provider is a recognized cloud but its region has NO node prices in
// the tables. This is the trigger for routing into the honest $0/unpriced state
// (and, in the run path, for the stderr warning). A non-cloud provider is never
// suppressed here.
func regionUnpriced(provider, region string, pp pricing.PriceProvider) bool {
	return isCloudProvider(provider) && !pp.RegionCovered(provider, region)
}

// uncoveredRegionNote is the Methodology line explaining a suppressed headline:
// the region isn't in the pricing tables, so the cost figure is unpriced (NOT
// $0). It names the gap so the reader sees an honest hole, not a silent zero.
func uncoveredRegionNote(provider, region string) string {
	return fmt.Sprintf(
		"Cost headline suppressed: no pricing table for %s/%s — node compute is UNPRICED (not $0). "+
			"Add the region to internal/pricing or footnote it before relying on cost figures.",
		provider, region)
}

func providerFrom(nodes []corev1.Node) string {
	if len(nodes) == 0 {
		return "unknown"
	}
	pid := nodes[0].Spec.ProviderID
	switch {
	case strings.HasPrefix(pid, "aws://"):
		return "eks"
	case strings.HasPrefix(pid, "gce://"):
		return "gke"
	case strings.HasPrefix(pid, "azure://"):
		return "aks"
	case strings.HasPrefix(pid, "kind://"):
		return "kind"
	case pid == "":
		return "unknown"
	}
	return "onprem"
}

func regionFrom(nodes []corev1.Node) string {
	for _, n := range nodes {
		if r := RegionOf(n); r != "" {
			return r
		}
	}
	return ""
}

// nodesHoldingPersistentData reports, per node name, whether persistent data is BOUND to it.
//
// WHY IT EXISTS. types.NodeRef.Stateful is read in four places in the node diagram — a distinct colour
// class, a group class, 50px of reserved name padding, and a 30×19 "DB" badge — and until 2026-09-10
// NOTHING SET IT, so all four had never rendered. Found by TestSchema_EveryFieldHasAProducer; the field's
// own comment had proposed this derivation ("StatefulSet presence or storage-class mounts") and never had
// code.
//
// TWO FACTS, BOTH READ STRAIGHT FROM A POD SPEC, NEITHER AN INFERENCE:
//
//   - a pod OWNED BY A STATEFULSET. StatefulSets own their pods directly — one hop, no intervening
//     ReplicaSet — so the owner reference is the whole test.
//   - a pod MOUNTING A PERSISTENT VOLUME CLAIM. A Deployment with a claim is stateful in the way that
//     matters here, and excluding it would mark a Postgres StatefulSet and miss the Postgres Deployment
//     beside it.
//
// AN emptyDir IS NOT PERSISTENT DATA. It dies with the pod, so a node hosting one loses nothing on
// eviction that the pod was not already going to lose — the same distinction M-56's Prometheus finding
// rests on.
//
// WHAT THE BADGE DOES NOT CLAIM: that the data is a database, that eviction loses it, or that the workload
// cannot tolerate a move. A PVC may be ReadWriteMany and a StatefulSet may be a cache. It marks where
// persistent data is bound, which is the fact a drain has to reckon with — and it is exactly the input
// internal/rules/node_drain.go already reasons about from the other direction.
func nodesHoldingPersistentData(pods []corev1.Pod) map[string]bool {
	out := map[string]bool{}
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" {
			continue // unscheduled: bound to nothing yet
		}
		if out[p.Spec.NodeName] {
			continue
		}
		for _, o := range p.OwnerReferences {
			if o.Kind == "StatefulSet" {
				out[p.Spec.NodeName] = true
				break
			}
		}
		if out[p.Spec.NodeName] {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				out[p.Spec.NodeName] = true
				break
			}
		}
	}
	return out
}

func buildArchitecture(inv *Inventory, findings []types.Finding, region, provider string, pp pricing.PriceProvider) *types.Architecture {
	// Tier defaults to declared: a no-Prometheus run is correctly Tier-3 at
	// assembly time. The pipeline calls collect.ApplyObservedGraph to upgrade it
	// to observed when a mesh/CNI telemetry source was reachable.
	arch := &types.Architecture{Tier: types.TierDeclared}

	// AZs from zone labels; node's dominant tenant = namespace with most of
	// its pods (system namespaces excluded so app tenants win the stripe).
	domByNode := dominantTenants(inv.Pods)
	statefulNodes := nodesHoldingPersistentData(inv.Pods)
	azNodes := map[string][]types.NodeRef{}
	for _, n := range inv.Nodes {
		// ZoneOf, not a raw label read: a cluster carrying only the beta key used to land in "unzoned" here,
		// which is an absence rendered as a fact. See zonelabels.go.
		zone := ZoneOf(n)
		if zone == "" {
			zone = "unzoned"
		}
		azNodes[zone] = append(azNodes[zone], types.NodeRef{
			Name:      n.Name,
			Type:      n.Labels["node.kubernetes.io/instance-type"],
			Namespace: domByNode[n.Name],
			Stateful:  statefulNodes[n.Name],
			Capacity:  ClassifyCapacityType(provider, n),
		})
	}
	zones := make([]string, 0, len(azNodes))
	for z := range azNodes {
		zones = append(zones, z)
	}
	sort.Strings(zones)
	for _, z := range zones {
		arch.AZs = append(arch.AZs, types.AZ{Name: z, Nodes: azNodes[z]})
	}

	// Node pools grouped by instance type + capacity type. Re-keying on capacity
	// (instead of instance-type alone) SPLITS a mixed on-demand/spot pool of the
	// same instance type into two pools so each is labelled correctly. CostMo is
	// the on-demand list price for (provider, region, type); a spot pool keeps
	// that same number relabelled as an UPPER BOUND (CostSourceSpotCeiling) — no
	// fabricated multiplier, no lower spot rate (it is unreadable from labels).
	// When unpriced (unknown type or a region the table doesn't cover) CostMo
	// stays 0 and the type is recorded in UnpricedNodeTypes so spend is honestly
	// undercounted rather than silently wrong.
	type poolKey struct {
		itype    string
		capacity types.CapacityType
	}
	poolCount := map[poolKey]int{}
	// poolSpec records the machine shape the kubelet actually reports for the pool's first node.
	// Derived from Status.Capacity rather than from the instance-type table on purpose: it is the
	// truth about this machine, so it stays right for a shape the pricing table has never heard of,
	// and it cannot drift from the table's idea of the same type. Empty when the node reports no
	// capacity — no claim rather than a guessed one.
	poolSpec := map[poolKey]string{}
	for _, n := range inv.Nodes {
		k := poolKey{itype: n.Labels["node.kubernetes.io/instance-type"], capacity: ClassifyCapacityType(provider, n)}
		poolCount[k]++
		if _, seen := poolSpec[k]; !seen {
			poolSpec[k] = nodeShape(n)
		}
	}
	keys := make([]poolKey, 0, len(poolCount))
	for k := range poolCount {
		keys = append(keys, k)
	}
	// Deterministic order: by instance type, then capacity.
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].itype != keys[j].itype {
			return keys[i].itype < keys[j].itype
		}
		return keys[i].capacity < keys[j].capacity
	})
	var unpriced []string
	seenUnpriced := map[string]bool{}
	for _, k := range keys {
		name := k.itype
		if name == "" {
			name = "unknown"
		}
		pool := types.NodePoolSummary{Type: name, Spec: poolSpec[k], Count: poolCount[k], Capacity: k.capacity}
		// Per-capacity counts on the (already capacity-homogeneous) pool, so a
		// reader sees the split is real and machine-readable.
		switch k.capacity {
		case types.CapacitySpot:
			pool.SpotCount = poolCount[k]
		case types.CapacityOnDemand:
			pool.OnDemandCount = poolCount[k]
		case types.CapacityUnknown:
			pool.UnknownCapCount = poolCount[k]
		}
		// CostSource provenance: spot pools are an upper bound; everything else is
		// the plain on-demand list estimate. Never "billed" here (Layer 2 only).
		if k.capacity == types.CapacitySpot {
			pool.CostSource = types.CostSourceSpotCeiling
		} else {
			pool.CostSource = types.CostSourceListEstimate
		}
		if pt, ok := pp.NodeMonthly(provider, region, k.itype, k.capacity); ok {
			cost := pt.Ceiling
			pool.CostMo = cost
		} else {
			// THE POOL SAYS SO, not only the report-level list. CostSource is stamped above, before this
			// lookup, so this branch used to leave "list-estimate" on a pool nobody could price — the same
			// string a priced pool carries. Every consumer then had to cross-reference
			// Architecture.UnpricedNodeTypes to tell them apart, and the instrument's island never carried
			// that list, so it printed $0 and called it a list estimate.
			pool.CostSource = types.CostSourceUnpriced
			if !seenUnpriced[name] {
				seenUnpriced[name] = true
				unpriced = append(unpriced, name)
			}
		}
		arch.NodePools = append(arch.NodePools, pool)
	}
	arch.UnpricedNodeTypes = unpriced

	// Namespace summaries with per-namespace finding counts.
	findingsByNs := map[string]int{}
	for _, f := range findings {
		seen := map[string]bool{}
		for _, r := range f.AffectedResources {
			if r.Namespace != "" && !seen[r.Namespace] {
				findingsByNs[r.Namespace]++
				seen[r.Namespace] = true
			}
		}
	}
	wlByNs := map[string][]string{}
	for _, d := range inv.Deployments {
		wlByNs[d.Namespace] = append(wlByNs[d.Namespace], "deploy")
	}
	for _, s := range inv.StatefulSets {
		wlByNs[s.Namespace] = append(wlByNs[s.Namespace], "sts")
	}
	for _, d := range inv.DaemonSets {
		wlByNs[d.Namespace] = append(wlByNs[d.Namespace], "ds")
	}
	for _, ns := range inv.Namespaces {
		counts := map[string]int{}
		for _, k := range wlByNs[ns.Name] {
			counts[k]++
		}
		parts := make([]string, 0, 3)
		for _, k := range []string{"deploy", "sts", "ds"} {
			if counts[k] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
			}
		}
		wl := strings.Join(parts, " · ")
		if wl == "" {
			wl = "no workloads"
		}
		arch.Namespaces = append(arch.Namespaces, types.NamespaceSummary{
			Name:         ns.Name,
			Workloads:    wl,
			FindingCount: findingsByNs[ns.Name],
		})
	}
	arch.Stack = detectStack(inv)
	arch.Topologies = buildTopologies(inv, findings)
	arch.Flows = buildFlows(inv, findings)
	arch.RBAC = buildRBACGraph(inv, findings)
	return arch
}

// dominantTenants maps node name → the non-system namespace owning the most
// pods on that node.
func dominantTenants(pods []corev1.Pod) map[string]string {
	counts := map[string]map[string]int{}
	for _, p := range pods {
		if p.Spec.NodeName == "" || isSystemNamespace(p.Namespace) {
			continue
		}
		if counts[p.Spec.NodeName] == nil {
			counts[p.Spec.NodeName] = map[string]int{}
		}
		counts[p.Spec.NodeName][p.Namespace]++
	}
	out := map[string]string{}
	for node, byNs := range counts {
		best, bestN := "", -1
		for ns, n := range byNs {
			if n > bestN || (n == bestN && ns < best) {
				best, bestN = ns, n
			}
		}
		out[node] = best
	}
	return out
}

// isSystemNamespace gates rule evaluation and tenant attribution.
func isSystemNamespace(ns string) bool { return types.IsSystemNamespace(ns) }

// nodeShape renders a node's reported machine shape as "4 vCPU · 16 GiB", or "" when the kubelet
// reports no capacity.
//
// It reads Capacity rather than Allocatable deliberately: "spec" means the machine you are paying
// for, while allocatable is what is left after kube/system reservations. Quoting allocatable next to
// a per-node list price would silently compare two different things.
//
// Memory is shown in binary GiB because that is what Kubernetes quantities express, and rounded to
// one decimal only when it is not whole, so an ordinary 16GiB node reads "16 GiB" rather than
// "16.0 GiB".
func nodeShape(n corev1.Node) string {
	cpuQ, hasCPU := n.Status.Capacity[corev1.ResourceCPU]
	memQ, hasMem := n.Status.Capacity[corev1.ResourceMemory]
	if !hasCPU && !hasMem {
		return ""
	}
	var parts []string
	if hasCPU {
		if milli := cpuQ.MilliValue(); milli%1000 == 0 {
			parts = append(parts, fmt.Sprintf("%d vCPU", milli/1000))
		} else {
			parts = append(parts, fmt.Sprintf("%.1f vCPU", float64(milli)/1000))
		}
	}
	if hasMem {
		gib := float64(memQ.Value()) / (1 << 30)
		if gib == math.Trunc(gib) {
			parts = append(parts, fmt.Sprintf("%d GiB", int64(gib)))
		} else {
			parts = append(parts, fmt.Sprintf("%.1f GiB", gib))
		}
	}
	return strings.Join(parts, " · ")
}

// deniedKindNames reduces Meta.Denied entries ("<kind>: <api error>") to kind names.
//
// The error text is deliberately dropped. It belongs in the human-readable DataSources sentence: it
// varies between runs for the same denial, so a guard comparing two runs would see spurious
// differences, and it repeats whatever the API server chose to say about the operator's permissions.
func deniedKindNames(denied []string) []string {
	if len(denied) == 0 {
		return nil
	}
	out := make([]string, 0, len(denied))
	seen := map[string]bool{}
	for _, d := range denied {
		// The collector writes a denial as fmt.Sprintf("%s: %v", kind, err), so the separator is a
		// colon FOLLOWED BY A SPACE. Splitting on the first bare colon truncated every
		// custom-resource step — "cr:certificates.cert-manager.io: forbidden" became "cr" — which
		// collapsed three distinct denials into three identical entries and, worse, meant an
		// analyzer's declared dependency on "cr:certificates.cert-manager.io" could never match the
		// denial of that same list. A kind name never contains ": ", so this split is exact.
		if i := strings.Index(d, ": "); i > 0 {
			d = d[:i]
		}
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// clusterUID returns the kube-system Namespace UID, the conventional stable identity of a cluster.
//
// It is read from an object already collected, so this costs no API call and no new permission. A kube
// context name is not usable for the purpose: it can be renamed, or reused for a rebuilt cluster, and
// keying two readings on it would silently compare different clusters. Empty when kube-system was not
// collected, and an empty identity must prevent a comparison rather than be guessed around.
func clusterUID(inv *Inventory) string {
	for _, ns := range inv.Namespaces {
		if ns.Name == "kube-system" {
			return string(ns.UID)
		}
	}
	return ""
}

// deniedSourceNote explains which lists did not succeed, and why, WITHOUT carrying the API's own error text
// into the report.
//
// It used to join inv.Meta.Denied verbatim under the words "access denied for". That text publishes two things
// this document must not: the API server URL and port when the cluster is unreachable, and the authenticated
// identity on a permission failure ("User \"system:serviceaccount:...\""). Neither is an identifier the
// redactor gathers, so both survived --redact — in the very section that exists to state the report's limits.
//
// It also called every cause "access denied", so a refused TCP connection was reported as a permissions
// problem, in a document whose own session trace would say zero requests were refused. The cause is now
// classified, and the raw text stays where it belongs: the local run log.
// unreadPairs classifies every failed list into (kind, cause) pairs, de-duplicated, in the collector's own
// order. Same classification the note uses — one call each, no second opinion.
func unreadPairs(denied []string) []types.UnreadKind {
	if len(denied) == 0 {
		return nil
	}
	out := make([]types.UnreadKind, 0, len(denied))
	seen := map[string]bool{}
	for _, d := range denied {
		kind, cause := kindAndCause(d)
		if kind == "" || seen[kind] {
			continue
		}
		seen[kind] = true
		out = append(out, types.UnreadKind{Kind: kind, Cause: cause})
	}
	return out
}

func deniedSourceNote(denied []string) string {
	// The sentence is formatted by types.UnreadNote, which is also the only thing that parses it back —
	// Methodology.UnreadKinds. A format written here and read in a renderer drifts, and this one is the only
	// place a cause survives into a saved reading.
	kinds := make([]types.UnreadKind, 0, len(denied))
	seen := map[string]bool{}
	for _, d := range denied {
		kind, cause := kindAndCause(d)
		key := kind + "|" + cause
		if kind == "" || seen[key] {
			continue
		}
		seen[key] = true
		kinds = append(kinds, types.UnreadKind{Kind: kind, Cause: cause})
	}
	return types.UnreadNote(kinds)
}

// ClassifyCause turns an error message into a cause the report may print, without carrying the message itself.
// Exported so the fleet loop classifies a per-cluster failure the same way a per-kind denial is classified —
// one classifier, so the two can never describe the same network failure differently.
func ClassifyCause(errText string) string {
	_, cause := kindAndCause("x: " + errText)
	return cause
}

// kindAndCause splits a "<kind>: <error>" entry and classifies the error into a cause the report may print. The
// split is on colon-SPACE because a custom-resource step name contains a bare colon (cr:<resource>.<group>).
func kindAndCause(entry string) (string, string) {
	kind, errText := entry, ""
	if i := strings.Index(entry, ": "); i > 0 {
		kind, errText = entry[:i], entry[i+2:]
	}
	return kind, CauseOf(errText)
}

// CauseOf classifies why one list did not come back, from the error text alone, into one of six causes.
//
// EXPORTED BECAUSE EVERY SURFACE NEEDS IT, which is the whole point. This classification existed here from
// the start and stayed here: the report's cover said "Grant the read-only role", the evidence pack said
// "Refused by the API server", and the live terminal frame said "denied by RBAC" — three permission claims
// over a run whose cluster was simply unreachable. Collect holds the error, so Collect answers the question,
// once, and the surfaces say what it answered.
//
// The returned strings are the words the surfaces print. They are deliberately not an enum: there is no
// behaviour keyed on them, and a caller that wants to branch should ask a narrower question.
//
// It never returns the error text. That text carries the API server's host and port on a network failure and
// the authenticated identity on a permission failure, and neither is an identifier --redact would catch.
func CauseOf(errText string) string {
	low := strings.ToLower(errText)
	switch {
	// A LIST THAT READ PAGES AND THEN FAILED, before whatever failed it: the pages it read were dropped, and
	// "timed out" or "could not be read" over a list that answered thirty pages would describe a different event.
	case strings.Contains(low, "list cut short"):
		return "cut short"
	// A server that kept answering 429 after every retry asked this reading to slow down; that is not a refusal and
	// not an unreachable cluster.
	case strings.Contains(low, "too many requests") || strings.Contains(low, "has asked us to try again later"):
		return "throttled"
	// THE CREDENTIAL ITSELF, BEFORE ANY PERMISSION. A 401 is not a 403: the server did not decide what this
	// identity may do, it did not accept the identity. client-go words it two ways — "Unauthorized" on a list, and
	// "the server has asked for the client to provide credentials" on discovery and the version — and the second
	// matched no branch, so an expired token's run read "28 lists could not be read". A credential plugin that
	// failed, and a certificate the client would not trust, are the same class: nothing about the cluster was
	// learned, and there is one thing to do about each.
	case strings.Contains(low, "provide credentials") || strings.Contains(low, "unauthorized"):
		return "credentials not accepted"
	case strings.Contains(low, "getting credentials") || strings.Contains(low, "exec plugin") ||
		strings.Contains(low, "exec: executable"):
		return "credentials could not be obtained"
	case strings.Contains(low, "x509:") || strings.Contains(low, "failed to verify certificate"):
		return "certificate not accepted"
	case strings.Contains(low, "forbidden"):
		return "not permitted"
	case strings.Contains(low, "could not find the requested resource") || strings.Contains(low, "no matches for kind"):
		return "not served by this cluster"
	// The network branch comes FIRST, and the timeout branch matches phrases rather than the bare word.
	// client-go puts ?timeout=32s in every request URL, and the URL is inside the error text, so a substring
	// test for "timeout" classified every unreachable cluster as a timeout. The test caught it.
	case strings.Contains(low, "connection refused") || strings.Contains(low, "no such host") ||
		strings.Contains(low, "dial tcp") || strings.Contains(low, "connection reset") ||
		strings.Contains(low, "eof") || strings.Contains(low, "tls handshake"):
		return "not reachable"
	case strings.Contains(low, "deadline exceeded") || strings.Contains(low, "client.timeout exceeded") ||
		strings.Contains(low, "i/o timeout") || strings.Contains(low, "timed out"):
		return "timed out"
	case errText == "":
		return "cause not recorded"
	default:
		return "could not be read"
	}
}

// readingStamp is when the reading was taken, in UTC and to the second.
//
// UTC, AND TO THE SECOND, for the reason the field has always had: `time.Now()` keeps the operator's zone,
// and a redacted reading — cluster, namespaces and workloads all replaced by tokens — then printed
// "2026-09-11 02:28 EEST" on every section of the document it was built to let somebody share. The
// microseconds were the second half: a stamp precise enough to tie two supposedly independent documents to
// one installation and one run. See TestRender_StatesTheMomentInUTCWhateverZoneTheReadingCarries.
//
// The fallback is now, matching readingTime in internal/rules and internal/analyzers: an inventory built by
// hand has no clock, and two packages disagreeing about what "no clock" means would be worse than the
// fallback itself.
func readingStamp(inv *Inventory) time.Time {
	if inv != nil && !inv.Meta.StartedAt.IsZero() {
		return inv.Meta.StartedAt.UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

// readVolume is the volume Collect measured before it dropped environment values, or — for an inventory that did
// not come through Collect (a capture, a test) — what this inventory holds.
func readVolume(inv *Inventory) *types.ReadVolume {
	if inv.volume != nil {
		return inv.volume
	}
	return volumeOf(inv)
}
