package rules

// rotation.go — GROUND TRUTH: what this cluster's own controllers have published, right now.
//
// The three rules here read `discovery.k8s.io/EndpointSlice` objects and report what the
// EndpointSlice controller wrote. That is the load-bearing distinction of the whole pillar: an
// entry means "a controller published this pod as a backend of this Service", never "this pod
// matches a selector" and never "a request reached it". The market reads intent. These read what
// was published.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THESE RULES DELIBERATELY DO NOT SAY, AND WHY
//
// The tempting version says "checkout is receiving no traffic and your users are seeing errors".
// Not one word of that is in the snapshot, and each refusal was argued separately:
//
//	No "no traffic", no "users affected", no "the service is down", no "outage". A published entry
//	is not a request and an absent entry is not an outage. We have no request data of any kind: a
//	Service with zero ready addresses may be a batch endpoint nobody calls, the idle half of a
//	blue/green pair, or a Service whose consumers were retired last year. All three read identically.
//
//	The verb is "published" or "registered", never "serving", "receiving" or "in rotation". Note
//	that "rotation" is already in bannedDrainPhrases — this file's NAME uses the word and its
//	OUTPUT must not, which rotation_test.go enforces.
//
//	No "misconfigured" for a pod that matches a selector and is not published. It may be mid-rollout,
//	may have failed a readiness gate a moment ago, or may sit behind a publishNotReadyAddresses
//	interaction. The supportable statement is the arithmetic: this pod is Ready, it carries the
//	labels in that selector, and no slice for that Service lists it.
//
//	No "single point of failure" for the one-node case. That is an outcome claim about failure
//	domains we cannot see. The provable statement is placement: all N ready addresses name node X.
//
//	No durations of anything that happens, and no dollars. The two windows these rules DO print —
//	the Service grace and the pod readiness gate — are windows on the READING, not claims about how
//	long anything takes, and both are printed in the finding because a window without its length is
//	an unbounded claim.
//
//	NODENAME IS NOT USED TO PLACE A POD. node_drain.go:795 refuses the same field for the same
//	reason: it has no referential integrity, is a batched copy that can disagree with the pod list
//	read in the same audit, and is absent on manually written slices. Rule 2 reports the field's own
//	content as published, says so in the same breath, and falls silent entirely when any ready entry
//	is missing it — rather than making a placement claim about the subset that happens to carry it.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// FOUR SERVICE SHAPES WE CANNOT JUDGE, AND THE COVERAGE LINE THAT SAYS SO
//
// A selectorless Service has its endpoints written by something outside the cluster — a human, an
// operator, a controller we cannot see — so we cannot judge it in EITHER direction. An ExternalName
// Service resolves by DNS and has no endpoints by design. A headless Service publishes per-pod DNS
// records, so "zero ready" is a real state with a different consumer contract. And a slice written
// by a controller other than endpointslice-controller.k8s.io does not owe us the upstream
// semantics this arithmetic assumes.
//
// Skipping those silently would make the report's coverage look total. So every finding carries a
// coverage line naming how many Services were judged and why each of the others was not. The line
// is part of the finding, not a footnote.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

const (
	// managedByLabel names the controller that wrote a slice; upstreamSliceController is the only
	// value whose semantics this arithmetic assumes.
	managedByLabel          = "endpointslice.kubernetes.io/managed-by"
	upstreamSliceController = "endpointslice-controller.k8s.io"

	// rotationServiceGrace excludes Services younger than this from the published-count rules. The
	// EndpointSlice controller writes asynchronously, so a Service created seconds before the
	// reading legitimately has nothing published yet, and reporting that would be reporting our own
	// timing. Printed in the coverage line.
	rotationServiceGrace = 5 * time.Minute

	// rotationReadyGrace is how long a pod must have been Ready before its absence from a slice is
	// worth stating. Any rollout produces pods that match a selector before the controller catches
	// up, so without this gate rule 3 fires transiently on every healthy deploy. Printed in the
	// finding.
	rotationReadyGrace = 60 * time.Second
)

// readingTime is when this snapshot was taken. Every window in this file is measured against it
// rather than against wall-clock now, so a finding says the same thing when a stored inventory is
// re-evaluated. Falls back to now for a caller that built an Inventory by hand (tests, fixtures) —
// the same fallback idle_loadbalancer.go:85 uses.
func readingTime(inv *collect.Inventory) time.Time {
	if inv != nil && !inv.Meta.StartedAt.IsZero() {
		return inv.Meta.StartedAt
	}
	return time.Now()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Service shape and coverage
// ─────────────────────────────────────────────────────────────────────────────────────────────

// svcShape records every reason a Service might not be judgeable. It is a set of independent facts
// rather than one classification because the rules disagree about which of them disqualify: a
// headless Service is excluded from the published-count rules and is eligible for rule 3.
type svcShape struct {
	externalName bool
	selectorless bool
	headless     bool
	foreign      bool // its slices are written by another controller
	tooNew       bool
}

func shapeOf(svc *corev1.Service, pub publishedEndpoints, reading time.Time) svcShape {
	s := svcShape{
		externalName: svc.Spec.Type == corev1.ServiceTypeExternalName,
		headless:     svc.Spec.ClusterIP == corev1.ClusterIPNone,
		foreign:      pub.foreign,
	}
	s.selectorless = !s.externalName && len(svc.Spec.Selector) == 0
	if !svc.CreationTimestamp.IsZero() && reading.Sub(svc.CreationTimestamp.Time) < rotationServiceGrace {
		s.tooNew = true
	}
	return s
}

// The exclusion reasons, spelled once. Each says what the shape is AND why the reading means
// something different for it, because a violation should teach rather than merely forbid.
var (
	reasonExternalName = "ExternalName (resolves by DNS and has no endpoints by design)"
	reasonSelectorless = "selectorless (endpoints are written by something outside this cluster, so they cannot be judged in either direction)"
	reasonHeadless     = "headless (publishes per-pod DNS records — a different consumer contract)"
	reasonForeign      = "EndpointSlices written by another controller (this arithmetic assumes the upstream controller's semantics)"
	reasonTooNew       = fmt.Sprintf("created less than %s before this reading", rotationServiceGrace)
	reasonNoNodeName   = "at least one published ready entry carries no nodeName, so placement cannot be read"
)

// reasonOrder fixes the coverage line's order so the sentence is stable across runs and its diff
// between two audits is readable.
var reasonOrder = []string{
	reasonExternalName, reasonSelectorless, reasonHeadless, reasonForeign, reasonTooNew, reasonNoNodeName,
}

type rotationCoverage struct {
	total   int
	judged  int
	skipped map[string]int
}

func newCoverage() *rotationCoverage { return &rotationCoverage{skipped: map[string]int{}} }

func (c *rotationCoverage) judge()              { c.total++; c.judged++ }
func (c *rotationCoverage) skip(reason string)  { c.total++; c.skipped[reason]++ }
func (c *rotationCoverage) skipJudged(r string) { c.judged--; c.skipped[r]++ }

// line renders the coverage sentence carried by every finding this rule emits.
func (c *rotationCoverage) line() string {
	var parts []string
	for _, r := range reasonOrder {
		if n := c.skipped[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, r))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("coverage: judged all %s in this reading", nWord(c.total, "Service", "Services"))
	}
	return fmt.Sprintf("coverage: judged %d of %s in this reading; not judged: %s",
		c.judged, nWord(c.total, "Service", "Services"), strings.Join(parts, ", "))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// What a Service publishes
// ─────────────────────────────────────────────────────────────────────────────────────────────

// publishedEndpoints is a count over EndpointSlice entries, and nothing else. Every field is
// arithmetic over objects this audit listed; none of it is request data.
type publishedEndpoints struct {
	family           string // the ONE address family the counts cover, named in evidence
	families         int    // how many families this Service publishes
	slices           int    // slices carrying this Service's name label
	total            int    // deduped entries in `family`
	ready            int    // conditions.ready == true
	readyFalse       int    // conditions.ready == false
	readyUnset       int    // conditions.ready == nil — the API calls this UNKNOWN, never true
	terminating      int
	readyByNode      map[string]int
	readyMissingNode int
	foreign          bool
	publishNotReady  bool
	// published holds every targetRef UID across EVERY family, because "appears in no slice" is a
	// question about the Service as a whole: a pod listed only in the IPv6 slice IS published.
	published map[apitypes.UID]bool
}

// publishedFor tallies one Service's slices.
//
// Deliberate choices, each guarding a way this could lie:
//   - counts cover ONE address family and are never summed across families. A dual-stack Service
//     publishes an IPv4 and an IPv6 slice for the same backends, so summing doubles every figure.
//     IPv4 wins when present, otherwise the lexicographically first family, so the choice is
//     deterministic rather than dependent on list order.
//   - entries are deduped by targetRef UID (falling back to the address list for a manually written
//     slice that carries no targetRef), because the same pod legitimately appears more than once.
//   - conditions.ready == nil is its own bucket. The API defines unset as unknown, and
//     internal/prom/portforward.go deliberately treats nil as ready — correct for picking a
//     port-forward target, wrong as the basis of a published figure. The two must not be harmonised.
func publishedFor(inv *collect.Inventory, svc *corev1.Service) publishedEndpoints {
	p := publishedEndpoints{
		readyByNode: map[string]int{},
		published:   map[apitypes.UID]bool{},
	}
	families := map[string]bool{}
	for i := range inv.EndpointSlices {
		s := &inv.EndpointSlices[i]
		if s.Namespace != svc.Namespace || s.Labels[discoveryv1.LabelServiceName] != svc.Name {
			continue
		}
		p.slices++
		families[string(s.AddressType)] = true
		if mgr := s.Labels[managedByLabel]; mgr != "" && mgr != upstreamSliceController {
			p.foreign = true
		}
		for _, ep := range s.Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.TargetRef.UID != "" {
				p.published[ep.TargetRef.UID] = true
			}
		}
	}
	p.families = len(families)
	p.family = pickAddressFamily(families)
	p.publishNotReady = svc.Spec.PublishNotReadyAddresses

	if p.family == "" {
		return p
	}
	seen := map[string]bool{}
	for i := range inv.EndpointSlices {
		s := &inv.EndpointSlices[i]
		if s.Namespace != svc.Namespace || s.Labels[discoveryv1.LabelServiceName] != svc.Name {
			continue
		}
		if string(s.AddressType) != p.family {
			continue
		}
		for _, ep := range s.Endpoints {
			key := endpointDedupKey(ep)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			p.total++
			switch {
			case ep.Conditions.Ready == nil:
				p.readyUnset++
			case *ep.Conditions.Ready:
				p.ready++
				if ep.NodeName != nil && *ep.NodeName != "" {
					p.readyByNode[*ep.NodeName]++
				} else {
					p.readyMissingNode++
				}
			default:
				p.readyFalse++
			}
			if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
				p.terminating++
			}
		}
	}
	return p
}

// pickAddressFamily prefers IPv4 so the figure is stable on dual-stack clusters, and falls back to
// the first family in sorted order so a v6-only or FQDN Service still gets a deterministic answer.
func pickAddressFamily(families map[string]bool) string {
	if families[string(discoveryv1.AddressTypeIPv4)] {
		return string(discoveryv1.AddressTypeIPv4)
	}
	names := make([]string, 0, len(families))
	for f := range families {
		names = append(names, f)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func endpointDedupKey(ep discoveryv1.Endpoint) string {
	if ep.TargetRef != nil && ep.TargetRef.UID != "" {
		return "uid:" + string(ep.TargetRef.UID)
	}
	if len(ep.Addresses) > 0 {
		return "addr:" + strings.Join(ep.Addresses, ",")
	}
	return ""
}

// sortedServices returns index order by namespace then name, so findings appear in the same order
// on every run regardless of what order the API server listed them in.
func sortedServices(inv *collect.Inventory) []int {
	idx := make([]int, 0, len(inv.Services))
	for i := range inv.Services {
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := &inv.Services[idx[a]], &inv.Services[idx[b]]
		if x.Namespace != y.Namespace {
			return x.Namespace < y.Namespace
		}
		return x.Name < y.Name
	})
	return idx
}

// rotationGuard is the shared denial guard. All three rules reason about ABSENCE — no ready entry,
// no slice entry — so an unlisted EndpointSlice or Service list must silence them rather than be
// read as an empty cluster.
func rotationGuard(inv *collect.Inventory) bool {
	return observed(inv, "endpointslices") && observed(inv, "services")
}

// familyNote is appended whenever a Service publishes more than one address family, so a reader
// knows the count covers one of them by design.
func familyNote(p publishedEndpoints) string {
	if p.families < 2 {
		return ""
	}
	return fmt.Sprintf(" (this Service publishes %d address families; counts cover %s only and are never summed across families)",
		p.families, p.family)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 1 — a Service that publishes no ready address
// ─────────────────────────────────────────────────────────────────────────────────────────────

type ServiceNoReadyEndpoints struct{}

func (ServiceNoReadyEndpoints) ID() string      { return "k8s.reliability.service-no-ready-endpoints" }
func (ServiceNoReadyEndpoints) Version() string { return "1.0.0" }

// RequiredKinds — the EndpointSlice list IS the claim, and without it "zero ready" cannot be told
// apart from "not read", which is the absence-versus-denial trap this declaration exists for. The
// Service list is what the rule iterates. `nodes` is deliberately omitted: this rule never reads a
// Node object, and a run without the node list makes exactly the same claim about exactly the same
// Services — declaring it would make the report say the rule was not evaluated when it was.
// `pods` is deliberately omitted for the same reason: rule 3 reads pods, this one does not.
// See deps.go for what belongs in this list.
func (ServiceNoReadyEndpoints) RequiredKinds() []string {
	return sortedKinds([]string{"endpointslices", "services"})
}

func (r ServiceNoReadyEndpoints) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !rotationGuard(inv) {
		return nil
	}
	reading := readingTime(inv)
	cov := newCoverage()
	type hit struct {
		svc *corev1.Service
		pub publishedEndpoints
	}
	var hits []hit

	for _, i := range sortedServices(inv) {
		svc := &inv.Services[i]
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		pub := publishedFor(inv, svc)
		shape := shapeOf(svc, pub, reading)
		switch {
		case shape.externalName:
			cov.skip(reasonExternalName)
			continue
		case shape.selectorless:
			cov.skip(reasonSelectorless)
			continue
		case shape.headless:
			cov.skip(reasonHeadless)
			continue
		case shape.foreign:
			cov.skip(reasonForeign)
			continue
		case shape.tooNew:
			cov.skip(reasonTooNew)
			continue
		}
		cov.judge()
		if pub.ready == 0 {
			hits = append(hits, hit{svc: svc, pub: pub})
		}
	}

	coverage := cov.line()
	out := make([]types.Finding, 0, len(hits))
	for _, h := range hits {
		svc, pub := h.svc, h.pub
		evidence := []string{}
		if pub.slices == 0 {
			evidence = append(evidence, fmt.Sprintf(
				"no EndpointSlice carrying the label %s=%s was listed in namespace %s",
				discoveryv1.LabelServiceName, svc.Name, svc.Namespace))
		} else {
			evidence = append(evidence, fmt.Sprintf(
				"Service %s/%s: %s publish %s in the %s family, 0 with conditions.ready=true "+
					"(%d ready=false, %d with ready unset — the API defines unset as unknown, never as true)%s",
				svc.Namespace, svc.Name, nWord(pub.slices, "slice", "slices"), nWord(pub.total, "address", "addresses"), pub.family,
				pub.readyFalse, pub.readyUnset, familyNote(pub)))
		}
		if pub.terminating > 0 {
			evidence = append(evidence, fmt.Sprintf(
				"%d of the published entries carry conditions.terminating=true", pub.terminating))
		}
		if pub.publishNotReady {
			evidence = append(evidence, "spec.publishNotReadyAddresses=true: this Service asks the controller "+
				"to publish addresses regardless of readiness, so the published total above includes addresses "+
				"the controller does not consider ready")
		}
		evidence = append(evidence, coverage)

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", svc.Namespace, svc.Name),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("No ready address is published for %s/%s", svc.Namespace, svc.Name),
			Description: fmt.Sprintf(
				"Every EndpointSlice listed for Service %s/%s publishes zero entries with conditions.ready=true. "+
					"An entry records that a controller published an address as a backend of this Service, so this "+
					"is a count of what was published and says nothing about what any request did. Whether the count "+
					"is expected depends on what this Service is for, which the snapshot does not record: a batch "+
					"endpoint nobody calls, the idle half of a blue/green pair, and a Service whose consumers were "+
					"retired all read exactly the same way.",
				svc.Namespace, svc.Name),
			WhyItMatters: "Only the cluster's own controllers can report the published set, and a zero there is " +
				"invisible to a deployment that reported success — this is the reading worth confirming against " +
				"what the Service is meant to do.",
			Evidence:          evidence,
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}},
			EstimatedEffort:   types.EffortLow,
			// Confidence is problem-certainty, not read-certainty: the count is exact, and whether a
			// zero is a problem here is exactly what the snapshot cannot settle.
			Confidence: 0.6,
			Provenance: provenance(),
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 2 — every ready address names one node
// ─────────────────────────────────────────────────────────────────────────────────────────────

type ServiceEndpointsOneNode struct{}

func (ServiceEndpointsOneNode) ID() string      { return "k8s.reliability.service-endpoints-one-node" }
func (ServiceEndpointsOneNode) Version() string { return "1.0.0" }

// RequiredKinds — same two lists as rule 1, for the same reasons. `nodes` is deliberately omitted:
// this rule reports the node NAME the controller wrote onto the endpoint and never resolves it
// against the Node list, so a run without nodes makes the identical claim.
// See deps.go for what belongs in this list.
func (ServiceEndpointsOneNode) RequiredKinds() []string {
	return sortedKinds([]string{"endpointslices", "services"})
}

func (r ServiceEndpointsOneNode) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !rotationGuard(inv) {
		return nil
	}
	reading := readingTime(inv)
	cov := newCoverage()
	type hit struct {
		svc  *corev1.Service
		pub  publishedEndpoints
		node string
	}
	var hits []hit

	for _, i := range sortedServices(inv) {
		svc := &inv.Services[i]
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		pub := publishedFor(inv, svc)
		shape := shapeOf(svc, pub, reading)
		switch {
		case shape.externalName:
			cov.skip(reasonExternalName)
			continue
		case shape.selectorless:
			cov.skip(reasonSelectorless)
			continue
		case shape.foreign:
			cov.skip(reasonForeign)
			continue
		case shape.tooNew:
			cov.skip(reasonTooNew)
			continue
		}
		// Headless Services ARE judged here: per-pod DNS records still resolve to addresses the
		// controller placed, and "all of them name one node" is the same placement reading.
		cov.judge()

		// A ready entry with no nodeName makes the placement unreadable for the whole Service. Say
		// so in the coverage line rather than claiming placement over the subset that has it.
		if pub.readyMissingNode > 0 {
			cov.skipJudged(reasonNoNodeName)
			continue
		}
		if pub.ready < 2 || len(pub.readyByNode) != 1 {
			continue
		}
		node := ""
		for n := range pub.readyByNode {
			node = n
		}
		hits = append(hits, hit{svc: svc, pub: pub, node: node})
	}

	coverage := cov.line()
	out := make([]types.Finding, 0, len(hits))
	for _, h := range hits {
		svc, pub := h.svc, h.pub
		evidence := []string{
			fmt.Sprintf("Service %s/%s: all %s in the %s family name node %s%s",
				svc.Namespace, svc.Name, nWord(pub.ready, "ready address", "ready addresses"), pub.family, h.node, familyNote(pub)),
			"nodeName on an EndpointSlice entry is the controller's own copy of the pod's node: it is written " +
				"in batches, has no referential integrity, and is absent on manually written slices. It is " +
				"reported here as published, not resolved against the Node list.",
			coverage,
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", svc.Namespace, svc.Name),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Every ready address for %s/%s names one node", svc.Namespace, svc.Name),
			Description: fmt.Sprintf(
				"The %d ready addresses published for Service %s/%s all name node %s. This is a placement "+
					"reading and not a verdict: whether one node holding every published backend matters depends "+
					"on failure domains, spread constraints and consumer behaviour the snapshot does not record.",
				pub.ready, svc.Namespace, svc.Name, h.node),
			WhyItMatters: "Placement of the published set is not visible in any workload manifest — it is " +
				"decided by the scheduler run by run, so a Service can drift onto one node without anything changing.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.5,
			Provenance:        provenance(),
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Rule 3 — a Ready pod the Service selects and no slice lists
// ─────────────────────────────────────────────────────────────────────────────────────────────

type PodSelectedButUnpublished struct{}

// TEST COVERAGE, STATED: unit tests only, and the reason is not laziness. The positive branch
// needs a pod that matches a Service selector and is Ready while the EndpointSlice controller has
// NOT published it — a race the controller closes in milliseconds. There is no honest way to hold
// a real cluster in that state on demand, and faking it by deleting the slice would test a
// different thing (a missing slice, not an unpublished ready pod). The shape is asserted against
// constructed inventories instead; the live testbed confirms only the negative.
//
// AND THE UNWITNESSABILITY IS A PROPERTY OF THE DEFECT, NOT A GAP IN OUR DILIGENCE. A Ready pod that
// matches a Service's selector and appears in none of that Service's slices means the EndpointSlice
// controller is absent, wedged, or being outrun — which is exactly why the finding is worth reporting
// and exactly why a healthy cluster cannot be made to produce it on demand. Reaching it would mean
// breaking the control plane of the testbed, and a testbed with a broken control plane verifies
// nothing else. This is the one rule in the family where "we could not witness it" and "the cluster is
// working correctly" are the same sentence.
//
// The two other unwitnessed rules in this epic were BOTH closed once looked at properly — the HPA one
// needed metrics-server, and the CronJob one had a comment claiming the status subresource was
// unwritable, which was false. That is the reason this note argues its case rather than asserting it.
func (PodSelectedButUnpublished) ID() string      { return "k8s.config.pod-selected-but-unpublished" }
func (PodSelectedButUnpublished) Version() string { return "1.0.0" }

// RequiredKinds — this rule is the one that reads Pods: the claim is a JOIN between the pod list
// and the slice list, so both are load-bearing, and the Service list supplies the selector. `nodes`
// is deliberately omitted — no Node object is read.
// See deps.go for what belongs in this list.
func (PodSelectedButUnpublished) RequiredKinds() []string {
	return sortedKinds([]string{"endpointslices", "pods", "services"})
}

func (r PodSelectedButUnpublished) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !rotationGuard(inv) || !observed(inv, "pods") {
		return nil
	}
	reading := readingTime(inv)
	cutoff := reading.Add(-rotationReadyGrace)
	graceLabel := fmt.Sprintf("%ds", int(rotationReadyGrace.Seconds()))
	cov := newCoverage()

	type hit struct {
		svc         *corev1.Service
		unpublished []corev1.Pod
		selected    int
	}
	var hits []hit
	podsIn := podsByNamespace(inv)

	for _, i := range sortedServices(inv) {
		svc := &inv.Services[i]
		if !opts.IncludeSystem && isSystemNamespace(svc.Namespace) {
			continue
		}
		pub := publishedFor(inv, svc)
		shape := shapeOf(svc, pub, reading)
		switch {
		case shape.externalName:
			cov.skip(reasonExternalName)
			continue
		case shape.selectorless:
			cov.skip(reasonSelectorless)
			continue
		case shape.foreign:
			cov.skip(reasonForeign)
			continue
		case shape.tooNew:
			cov.skip(reasonTooNew)
			continue
		}
		// Headless Services are eligible: the controller publishes their backends too.
		cov.judge()

		sel := labels.SelectorFromSet(labels.Set(svc.Spec.Selector))
		var missing []corev1.Pod
		selected := 0
		for _, j := range podsIn[svc.Namespace] {
			p := inv.Pods[j]
			if !sel.Matches(labels.Set(p.Labels)) {
				continue
			}
			if !podSettledReady(&p, cutoff) {
				continue
			}
			selected++
			if !pub.published[p.UID] {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			sort.Slice(missing, func(a, b int) bool { return missing[a].Name < missing[b].Name })
			hits = append(hits, hit{svc: svc, unpublished: missing, selected: selected})
		}
	}

	coverage := cov.line()
	out := make([]types.Finding, 0, len(hits))
	for _, h := range hits {
		svc := h.svc
		names := make([]string, 0, len(h.unpublished))
		refs := []types.ResourceRef{{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}}
		for _, p := range h.unpublished {
			names = append(names, p.Name)
			refs = append(refs, types.ResourceRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name})
		}
		shown := names
		more := ""
		if len(shown) > 10 {
			more = fmt.Sprintf(" (+%d more)", len(shown)-10)
			shown = shown[:10]
		}
		evidence := []string{
			fmt.Sprintf("Service %s/%s selects %s whose Ready condition has been true for at least %s "+
				"before this reading; not listed in any EndpointSlice labelled %s=%s: %d of those %d — %s%s",
				svc.Namespace, svc.Name, nWord(h.selected, "pod", "pods"), graceLabel,
				discoveryv1.LabelServiceName, svc.Name, len(names), h.selected, strings.Join(shown, ", "), more),
			fmt.Sprintf("the %s gate on Ready.lastTransitionTime is deliberate: a shorter window reports every "+
				"pod a rollout has just produced, because the EndpointSlice controller writes after the kubelet "+
				"reports readiness. Pods carrying a deletionTimestamp, and pods not in phase Running, are excluded.",
				graceLabel),
			fmt.Sprintf("selector read from Service %s/%s spec.selector: %s",
				svc.Namespace, svc.Name, labelsAsText(svc.Spec.Selector)),
			coverage,
		}
		out = append(out, types.Finding{
			ID:          findingID(r.ID(), "Service", svc.Namespace, svc.Name),
			IDBasis:     &types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Ready pods selected by %s/%s appear in no EndpointSlice", svc.Namespace, svc.Name),
			Description: fmt.Sprintf(
				"%s in namespace %s carry the labels in Service %s's selector and report Ready, and no "+
					"EndpointSlice published for that Service lists them. This finding states that arithmetic and "+
					"stops there — a readiness gate the kubelet has reported but the controller has not written yet, "+
					"and a publishNotReadyAddresses interaction, both read the same way as a controller that stopped.", nWord(len(names), "pod", "pods"), svc.Namespace, svc.Name),
			WhyItMatters: "A pod that reports Ready and is published nowhere is a disagreement between two of the " +
				"cluster's own controllers, and neither side reports it.",
			Evidence: evidence,
			// info, per the design decision recorded in the spec: this is the rule most likely to
			// fire transiently, and the readiness gate reduces that rather than removing it.
			Severity:          types.SeverityInfo,
			Category:          types.CategoryConfig,
			AffectedResources: refs,
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.4,
			Provenance:        provenance(),
		})
	}
	return out
}

// podSettledReady reports whether this pod has been Ready since before cutoff, is Running, and is
// not being deleted. Each clause removes a shape that is legitimately absent from a slice: a
// terminating pod is removed on purpose, a non-Running pod was never published, and a pod that
// became Ready a moment ago is simply ahead of the controller.
func podSettledReady(p *corev1.Pod, cutoff time.Time) bool {
	if p.DeletionTimestamp != nil {
		return false
	}
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		if c.Status != corev1.ConditionTrue {
			return false
		}
		// A missing lastTransitionTime cannot be aged, so it is not settled.
		if c.LastTransitionTime.IsZero() {
			return false
		}
		return c.LastTransitionTime.Time.Before(cutoff) || c.LastTransitionTime.Time.Equal(cutoff)
	}
	return false
}

// labelsAsText renders a selector map in a stable order for evidence.
func labelsAsText(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}
