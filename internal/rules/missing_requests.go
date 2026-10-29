package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/prom"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type MissingRequests struct{}

func (MissingRequests) ID() string { return "k8s.workload.missing-resource-requests" }

// Version 1.1.0 (2026-08-30): the uncapped branch below. Rule logic changed, so Gate 2 (RuleChanged)
// withholds a comparison across it rather than reporting the extra evidence line as a cluster change.
func (MissingRequests) Version() string { return "1.1.0" }

func (r MissingRequests) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// Per-namespace Container-type LimitRange defaultRequest map. A container
	// that omits a request still gets an *effective* request injected at
	// admission from this default, so it is NOT actually request-less. The
	// sibling ns_governance rule recommends exactly this mechanism; honoring it
	// here avoids flagging a namespace that is already governed by a LimitRange.
	nsDefaults := limitRangeDefaultRequests(inv)

	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		var badContainers []string
		var evidence []string
		// SCOPE: regular containers AND native sidecars, and the restart policy is the boundary.
		//
		// KEP-753 made an initContainer with restartPolicy: Always run for the pod's whole life, so the
		// scheduler reserves its request for the whole life of the pod and the kubelet ranks the pod for
		// eviction using it. A request-less one is exactly what this rule exists to find, and it was
		// invisible here until now — the same blind spot as B-102 in node_headroom's arithmetic, one file
		// over, found by the same recount.
		//
		// A PLAIN init container is still not assessed, and that asymmetry is the whole point: it runs once,
		// before the app containers, so its request is not part of the steady-state footprint. Flagging it
		// would be the mirror-image error of the one being fixed.
		//
		// This widening raises the finding count on every mesh-injected cluster. That was a founder decision,
		// not a sweep side effect.
		var uncappedNotes []string
		for _, ac := range assessedContainers(w.PodSpec) {
			c := ac.c
			// A resource is effectively requested when EITHER an explicit
			// request is set OR a limit is set (the apiserver copies
			// limits -> requests at admission, so a limit-only container is
			// fully scheduled and is NOT a low-priority eviction candidate).
			cpuSet := hasResource(c.Resources.Requests, corev1.ResourceCPU) ||
				hasResource(c.Resources.Limits, corev1.ResourceCPU)
			memSet := hasResource(c.Resources.Requests, corev1.ResourceMemory) ||
				hasResource(c.Resources.Limits, corev1.ResourceMemory)

			// Namespace LimitRange defaultRequest closes the remaining gap.
			defaults := nsDefaults[w.Namespace]
			cpuFromLR := !cpuSet && hasResource(defaults, corev1.ResourceCPU)
			memFromLR := !memSet && hasResource(defaults, corev1.ResourceMemory)

			cpuMissing := !cpuSet && !cpuFromLR
			memMissing := !memSet && !memFromLR

			if !cpuMissing && !memMissing {
				// Effectively requested (explicit request, a limit, or a
				// namespace LimitRange default) — not a finding for the request half.
				//
				// THE UNCAPPED BRANCH — a REFINEMENT, not a second rule, and the measurement is why.
				//
				// kube-score and Popeye both publish "no resource limits" as its own check, and the Phase 1
				// overlap census measured what building it separately would cost on a real cluster: of 225
				// non-system containers, 55 declare NEITHER a request nor a limit — those are already
				// reported above, and a second rule would put a second card on 46 workloads — while only 4
				// declare a request and no limit. A new rule would have added 46 duplicates to state 4 real
				// things.
				//
				// So the four are stated HERE, inside the rule that already owns "this container's
				// resources are not fully declared", as an extra evidence line on a finding that fires
				// anyway — and on a container that is otherwise fully declared it produces nothing at all,
				// because an uncapped container that IS requested is a choice, not an omission.
				// COLLECTED UNCONDITIONALLY, GATED AT THE END — and the order matters. `badContainers` is
				// filled as this loop runs, so testing it HERE would drop the note for any workload whose
				// uncapped container is listed BEFORE its unrequested one. The first version did exactly
				// that and the test missed it, because the fixture happened to list them the lucky way
				// round. The `continue` below is the real gate: no bad container, no finding, notes
				// discarded with it.
				if uncapped := uncappedResources(c); len(uncapped) > 0 {
					uncappedNotes = append(uncappedNotes, fmt.Sprintf(
						"%s %s in %s %s/%s: %s requested but never capped — resources.limits sets no %s, so "+
							"nothing bounds what this container may take from the node",
						ac.noun, c.Name, w.Kind, w.Namespace, w.Name,
						strings.Join(uncapped, "/"), strings.Join(uncapped, "/")))
				}
				continue
			}

			missing := []string{}
			if cpuMissing {
				missing = append(missing, "cpu")
			}
			if memMissing {
				missing = append(missing, "memory")
			}
			badContainers = append(badContainers, c.Name)
			// The noun says WHICH KIND of container this is, because otherwise a reader sees an
			// initContainer flagged by a rule about steady-state requests and has no way to know why.
			evidence = append(evidence, fmt.Sprintf(
				"%s %s in %s %s/%s: no %s in resources.requests or resources.limits, and no namespace LimitRange defaultRequest covers it",
				ac.noun, c.Name, w.Kind, w.Namespace, w.Name, strings.Join(missing, "/")))
		}
		if len(badContainers) == 0 {
			continue
		}
		// The uncapped notes ride along ONLY on a finding that already exists. They never create one:
		// a workload whose every container is requested-but-uncapped is not reported by this rule, which
		// is the whole point of the measurement above.
		evidence = append(evidence, uncappedNotes...)

		out = append(out, types.Finding{
			ID:          findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:     &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:      r.ID(),
			RuleVersion: r.Version(),
			Title:       fmt.Sprintf("Set resource requests on %s/%s", w.Namespace, w.Name),
			Description: fmt.Sprintf(
				"%s %s/%s has %s that declare neither a resources.requests nor a resources.limits entry for CPU/memory, and the namespace has no LimitRange defaultRequest to inject one. With no effective request the scheduler places these pods on best-fit guesswork, and they fall into the BestEffort QoS class — first to be evicted under node memory pressure.",
				w.Kind, w.Namespace, w.Name, nWord(len(badContainers), "container", "containers")),
			WhyItMatters:      "Containers with no effective request (no explicit request, no limit defaulting, no namespace LimitRange) land in BestEffort QoS: the scheduler can't bin-pack them safely and the kubelet evicts them first under pressure. Note: a limit alone, or a namespace LimitRange defaultRequest, already supplies an effective request — those cases are NOT flagged here.",
			Evidence:          evidence,
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortLow,
			RemediationYAML:   requestsPatch(w, badContainers, opts.Usage, inv, usageSpan(opts)),
			// Detection now models the two K8s defaulting paths (limits->requests
			// and LimitRange defaultRequest), so a flagged container genuinely has
			// no effective request — a verifiable spec fact with near-universal
			// negative impact. Not 1.0: whether a given BestEffort pod is *first*
			// to be evicted still depends on its peers' QoS, which we don't model.
			Confidence: 0.9,
			Provenance: provenance(),
		})
	}
	return out
}

// hasResource reports whether a ResourceList carries a (positive-or-zero)
// quantity for the named resource. A present key is what K8s admission keys
// its defaulting decisions on, so presence — not value — is the signal.
// uncappedResources names the resources a container REQUESTS but never LIMITS. It deliberately says
// nothing about a container that requests nothing — that container is the rule's main claim, not this
// branch's — and nothing about a limit-only container, because the apiserver copies limits to requests.
func uncappedResources(c corev1.Container) []string {
	var out []string
	for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		if hasResource(c.Resources.Requests, r) && !hasResource(c.Resources.Limits, r) {
			out = append(out, string(r))
		}
	}
	return out
}

func hasResource(rl corev1.ResourceList, name corev1.ResourceName) bool {
	_, ok := rl[name]
	return ok
}

// limitRangeDefaultRequests folds inv.LimitRanges into a per-namespace
// ResourceList of Container-type defaultRequest values. When multiple
// LimitRange objects (or items) in a namespace set a defaultRequest for the
// same resource, the first seen wins — we only need presence, not the precise
// value the apiserver would pick, to know the request will be injected.
func limitRangeDefaultRequests(inv *collect.Inventory) map[string]corev1.ResourceList {
	if inv == nil {
		return nil
	}
	out := map[string]corev1.ResourceList{}
	for i := range inv.LimitRanges {
		lr := inv.LimitRanges[i]
		for _, item := range lr.Spec.Limits {
			if item.Type != corev1.LimitTypeContainer {
				continue
			}
			for name, qty := range item.DefaultRequest {
				rl := out[lr.Namespace]
				if rl == nil {
					rl = corev1.ResourceList{}
					out[lr.Namespace] = rl
				}
				if _, exists := rl[name]; !exists {
					rl[name] = qty
				}
			}
		}
	}
	return out
}

// requestsPatch emits a resources.requests patch for the flagged containers.
//
// When 7d usage is available (opts.Usage, populated only with --prometheus-url),
// the patch is seeded from the busiest replica's p95 CPU and observed MAX
// memory — measured values an operator can apply with care. When usage is
// ABSENT the patch must NOT be applied verbatim: hardcoded 100m/128Mi for a
// memory-heavy container (a JVM, Prometheus, a database) would make the
// scheduler under-pack the node and the kernel OOM-kill pods under real load.
// In that case we emit a blocking PLACEHOLDER comment so a `kubectl apply` of
// the raw block is self-evidently unsafe.
// span is the window the usage covers, as the run measured it — "" when nothing did. The comment in the
// patch below said "from 7d p95 CPU" whatever the usage source actually held, which on a six-hour-old
// Prometheus put a seven-day claim in a YAML an operator is invited to apply (M-127).
func requestsPatch(w workload, containers []string, usage map[string]prom.ContainerUsage, inv *collect.Inventory, span string) string {
	measured := map[string]struct{ cpu, mem string }{}
	if len(usage) > 0 {
		pods := podsMatchingWorkload(inv, w)
		for _, name := range containers {
			cpuCores, _, memMax, found := usageForContainer(usage, pods, name)
			if !found {
				continue
			}
			// CPU is compressible (throttled, not killed): size to p95.
			// Memory is non-compressible (OOMKilled below peak): size to the
			// observed 7d MAX with a small safety margin, never p95.
			cpuMilli := int64(cpuCores*1000) + 1
			memMiB := (memMax + (1 << 20) - 1) >> 20 // bytes -> ceil MiB
			memMiB = (memMiB*105 + 99) / 100         // +5% safety margin
			measured[name] = struct{ cpu, mem string }{
				cpu: fmt.Sprintf("%dm", cpuMilli),
				mem: fmt.Sprintf("%dMi", memMiB),
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apps/v1\nkind: %s\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      containers:\n", w.Kind, w.Name, w.Namespace)
	for _, c := range containers {
		if m, ok := measured[c]; ok {
			fmt.Fprintf(&b, "        - name: %s\n          resources:\n            requests:\n              cpu: %s      # from %s p95 CPU — validate against your workload before applying\n              memory: %s  # from %s MAX working-set +5%% — validate against your workload before applying\n", c, m.cpu, span, m.mem, span)
			continue
		}
		fmt.Fprintf(&b, "        - name: %s\n          resources:\n            requests:\n              # PLACEHOLDER — DO NOT apply blind: these are not measured values.\n              # Size from this container's real usage (`kubectl top pod` or a\n              # 7d Prometheus p95/max) or it may OOM the node under load.\n              cpu: 100m      # placeholder — replace with measured CPU\n              memory: 128Mi  # placeholder — replace with measured memory\n", c)
	}
	return b.String()
}

// usageForContainer returns the busiest-replica p95 CPU (cores), p95 memory
// (bytes), and observed MAX memory (bytes) for container `cname`, plus whether
// any usage series was found. Memory MAX is reported separately so the patch
// can size memory to peak (non-compressible) while CPU uses p95 (compressible).
func usageForContainer(usage map[string]prom.ContainerUsage, pods []corev1.Pod, cname string) (cpuCores, memP95Bytes float64, memMaxBytes int64, found bool) {
	for i := range pods {
		key := pods[i].Namespace + "/" + pods[i].Name + "/" + cname
		u, ok := usage[key]
		if !ok {
			continue
		}
		found = true
		if u.CPUCoresP95 > cpuCores {
			cpuCores = u.CPUCoresP95
		}
		if u.MemBytesP95 > memP95Bytes {
			memP95Bytes = u.MemBytesP95
		}
		if int64(u.MemBytesMax) > memMaxBytes {
			memMaxBytes = int64(u.MemBytesMax)
		}
	}
	// Guard: if MAX somehow came back below p95 (sparse series), use p95.
	if memMaxBytes < int64(memP95Bytes) {
		memMaxBytes = int64(memP95Bytes)
	}
	return cpuCores, memP95Bytes, memMaxBytes, found
}

// podsMatchingWorkload returns the live pods carrying the workload's pod
// labels, used to key the usage map. An empty label set matches nothing — we
// never claim every pod in the namespace. Kept local to this file so the
// usage-seeding path doesn't depend on a sibling rule's helper.
func podsMatchingWorkload(inv *collect.Inventory, w workload) []corev1.Pod {
	if inv == nil || len(w.PodLabels) == 0 {
		return nil
	}
	sel := labels.SelectorFromSet(labels.Set(w.PodLabels))
	var out []corev1.Pod
	for i := range inv.Pods {
		p := inv.Pods[i]
		if p.Namespace != w.Namespace {
			continue
		}
		if sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// RequiredKinds — A LimitRange default means the container DOES get requests, so a denied list would fabricate findings.
// Pods are read only to seed usage, which changes wording rather than the claim, so they stay out.
// See deps.go for what belongs in this list.
func (r MissingRequests) RequiredKinds() []string { return withWorkloads("limitranges") }

// assessedContainer is one container this rule judges, with the noun that describes it to a reader.
type assessedContainer struct {
	c    corev1.Container
	noun string
}

// assessedContainers returns every container whose request is part of the pod's steady-state footprint: the
// regular containers, plus the native sidecars.
//
// A native sidecar is an initContainer with restartPolicy: Always (KEP-753). It is listed among the init
// containers and behaves like a regular one — started before the app containers and kept running for the
// pod's whole life — which is why the scheduler counts its request for the pod's whole life and why this rule
// has to. Anything else in InitContainers runs to completion first and is deliberately skipped.
//
// node_headroom.podRequests draws the same line for the same reason. The two are separate because they answer
// different questions (what is bound versus what was declared); they must not disagree about what a sidecar
// is, and a test in each file pins the boundary.
func assessedContainers(spec corev1.PodSpec) []assessedContainer {
	out := make([]assessedContainer, 0, len(spec.Containers)+len(spec.InitContainers))
	for _, c := range spec.Containers {
		out = append(out, assessedContainer{c: c, noun: "container"})
	}
	for _, c := range spec.InitContainers {
		if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			continue
		}
		out = append(out, assessedContainer{c: c, noun: "sidecar container"})
	}
	return out
}
