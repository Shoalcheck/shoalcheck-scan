package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/apiremoval"
	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// upgrade_preflight.go — WHAT THE CLUSTER WILL STOP SERVING, AND WHAT IT CANNOT COMPLETE.
//
// Spec: docs/superpowers/specs/2026-08-29-upgrade-preflight-design.md, whose §3 is the boundary this whole
// family lives or dies on:
//
//	WE CAN SEE THE CLUSTER. WE CANNOT SEE ITS CLIENTS.
//
//	When an API version is removed, existing OBJECTS keep being served at the surviving version —
//	storage-version migration handles them. What breaks is CLIENTS: YAML in a git repo, a Helm chart, a
//	controller's client library, a CI pipeline applying an old apiVersion. None of those is in a
//	kubeconfig. So "this upgrade will break your deployments" is unobtainable, for the same reason
//	node_drain.go refuses user impact: the thing that breaks is on the other side of a boundary the
//	snapshot does not cross.
//
// What IS obtainable is what the cluster will stop SERVING, and what the cluster itself cannot complete.
// Smaller, and true.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS FAMILY REFUSES
//
//	NO WORKLOAD IS EVER NAMED by the deprecated-API rule. §3 — naming one would assert that this object
//	is the thing at risk, and the object is precisely what survives.
//
//	`last-applied-configuration` IS REFUSED, on four grounds and the fourth is disqualifying: it is
//	absent on every GitOps cluster (the exact buyer), it records what was APPLIED rather than what is
//	used, nothing updates it on storage migration, and it holds the ENTIRE applied manifest — env values,
//	arguments, ConfigMap keys — which `redact` does not cover and which anyone able to apply an object
//	controls.
//
//	SILENCE FROM THIS FAMILY MEANS THESE THREE THINGS WERE CHECKED, never that an upgrade will succeed.
//
//	NO DOLLARS. Nothing here has a cost basis.

// ── Rule: the cluster serves a group/version a named release removes ─────────────────────────────

// DeprecatedAPIServed reports served group/versions the API-removal schedule says a release removes.
type DeprecatedAPIServed struct{}

func (DeprecatedAPIServed) ID() string      { return "k8s.upgrade.deprecated-api-served" }
func (DeprecatedAPIServed) Version() string { return "1.0.0" }

// RequiredKinds — `server-resources` is the discovery step that fills ServedGroupVersions. Nothing else is
// read: the claim names no object, so no object list can change it.
func (DeprecatedAPIServed) RequiredKinds() []string { return sortedKinds([]string{"server-resources"}) }

var k8sVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// parseMinor returns major.minor as comparable integers. A major below 1 is rejected for the reason
// oblique.go records: "0.0.0-master+$Format:%H$" is what an unstamped build reports, and comparing against
// it would make every removal look imminent.
func parseMinor(s string) (maj, min int, ok bool) {
	m := k8sVersionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, 0, false
	}
	a, e1 := strconv.Atoi(m[1])
	b, e2 := strconv.Atoi(m[2])
	if e1 != nil || e2 != nil || a < 1 {
		return 0, 0, false
	}
	return a, b, true
}

func (r DeprecatedAPIServed) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "server-resources") || len(inv.ServedGroupVersions) == 0 {
		return nil
	}
	// THE CLUSTER'S OWN VERSION MUST PARSE BEFORE ANY COMPARISON, and an unparseable one withholds the
	// WHOLE rule with the reason stated — never renders as "no deprecated APIs served", which is the
	// absence-as-fact defect this product exists to refuse.
	curMaj, curMin, ok := parseMinor(inv.Meta.ServerVersion)
	if !ok {
		return nil
	}

	type hit struct {
		gv  string
		rem apiremoval.Removal
	}
	var future, past []hit
	for _, gv := range inv.ServedGroupVersions {
		// Applicable, NOT For — B-155. A group/version string is not a stable identity across releases:
		// `admissionregistration.k8s.io/v1beta1` was removed in 1.22 carrying MutatingWebhookConfiguration
		// and reintroduced in 1.28 carrying ValidatingAdmissionPolicy. Narrowing by the SERVER'S version is
		// what stops a current cluster being measured against the string's previous life.
		for _, rem := range apiremoval.Applicable(gv, curMaj, curMin) {
			rMaj, rMin, rok := parseMinor(rem.RemovedIn)
			if !rok {
				continue
			}
			h := hit{gv: gv, rem: rem}
			// A version this cluster ALREADY passed and still serves is a different and stranger fact:
			// the server says it serves something the schedule says was removed. That is a statement
			// about our TABLE being wrong, or about a re-registered aggregated API — either way it is
			// not an upgrade warning, and conflating the two would report a healthy cluster as doomed.
			if rMaj < curMaj || (rMaj == curMaj && rMin <= curMin) {
				past = append(past, h)
			} else {
				future = append(future, h)
			}
			break // For() is sorted; the earliest removal is the one that matters
		}
	}
	if len(future) == 0 {
		return nil
	}
	sort.Slice(future, func(i, j int) bool {
		if future[i].rem.RemovedIn != future[j].rem.RemovedIn {
			return future[i].rem.RemovedIn < future[j].rem.RemovedIn
		}
		return future[i].gv < future[j].gv
	})

	evidence := []string{
		snapshotNote(inv),
		fmt.Sprintf("the API server reports version %s, and this reading enumerated %s", inv.Meta.ServerVersion,
			nWord(len(inv.ServedGroupVersions), "served group/version", "served group/versions")),
	}
	refs := []types.ResourceRef{}
	for _, h := range future {
		repl := h.rem.Replacement
		if repl == "" {
			repl = "the guide names no replacement"
		}
		kinds := "the whole group/version"
		if len(h.rem.Kinds) > 0 {
			kinds = strings.Join(h.rem.Kinds, ", ")
		}
		evidence = append(evidence, fmt.Sprintf("%s is served now and is removed in %s — affecting %s; "+
			"the replacement is %s", h.gv, h.rem.RemovedIn, kinds, repl))
		refs = append(refs, types.ResourceRef{Kind: "APIService", Name: h.gv})
	}
	if len(past) > 0 {
		names := make([]string, 0, len(past))
		for _, h := range past {
			names = append(names, fmt.Sprintf("%s (scheduled for removal in %s)", h.gv, h.rem.RemovedIn))
		}
		sort.Strings(names)
		evidence = append(evidence, fmt.Sprintf("%s are recorded as removed at or "+
			"before this cluster's own version and are NOT reported above: %s. A server that serves one "+
			"either means this reading's schedule is wrong or an aggregated API has re-registered it, and "+
			"neither is an upgrade warning.", nWord(len(past), "served group/version", "served group/versions"), strings.Join(names, ", ")))
	}
	evidence = append(evidence,
		fmt.Sprintf("the removal schedule was last reconciled with the upstream deprecation guide on %s",
			apiremoval.AsOf()),
		"NO WORKLOAD IS NAMED, and that is not an omission: when a version is removed the existing "+
			"objects keep being served at the surviving version. What stops working is a CLIENT — a "+
			"manifest in a repository, a chart, a controller's library, a pipeline — and none of those is "+
			"visible from a kubeconfig.")

	earliest := future[0].rem.RemovedIn
	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "deprecated-api-served"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "deprecated-api-served"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s %s removed by Kubernetes %s or later",
			nWord(len(future), "served API version", "served API versions"), pick(len(future), "is", "are"), earliest),
		Description: fmt.Sprintf("This cluster reports version %s and serves %s that the "+
			"upstream deprecation guide records as removed in a later release, the earliest being %s. The "+
			"objects themselves survive an upgrade — the API server migrates their storage version. What "+
			"stops working is anything that still ASKS for the removed version.",
			inv.Meta.ServerVersion, nWord(len(future), "group/version", "group/versions"), earliest),
		WhyItMatters: "The list of versions a cluster serves is not the list anything uses, and the " +
			"difference is only discoverable from outside the cluster — in repositories, charts and " +
			"pipelines. This names what the cluster will stop offering, so that search has somewhere to " +
			"start.",
		Evidence:          evidence,
		Severity:          types.SeverityMedium,
		Category:          types.CategoryConfig,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

// ── Rule: a CRD whose conversion webhook has nothing behind it ───────────────────────────────────

// CRDConversionWebhookUnbacked reports CRDs declaring a conversion webhook whose Service publishes no
// ready endpoints.
type CRDConversionWebhookUnbacked struct{}

func (CRDConversionWebhookUnbacked) ID() string      { return "k8s.upgrade.crd-conversion-webhook-unbacked" }
func (CRDConversionWebhookUnbacked) Version() string { return "1.0.0" }

func (CRDConversionWebhookUnbacked) RequiredKinds() []string {
	return sortedKinds([]string{"customresourcedefinitions", "endpointslices", "services"})
}

func (r CRDConversionWebhookUnbacked) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	if !observed(inv, "customresourcedefinitions") || !observed(inv, "services") ||
		!observed(inv, "endpointslices") {
		return nil
	}
	var unbacked, unknown []string
	var refs []types.ResourceRef

	for i := range inv.CRDs {
		crd := &inv.CRDs[i]
		// strategy None — and an ABSENT strategy, which the API server defaults to None — is out of
		// scope and silent. There is no webhook to be unbacked.
		if crd.ConversionStrategy != "Webhook" {
			continue
		}
		if crd.WebhookServiceName == "" {
			// Addressed by URL, which is outside the cluster and outside this reading. Stated rather than
			// silently skipped, so the count in the finding is honest about what it did not judge.
			if crd.WebhookURL != "" {
				unknown = append(unknown, fmt.Sprintf("%s (webhook addressed by URL, which this reading "+
					"cannot resolve)", crd.Name))
			}
			continue
		}
		svc := findService(inv, crd.WebhookServiceNamespace, crd.WebhookServiceName)
		if svc == nil {
			// A SERVICE THIS READING DID NOT SEE IS `unknown`, NEVER `unbacked`. The Services list was
			// read, but a namespace-scoped RBAC narrowing can hide one namespace while another is
			// visible — and calling that "no endpoints" would fabricate the finding.
			unknown = append(unknown, fmt.Sprintf("%s (Service %s/%s not in this reading)",
				crd.Name, crd.WebhookServiceNamespace, crd.WebhookServiceName))
			continue
		}
		pub := publishedFor(inv, svc)
		if pub.ready > 0 {
			continue
		}
		unbacked = append(unbacked, fmt.Sprintf("%s: conversion webhook points at Service %s/%s, which "+
			"publishes %s across %s",
			crd.Name, svc.Namespace, svc.Name, nWord(pub.ready, "ready address", "ready addresses"), nWord(pub.slices, "EndpointSlice", "EndpointSlices")))
		refs = append(refs,
			types.ResourceRef{Kind: "CustomResourceDefinition", Name: crd.Name},
			types.ResourceRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
	}
	if len(unbacked) == 0 {
		return nil
	}
	sort.Strings(unbacked)
	evidence := append([]string{snapshotNote(inv)}, unbacked...)
	if len(unknown) > 0 {
		sort.Strings(unknown)
		evidence = append(evidence, fmt.Sprintf("%s were NOT judged: %s", nWord(len(unknown), "conversion webhook", "conversion webhooks"), strings.Join(unknown, "; ")))
	}
	evidence = append(evidence,
		"a webhook with no ready endpoint is what this states; whether the API server needs to call it "+
			"during any particular upgrade is not readable from here",
		"CRDs with conversion strategy None are out of scope and silent — there is no webhook to back")

	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "conversion-webhook-unbacked"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "conversion-webhook-unbacked"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title: fmt.Sprintf("%s %s a conversion webhook with nothing behind it",
			nWord(len(unbacked), "CustomResourceDefinition", "CustomResourceDefinitions"),
			pick(len(unbacked), "declares", "declare")),
		Description: fmt.Sprintf("%s declare spec.conversion.strategy=Webhook "+
			"and name a Service that publishes no ready addresses in this reading. A conversion webhook is "+
			"how the API server translates between stored and requested versions of a custom resource.", nWord(len(unbacked), "CustomResourceDefinition", "CustomResourceDefinitions")),
		WhyItMatters: "A conversion webhook is invisible until something needs it, and what needs it is " +
			"usually a version change — an operator upgrade, or the API server migrating a stored " +
			"version. The CRD reads as correctly configured throughout.",
		Evidence:          evidence,
		Severity:          types.SeverityHigh,
		Category:          types.CategoryReliability,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortMedium,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}

// ── Rule: the node roll cannot complete ──────────────────────────────────────────────────────────

// DrainStops are the rules whose findings stop a drain of a node: a budget at zero, a pod nothing recreates, a
// volume pinned to the node, work with nowhere to go. Placement concentration is a note there, not a stop.
// internal/preflight's drain question is these plus that note, and internal/headline counts the nodes these name,
// both held to this list by internal/gatecheck — one list, so the opening, the drain and the roll cannot disagree
// about which nodes cannot be evacuated.
func DrainStops() []Rule {
	return []Rule{NodeDrainBudget{}, NodeDrainUnmanaged{}, NodePinnedVolume{}, NodeLossFeasibility{}}
}

// NodePoolCannotRoll composes the drain's per-node findings into the upgrade question.
//
// COMPOSITION, NOT NEW ARITHMETIC, and that is the whole design. Drain Preflight already computes per-node
// evacuation feasibility and already found four undrainable nodes on a real AKS. The upgrade framing turns
// a per-node observation into a cluster-level one: an operator can live with one stuck node indefinitely
// and cannot complete a node-image roll with it.
//
// EVERY DRAIN STOP, NOT ONE OF THEM. It composed the node-loss model alone, so the sample opened on "5 nodes
// cannot be evacuated" — the drain's own stops — while this finding said the roll meets 1 of 12, and on kind
// `preflight upgrade` answered ✓ where `preflight drain` stopped on two of three nodes (D50 product review). A
// roll drains every node, so whatever stops a drain stops the roll at that node.
//
// IT CITES THE PER-NODE FINDINGS BY ID AND DOES NOT RESTATE THEM. RolloutPassesThroughZero colliding with
// RiskyRolloutStrategy is the lesson: two cards describing one configuration make the count wrong and
// verdict.Select cannot dedupe them.
type NodePoolCannotRoll struct{}

func (NodePoolCannotRoll) ID() string      { return "k8s.upgrade.node-pool-cannot-roll" }
func (NodePoolCannotRoll) Version() string { return "1.1.0" }

// RequiredKinds are the union of the drain stops' — this rule's claim rests on exactly their reads, and it adds
// no input of its own.
func (NodePoolCannotRoll) RequiredKinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range DrainStops() {
		for _, k := range r.RequiredKinds() {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return sortedKinds(out)
}

// Evaluate runs the drain stops and joins their findings to nodes.
func (r NodePoolCannotRoll) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	// JOINING TO THE NODE. The budget, unmanaged-pod and pinned-volume findings name their node among their
	// affected resources. The node-loss finding lists the displaced PODS there — correct for that finding, since
	// the pods are what has nowhere to go — and carries the node only inside its hashed ID, which is sha256 and
	// one-way. Two wrong ways to recover the node from it: parse the Title, which makes a sentence load-bearing;
	// or re-run the feasibility model per node, which is exactly the "new arithmetic" this rule exists not to do.
	// What is stable is findingID itself: deriving the same key for each node and looking it up reproduces no
	// feasibility logic at all.
	nodes := map[string]bool{}
	var ids []string
	for _, stop := range DrainStops() {
		perNode := stop.Evaluate(inv, opts)
		if len(perNode) == 0 {
			continue
		}
		if stop.ID() == (NodeLossFeasibility{}).ID() {
			byID := map[string]bool{}
			for _, f := range perNode {
				byID[f.ID] = true
			}
			joined := 0
			for i := range inv.Nodes {
				name := inv.Nodes[i].Name
				if id := findingID(stop.ID(), "Node", "", name); byID[id] {
					nodes[name] = true
					ids = append(ids, id)
					joined++
				}
			}
			if joined != len(perNode) {
				// EVERY node-loss finding must join, or the count in this finding's own sentence is wrong.
				// Withhold rather than under-report.
				return nil
			}
			continue
		}
		for _, f := range perNode {
			named := false
			for _, ref := range f.AffectedResources {
				if ref.Kind == "Node" && ref.Name != "" {
					nodes[ref.Name] = true
					named = true
				}
			}
			if !named {
				return nil // a stop that names no node cannot be counted; withhold rather than under-report
			}
			ids = append(ids, f.ID)
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	sort.Strings(ids)

	total := len(inv.Nodes)
	refs := make([]types.ResourceRef, 0, len(names))
	for _, n := range names {
		refs = append(refs, types.ResourceRef{Kind: "Node", Name: n})
	}
	return []types.Finding{{
		ID:          findingID(r.ID(), "Cluster", "", "node-pool-cannot-roll"),
		IDBasis:     &types.ResourceRef{Kind: "Cluster", Namespace: "", Name: "node-pool-cannot-roll"},
		RuleID:      r.ID(),
		RuleVersion: r.Version(),
		Title:       fmt.Sprintf("A node roll meets %d of %s it cannot evacuate", len(names), nWord(total, "node", "nodes")),
		Description: fmt.Sprintf("A node-image upgrade replaces nodes one at a time, and each replacement "+
			"needs the node drained first. A drain stops on %d of this cluster's %s — a budget that allows no "+
			"eviction, a pod nothing recreates, a volume pinned to the node, or work this reading finds no "+
			"remaining node for. Each is already reported on its own; this states what they mean together, "+
			"which is that the roll does not complete without forcing one of them.",
			len(names), nWord(total, "node", "nodes")),
		WhyItMatters: "A single node that cannot be drained is something an operator can live with " +
			"indefinitely. An upgrade cannot: it has to visit every node, so the same fact changes from " +
			"an inconvenience into a stopping condition.",
		Evidence: []string{
			snapshotNote(inv),
			fmt.Sprintf("%d of %s: %s", len(names), nWord(total, "node", "nodes"), strings.Join(names, ", ")),
			fmt.Sprintf("each is reported by the drain's own rules, findings %s — the evidence is there and "+
				"is deliberately not repeated here, so one problem is not counted twice", strings.Join(ids, ", ")),
			"no duration, no ordering, and no claim that the upgrade fails: the supportable sentence is " +
				"that the roll encounters these nodes",
			"the managed provider's own upgrade orchestration — surge nodes, batch size, its own " +
				"eviction handling — is not read and not modelled",
		},
		Severity:          types.SeverityHigh,
		Category:          types.CategoryReliability,
		AffectedResources: refs,
		EstimatedEffort:   types.EffortHigh,
		Confidence:        1.0,
		Provenance:        provenance(),
	}}
}
