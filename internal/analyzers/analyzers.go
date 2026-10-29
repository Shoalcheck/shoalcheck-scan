// Package analyzers inspects well-known operator CRDs (cert-manager, Istio,
// Argo/Flux, Cilium/Calico, KEDA, Strimzi, Gateway API) read into the Phase-0
// Inventory.StackObjects, and emits schema-v1 Findings through the SAME
// pipeline as internal/rules. It is a leaf alongside internal/rules: it imports
// internal/collect for *Inventory and internal/types for Finding, and is
// imported only by internal/pipeline. It MUST NOT import internal/report or any
// cloud SDK / internal/billing — the open-core boundary holds.
package analyzers

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// StackAnalyzer mirrors rules.Rule: it reads the read-only Inventory and emits
// Findings. Unlike a Rule it declares the CRD GVRs it needs; the runner gates
// on inv.PresentGVRs so an analyzer for an absent operator silently emits
// nothing (no 404 List, no "not found" noise).
type StackAnalyzer interface {
	// ID is the REGISTRATION id — "stack.hpa.sanity". No finding carries it; see FindingIDs.
	ID() string
	Version() string
	RequiredGVRs() []schema.GroupVersionResource

	// FindingIDs is every rule id a finding from this analyzer can carry, and it exists because ID() is
	// not one of them.
	//
	// The ids findings carry are more specific than the registration id — "stack.hpa.no-headroom",
	// "stack.monitoring.prometheus-storage-ephemeral" — and until 2026-09-10 nothing declared them, so
	// every gate that needed them scanned this package's SOURCE with a regex over `"stack\..."` literals.
	// The ids are minted in three shapes: a named const (istio.go), a helper ARGUMENT (hpa.go), and four
	// types in one file (monitoring.go, where a file-level scan cannot say which type emits which). A
	// scanner has to know all three; a declared method has to know none of them, and the compiler checks it.
	//
	// EMPTY IS A DECLARATION, not an omission: CalicoPolicy and CiliumPolicy return nil from Analyze by
	// design — they exist so netpol.go can count policy objects rather than fall back to its honest 0.45
	// confidence — and saying so stops a coverage gate demanding boundary text for findings nobody emits.
	FindingIDs() []string

	Analyze(inv *collect.Inventory) []types.Finding
}

// All returns the analyzer registry in stable order: cert-manager first (the
// wow factor), then the segmentation analyzers that retire the netpol apology,
// then mesh, GitOps, scaling, and the long tail — security-first like
// rules.All().
func All() []StackAnalyzer {
	return []StackAnalyzer{
		CertManagerExpiry{},
		CiliumPolicy{}, CalicoPolicy{},
		IstioMTLS{}, LinkerdMTLS{},
		ArgoSync{}, FluxSync{},
		HPASanity{}, KEDAScaledObject{},
		StrimziKafka{}, GatewayAPI{},
		// The monitoring stack, last because it is the one component that cannot audit itself — see
		// monitoring.go. Four analyzers rather than one: hasAllGVRs is an AND, so a single analyzer
		// declaring all four CRDs would fall silent on any cluster missing one of them.
		ServiceMonitorTargets{}, PodMonitorTargets{}, AlertRouting{}, PrometheusDurability{},
	}
}

// RequiredGVRsUnion is the dedup'd set of every GVR any analyzer needs. The
// pipeline passes it into collect.Collect (Phase-0 signature) so the dynamic
// client lists exactly those CRDs that are both wanted AND served.
func RequiredGVRsUnion() []schema.GroupVersionResource {
	seen := map[schema.GroupVersionResource]bool{}
	var out []schema.GroupVersionResource
	for _, a := range All() {
		for _, gvr := range a.RequiredGVRs() {
			if !seen[gvr] {
				seen[gvr] = true
				out = append(out, gvr)
			}
		}
	}
	return out
}

// hasAllGVRs reports whether every GVR an analyzer needs is in the server's
// present set. The runner calls Analyze only when this is true.
func hasAllGVRs(present collect.GVRSet, want []schema.GroupVersionResource) bool {
	for _, gvr := range want {
		if !present.Has(gvr) {
			return false
		}
	}
	return true
}

// engineVersion stamps Provenance.Version on every stack finding, mirroring
// rules.engineVersion. Kept in this package so analyzers do not reach into
// internal/rules.
const engineVersion = "0.1.0"

// provenance mirrors rules.provenance. Collector stays "kubernetes" — the
// schema's allowed set is kubernetes|polaris|opencost; do not invent a new
// collector string.
func provenance() types.Provenance {
	return types.Provenance{Collector: "kubernetes", Version: engineVersion}
}

// readingTime is when this snapshot was taken.
//
// AN ANALYZER THAT CONSULTS THE WALL CLOCK CANNOT BE REPLAYED. certmanager decided from time.Now() whether a
// certificate was expired or merely expiring, so one stored inventory produced DIFFERENT FINDINGS on
// different days — the exact property the re-derivability claim is about, and the one place in this package
// it was broken. internal/rules has had this seam since rotation.go was written and nine producers anchor to
// it; internal/analyzers read Meta.StartedAt nowhere.
//
// The fallback matches rules.readingTime deliberately, rather than being stricter. A hand-built inventory
// (tests, fixtures) has no reading clock and gets wall-clock now, exactly as the rules do — two producer
// packages disagreeing about what "no clock" means would be worse than the fallback itself. What makes a
// REPLAY reproducible is that the captured inventory carries Meta.StartedAt, and the test for that asserts
// the captured value rather than merely that a clock is non-zero.
func readingTime(inv *collect.Inventory) time.Time {
	if inv != nil && !inv.Meta.StartedAt.IsZero() {
		return inv.Meta.StartedAt
	}
	return time.Now()
}

// findingID mirrors rules.findingID: a stable hash of ruleID + canonical
// resource ref so the same issue keeps the same ID across runs. RuleID is part
// of the hash, so stack findings never collide with rule findings even on the
// same resource.
func findingID(ruleID, kind, ns, name string) string {
	h := sha256.Sum256([]byte(ruleID + "|" + kind + "|" + ns + "|" + name))
	return "f-" + hex.EncodeToString(h[:])[:12]
}

// stackObjects returns every collected CR whose GVR matches group+resource,
// IGNORING version — Phase-0 keyed StackObjects by the server-preferred version
// (which may be v1alpha2 / v1beta1 / v2), so analyzers must not key on a fixed
// version literal. group/resource are stable across versions.
//
// THE MATCHING GVRS ARE SORTED FIRST, because this ranges a MAP. It is harmless today for two independent
// reasons — gvrs.go declares one version per (group, resource) so at most one key matches, and every emitting
// analyzer re-sorts by id — and NOTHING PINS EITHER. Add a second version for one resource, or let one
// analyzer aggregate across objects instead of emitting per object, and the CR order becomes whatever the
// runtime's map iteration gives, which differs between two evaluations of one inventory.
func stackObjects(inv *collect.Inventory, group, resource string) []unstructured.Unstructured {
	var keys []schema.GroupVersionResource
	for gvr := range inv.StackObjects {
		if gvr.Group == group && gvr.Resource == resource {
			keys = append(keys, gvr)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	var out []unstructured.Unstructured
	for _, gvr := range keys {
		out = append(out, inv.StackObjects[gvr]...)
	}
	return out
}

// listSucceeded generalizes the netpol denial guard to any CR GVR. The Phase-0
// collector records "cr:<resource>.<group>" in Meta.Collected on a successful
// list and "cr:<resource>.<group>: <err>" in Meta.Denied otherwise. We must NOT
// assert observed-absence ("0 Certificates expiring") off a list we never saw —
// a denied list is a coverage gap, not a clean cluster. The key is derived from
// schema.GroupResource().String() so it can never drift from the collector's
// step label (collectStack uses gvr.GroupResource().String()).
func listSucceeded(inv *collect.Inventory, group, resource string) bool {
	gr := schema.GroupResource{Group: group, Resource: resource}
	key := collect.CRStepPrefix + gr.String() // exactly what Phase-0 collectStack() recorded
	for _, c := range inv.Meta.Collected {
		if c == key {
			return true
		}
	}
	for _, d := range inv.Meta.Denied {
		if d == key || strings.HasPrefix(d, key+":") {
			return false
		}
	}
	// Neither recorded: the run has no record of having looked, and this guard exists precisely to stop
	// an unlooked-at list being read as an empty one. A fixture that means "I observed no Certificates"
	// says so in Meta; see internal/rules/observed.go for why the escape hatch that used to sit here was
	// removed from all five copies of this guard at once.
	return false
}

// readyCondition scans status.conditions[] for the entry with type=="Ready"
// and returns its status string (e.g. "True"/"False") and whether it was found.
// Uses NestedSlice + NestedString discipline — never a raw []interface{}
// assertion — so a JSON-decoded CR can't panic the read.
func readyCondition(obj map[string]interface{}) (status string, found bool) {
	conds, ok, err := unstructured.NestedSlice(obj, "status", "conditions")
	if !ok || err != nil {
		return "", false
	}
	for _, ci := range conds {
		cm, ok := ci.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _, _ := unstructured.NestedString(cm, "type")
		if typ == "Ready" {
			st, _, _ := unstructured.NestedString(cm, "status")
			return st, true
		}
	}
	return "", false
}

// Analyzer types are declared here so the registry compiles; each type's
// RequiredGVRs/Analyze logic is implemented in its own file. CertManagerExpiry,
// HPASanity, etc. land file-by-file; until a per-analyzer file replaces its
// stubs.go block its Analyze is a no-op (no findings, never a panic).
type CertManagerExpiry struct{}
type CiliumPolicy struct{}
type CalicoPolicy struct{}
type IstioMTLS struct{}
type LinkerdMTLS struct{}
type ArgoSync struct{}
type FluxSync struct{}
type HPASanity struct{}
type KEDAScaledObject struct{}
type StrimziKafka struct{}
type GatewayAPI struct{}
