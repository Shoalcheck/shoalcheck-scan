package rules

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func ciliumGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
}

// ciliumCWGVR is the cluster-wide sibling. On a real Cilium cluster BOTH lists
// are collected; crdPolicyCounts now requires both to have succeeded before it
// trusts the cluster-wide count (denial guard), so tests that exercise the
// CRD-aware path must mark both collected.
func ciliumCWGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}
}

// ciliumCollected marks both the namespaced and cluster-wide Cilium CRD lists as
// successfully collected (the real-cluster state).
func ciliumCollected() []string {
	return []string{
		"deployments", "networkpolicies",
		"cr:" + ciliumGVR().GroupResource().String(),
		"cr:" + ciliumCWGVR().GroupResource().String(),
	}
}

func cnpObj(ns, name string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
	}}
}

// When Cilium CRDs were ACTUALLY listed and the namespace HAS a
// CiliumNetworkPolicy, the upstream-netpol finding is a false positive and must
// be SUPPRESSED.
func TestNoNetworkPolicy_CiliumCRDSegmentedSuppresses(t *testing.T) {
	g := ciliumGVR()
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "cilium")},
		PresentGVRs: collect.GVRSet{g: struct{}{}},
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{
			g: {cnpObj("app", "deny-all")},
		},
		Meta: collect.Meta{Collected: ciliumCollected()},
	}
	if fs := (NoNetworkPolicy{}).Evaluate(inv, Options{}); len(fs) != 0 {
		t.Errorf("namespace segmented by a CiliumNetworkPolicy must be suppressed, got %+v", fs)
	}
}

// DENIAL GUARD (fix #10): Cilium namespaced CRD listed, but the CLUSTER-WIDE list
// was DENIED. clusterWide would read 0 silently, so we must NOT confidently emit
// an "unsegmented" finding — a CiliumClusterwideNetworkPolicy we couldn't see may
// segment the namespace. The rule falls back to the honest 0.45 "verify CRDs"
// path instead of the CRD-confirmed 0.8.
func TestNoNetworkPolicy_CiliumClusterwideListDeniedFallsBack(t *testing.T) {
	g, cw := ciliumGVR(), ciliumCWGVR()
	inv := &collect.Inventory{
		Deployments:  []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:   []appsv1.DaemonSet{daemonSet("kube-system", "cilium")},
		PresentGVRs:  collect.GVRSet{g: struct{}{}, cw: struct{}{}}, // both GVRs present
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{g: {}},
		Meta: collect.Meta{
			Collected: []string{"deployments", "networkpolicies", "cr:" + g.GroupResource().String()},
			Denied:    []string{"cr:" + cw.GroupResource().String() + ": forbidden"},
		},
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Confidence != 0.45 {
		t.Errorf("denied cluster-wide list must NOT yield the CRD-confirmed 0.8 — want honest 0.45 fallback, got %v", fs[0].Confidence)
	}
}

// Cilium CRD present + listed + ZERO of both kinds → real gap, confidence 0.8,
// evidence cites the CRD count (no more 0.45 apology).
func TestNoNetworkPolicy_CiliumCRDPresentZeroOfBothIs08(t *testing.T) {
	g, cw := ciliumGVR(), ciliumCWGVR()
	inv := &collect.Inventory{
		Deployments:  []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:   []appsv1.DaemonSet{daemonSet("kube-system", "cilium")},
		PresentGVRs:  collect.GVRSet{g: struct{}{}, cw: struct{}{}}, // both GVRs present + both listed
		StackObjects: map[schema.GroupVersionResource][]unstructured.Unstructured{g: {}},
		Meta:         collect.Meta{Collected: ciliumCollected()},
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("zero of both must yield 1 finding, got %d", len(fs))
	}
	if fs[0].Confidence != 0.8 {
		t.Errorf("CRD-confirmed zero-of-both confidence = %v, want 0.8", fs[0].Confidence)
	}
	if !strings.Contains(strings.Join(fs[0].Evidence, " "), "0 CiliumNetworkPolicy") {
		t.Errorf("evidence must cite the CRD count: %v", fs[0].Evidence)
	}
}

// Cilium GVR ABSENT → legacy 0.45 conditional still stands (the existing test
// TestNoNetworkPolicy_CiliumCRDsNotFlaggedAsFlat already covers this; this pins
// the boundary explicitly).
func TestNoNetworkPolicy_CiliumGVRAbsentKeepsLegacyFallback(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "cilium")},
		Meta:        collectedNetpols(), // no cr: entry, no PresentGVRs
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].Confidence != 0.45 {
		t.Fatalf("absent Cilium GVR must keep the 0.45 fallback, got %+v", fs)
	}
}

func netpolObj(ns, name string) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

// daemonSet builds a minimal DaemonSet for CNI-posture detection tests.
func daemonSet(ns, name string) appsv1.DaemonSet {
	return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

// collectedNetpols marks the NetworkPolicy list as successfully collected so
// the denial guard does not fire.
func collectedNetpols() collect.Meta {
	return collect.Meta{Collected: []string{"deployments", "networkpolicies"}}
}

func TestNoNetworkPolicy(t *testing.T) {
	inv := &collect.Inventory{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "empty"}}, // no workloads → never flagged
		},
		Deployments: []appsv1.Deployment{
			deploy("app", "api", 2, nil),
			deploy("app", "worker", 2, nil),
			deploy("guarded", "db", 1, nil),
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{netpolObj("guarded", "default-deny")},
		Meta:            collectedNetpols(),
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (app only — guarded has a netpol, empty has no workloads), got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.namespace.no-network-policy" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0].Kind != "Namespace" || f.AffectedResources[0].Name != "app" {
		t.Errorf("affected = %+v, want single Namespace/app ref", f.AffectedResources)
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "namespace app") || !strings.Contains(ev, "2 workload") || !strings.Contains(ev, "0 networking.k8s.io/v1 NetworkPolicy") {
		t.Errorf("evidence must cite namespace, workload count, and zero upstream netpols: %v", f.Evidence)
	}
	// Honesty: evidence must NOT assert observed flat allow-all when CNI
	// enforcement is unknown.
	if strings.Contains(ev, "every pod accepts traffic from every other pod") {
		t.Errorf("must not assert observed flat allow-all when CNI enforcement is unknown: %v", f.Evidence)
	}
	if !strings.Contains(f.RemediationYAML, "kind: NetworkPolicy") ||
		!strings.Contains(f.RemediationYAML, "namespace: app") ||
		!strings.Contains(f.RemediationYAML, "Ingress") {
		t.Errorf("remediation must be a default-deny-ingress netpol for the namespace:\n%s", f.RemediationYAML)
	}
	// CONDITIONAL HEADLINE: WhyItMatters must not assert enforcement as
	// guaranteed fact when the CNI is unknown — it must hedge.
	if !strings.Contains(strings.ToLower(f.WhyItMatters), "if the cluster cni") {
		t.Errorf("WhyItMatters must phrase lateral-movement risk conditionally on CNI enforcement: %q", f.WhyItMatters)
	}
	if f.Confidence != 0.8 {
		t.Errorf("unknown-CNI confidence = %v, want 0.8", f.Confidence)
	}
}

func TestNoNetworkPolicy_SystemNamespaces(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("kube-system", "coredns", 2, nil)},
		Meta:        collectedNetpols(),
	}
	if got := len(NoNetworkPolicy{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("system namespace must be skipped by default, got %d findings", got)
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{IncludeSystem: true})
	if len(fs) != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", len(fs))
	}
}

func TestNoNetworkPolicy_StableDistinctIDs(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app-a", "x", 1, nil),
			deploy("app-b", "y", 1, nil),
		},
		Meta: collectedNetpols(),
	}
	first := NoNetworkPolicy{}.Evaluate(inv, Options{})
	second := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("want 2 findings per run, got %d and %d", len(first), len(second))
	}
	if first[0].ID != second[0].ID || first[1].ID != second[1].ID {
		t.Errorf("IDs must be stable across runs: %q/%q vs %q/%q", first[0].ID, first[1].ID, second[0].ID, second[1].ID)
	}
	if first[0].ID == first[1].ID {
		t.Errorf("different namespaces must not share an ID: %q", first[0].ID)
	}
	if !strings.HasPrefix(first[0].ID, "f-") {
		t.Errorf("ID must be f-prefixed: %q", first[0].ID)
	}
}

// DENIAL GUARD: an RBAC-denied / timed-out NetworkPolicy list must NOT produce
// one false positive per namespace. It must produce exactly one informational,
// confidence-0 "not assessed" finding.
func TestNoNetworkPolicy_DeniedListDoesNotFabricate(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{
			deploy("app", "api", 2, nil),
			deploy("payments", "ledger", 3, nil),
			deploy("infra", "thing", 1, nil),
		},
		// NetworkPolicies empty, but the list was DENIED — not observed-zero.
		Meta: collect.Meta{
			Collected: []string{"deployments"},
			Denied:    []string{"networkpolicies: networkpolicies.networking.k8s.io is forbidden"},
		},
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("denied netpol list must yield exactly one not-assessed finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Severity != types.SeverityInfo {
		t.Errorf("not-assessed finding severity = %q, want info", f.Severity)
	}
	if f.Confidence != 0.0 {
		t.Errorf("not-assessed finding confidence = %v, want 0.0 (we observed nothing)", f.Confidence)
	}
	body := strings.ToLower(f.Title + " " + f.Description + " " + strings.Join(f.Evidence, " "))
	if strings.Contains(body, "zero networkpolic") || strings.Contains(body, "0 network") {
		t.Errorf("must NOT assert zero NetworkPolicies on a denied list: %+v", f)
	}
	if !strings.Contains(body, "not assessed") && !strings.Contains(body, "not collect") {
		t.Errorf("not-assessed finding must say so: %+v", f)
	}
}

// When the list also isn't recorded as collected (e.g. a run that never
// reached the step), we must still not fabricate per-namespace findings.
func TestNoNetworkPolicy_NotCollectedIsNotAbsence(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		// Meta records OTHER kinds collected but NOT networkpolicies, and no
		// denial entry — the step simply didn't record success.
		Meta: collect.Meta{Collected: []string{"deployments", "nodes"}},
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].Severity != types.SeverityInfo {
		t.Fatalf("un-confirmed netpol list must yield one info not-assessed finding, got %d: %+v", len(fs), fs)
	}
}

// Cilium/Calico carry segmentation in their own CRDs we don't read — zero
// upstream objects must NOT be reported as flat allow-all. Soften wording,
// lower confidence, and lower severity.
func TestNoNetworkPolicy_CiliumCRDsNotFlaggedAsFlat(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "cilium")},
		Meta:        collectedNetpols(),
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != types.SeverityLow {
		t.Errorf("Cilium namespace severity = %q, want low (segmentation may be in CRDs)", f.Severity)
	}
	if f.Confidence >= 0.8 {
		t.Errorf("Cilium confidence = %v, want lowered (we don't read Cilium CRDs)", f.Confidence)
	}
	body := strings.ToLower(f.Title + " " + f.Description + " " + f.WhyItMatters + " " + strings.Join(f.Evidence, " "))
	if !strings.Contains(body, "cilium") {
		t.Errorf("Cilium finding must name the CNI and its CRDs: %+v", f)
	}
	if strings.Contains(body, "every pod accepts traffic from every other pod") {
		t.Errorf("must NOT assert flat allow-all when a policy-CRD CNI is present: %+v", f)
	}
	if !strings.Contains(strings.ToLower(f.RemediationYAML), "cilium") {
		t.Errorf("remediation YAML should note the Cilium-CRD caveat:\n%s", f.RemediationYAML)
	}
}

func TestNoNetworkPolicy_CalicoCRDsNotFlaggedAsFlat(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "calico-node")},
		Meta:        collectedNetpols(),
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 || fs[0].Confidence >= 0.8 {
		t.Fatalf("Calico namespace must be softened with lowered confidence, got %+v", fs)
	}
}

// AWS VPC CNI with no policy agent silently ignores NetworkPolicy. The
// remediation MUST warn loudly and confidence MUST drop, so we never give
// false security.
func TestNoNetworkPolicy_AWSVPCCNIWarnsNoEnforcement(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "aws-node")},
		Meta:        collectedNetpols(),
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Confidence >= 0.8 {
		t.Errorf("AWS VPC CNI confidence = %v, want lowered (object is silently ignored)", f.Confidence)
	}
	body := strings.ToLower(f.Title + " " + f.Description + " " + f.WhyItMatters)
	mentionsCNI := strings.Contains(body, "aws vpc cni")
	warnsNoEnforcement := strings.Contains(body, "not enforce") || strings.Contains(body, "silently ignored")
	if !mentionsCNI || !warnsNoEnforcement {
		t.Errorf("AWS VPC CNI finding must warn that NetworkPolicy is not enforced: %+v", f)
	}
	if !strings.Contains(strings.ToLower(f.RemediationYAML), "warning") || !strings.Contains(strings.ToLower(f.RemediationYAML), "vpc cni") {
		t.Errorf("remediation YAML must lead with a no-enforcement WARNING:\n%s", f.RemediationYAML)
	}
}

// A policy-enforcing CNI with no special CRD convention (Weave) is a real
// allow-all gap: keep the standard medium/0.8 calibration.
func TestNoNetworkPolicy_EnforcingCNIKeepsStandardCalibration(t *testing.T) {
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{deploy("app", "api", 2, nil)},
		DaemonSets:  []appsv1.DaemonSet{daemonSet("kube-system", "weave-net")},
		Meta:        collectedNetpols(),
	}
	fs := NoNetworkPolicy{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != types.SeverityMedium || fs[0].Confidence != 0.8 {
		t.Errorf("enforcing-CNI (Weave) should keep medium/0.8, got severity=%q conf=%v", fs[0].Severity, fs[0].Confidence)
	}
}
