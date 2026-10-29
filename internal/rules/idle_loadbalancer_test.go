package rules

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// regionNode builds a node carrying the region label the rule reads. Region ""
// means "no label" so the unknown-region path can be exercised. It carries NO
// providerID, so the dollar gate (confirmedCloudProvider) treats it as an
// unconfirmed cloud — use cloudNode for the priced path.
func regionNode(name, region string) corev1.Node {
	labels := map[string]string{}
	if region != "" {
		labels["topology.kubernetes.io/region"] = region
	}
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// cloudNode builds a node carrying an authoritative providerID scheme so the
// dollar gate confirms a managed cloud LB. scheme is "aws://" / "azure://" /
// "gce://".
func cloudNode(name, region, providerIDScheme string) corev1.Node {
	n := regionNode(name, region)
	n.Spec.ProviderID = providerIDScheme + "some/instance/id"
	return n
}

func lbService(ns, name string, selector map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: selector,
		},
	}
}

// provisionedLBService is an LB Service that the cloud-controller has assigned
// an address to (status.loadBalancer.ingress non-empty) — i.e. a real billed
// LB exists. The dollar gate prices only provisioned LBs.
func provisionedLBService(ns, name string, selector map[string]string) corev1.Service {
	svc := lbService(ns, name, selector)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "lb-123.example.elb.amazonaws.com"}}
	return svc
}

// runningPod is a pod with labels in a namespace, used to back a Service.
func runningPod(ns, name string, labels map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
	}
}

func TestIdleLoadBalancer_FlaggedWithDollarImpact(t *testing.T) {
	inv := &collect.Inventory{
		// aws:// providerID confirms a managed cloud LB; provisioned ingress
		// confirms the LB actually exists — both gates the dollar requires.
		Nodes: []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{
			provisionedLBService("app", "orphan-lb", map[string]string{"app": "ghost"}),
		},
		// pods exist, but none match selector app=ghost
		Pods: []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (orphan-lb), got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "k8s.cost.idle-loadbalancer" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if f.Category != "cost" {
		t.Errorf("category = %q, want cost", f.Category)
	}
	if f.Severity != "medium" {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.EstimatedEffort != "low" {
		t.Errorf("effort = %q, want low", f.EstimatedEffort)
	}
	wantUSD, ok := pricing.NLBMonthlyUSD("eu-central-1")
	if !ok {
		t.Fatal("test precondition: eu-central-1 NLB price must be known")
	}
	if f.DollarImpactMonthly != wantUSD {
		t.Errorf("dollar impact = %v, want %v", f.DollarImpactMonthly, wantUSD)
	}
	ev := strings.Join(f.Evidence, " ")
	// Honest wording: the rule never reads Pod phase, so it claims "0 pods (any
	// phase)", NOT "0 running pods".
	if !strings.Contains(ev, "app/orphan-lb") || !strings.Contains(ev, "LoadBalancer") || !strings.Contains(ev, "0 pods (any phase)") {
		t.Errorf("evidence must cite ns/name, type, and zero matching pods (any phase): %v", f.Evidence)
	}
	if strings.Contains(ev, "0 running pods") {
		t.Errorf("evidence must NOT claim 'running' — phase is never checked: %v", f.Evidence)
	}
	// The dollar is the FIXED per-LB base only (excludes LCU/rule/data-processing).
	// The evidence must frame it as the base, and must NOT overclaim it as a
	// "lower bound" / "at least" realizable saving (that wording was inverted —
	// the base is the ceiling of what one Service can free, not a floor).
	if !strings.Contains(ev, "base price") {
		t.Errorf("evidence must frame the dollar as the per-LB base price: %v", f.Evidence)
	}
	if assertNoOverclaim(t, ev); strings.Contains(strings.ToLower(ev), "lower bound") {
		t.Errorf("public-LB evidence must NOT claim a lower bound / realizable-at-least saving: %v", f.Evidence)
	}
	if !strings.Contains(f.RemediationCommand, "kubectl -n app delete service orphan-lb") {
		t.Errorf("remediation command = %q", f.RemediationCommand)
	}
	// The delete is destructive, so it must ship as commented documentation —
	// never a one-click copy button (see SafeRemediationCommand / V1-Q02).
	if !strings.HasPrefix(strings.TrimSpace(f.RemediationCommand), "#") {
		t.Errorf("destructive remediation command must be comment-prefixed: %q", f.RemediationCommand)
	}
	if safe, reason := SafeRemediationCommand(f.RemediationCommand); !safe {
		t.Errorf("idle-lb remediation command must pass the safety gate, got unsafe: %s (%q)", reason, f.RemediationCommand)
	}
	if !strings.Contains(strings.ToLower(f.Description), "verify") {
		t.Errorf("description must caution to verify it's truly unused: %q", f.Description)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0].Kind != "Service" || f.AffectedResources[0].Name != "orphan-lb" {
		t.Errorf("affected = %+v, want single Service/orphan-lb", f.AffectedResources)
	}
}

func TestIdleLoadBalancer_BackedServiceNotFlagged(t *testing.T) {
	inv := &collect.Inventory{
		Nodes: []corev1.Node{regionNode("n1", "eu-central-1")},
		Services: []corev1.Service{
			lbService("app", "live-lb", map[string]string{"app": "live"}),
		},
		Pods: []corev1.Pod{runningPod("app", "live-0", map[string]string{"app": "live"})},
	}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("LB with matching pods must not be flagged, got %d findings", got)
	}
}

func TestIdleLoadBalancer_NonLBServiceSkipped(t *testing.T) {
	clusterIP := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "internal", Namespace: "app"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "ghost"}},
	}
	inv := &collect.Inventory{
		Nodes:    []corev1.Node{regionNode("n1", "eu-central-1")},
		Services: []corev1.Service{clusterIP},
	}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("non-LoadBalancer service must be skipped, got %d findings", got)
	}
}

func TestIdleLoadBalancer_EmptySelectorSkipped(t *testing.T) {
	// Empty/nil selector → cannot confirm idle (could be headless / manual
	// Endpoints). Must be skipped, not flagged.
	inv := &collect.Inventory{
		Nodes: []corev1.Node{regionNode("n1", "eu-central-1")},
		Services: []corev1.Service{
			lbService("app", "no-selector", nil),
			lbService("app", "empty-selector", map[string]string{}),
		},
	}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("LB with empty/nil selector must be skipped, got %d findings", got)
	}
}

func TestIdleLoadBalancer_UnknownRegionZeroDollarWithNote(t *testing.T) {
	inv := &collect.Inventory{
		// node has an aws:// providerID (cloud confirmed) but no region label →
		// price unknown, so dollar must be 0 with a price-unknown note.
		Nodes: []corev1.Node{cloudNode("n1", "", "aws://")},
		Services: []corev1.Service{
			provisionedLBService("app", "orphan-lb", map[string]string{"app": "ghost"}),
		},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("idle LB still flagged when region unknown, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("unknown region → dollar impact 0, got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	if !strings.Contains(strings.ToLower(ev), "price unknown") {
		t.Errorf("evidence must note price unknown: %v", fs[0].Evidence)
	}
}

func TestIdleLoadBalancer_AzureDollarImpact(t *testing.T) {
	// AKS cluster with an azure:// providerID (managed cloud confirmed) and a
	// provisioned LB: the dollar impact must be the Azure Standard LB base.
	inv := &collect.Inventory{
		Nodes: []corev1.Node{cloudNode("n1", "westus3", "azure://")},
		Services: []corev1.Service{
			provisionedLBService("app", "orphan-lb", map[string]string{"app": "ghost"}),
		},
		Pods: []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	want, ok := pricing.LBMonthlyUSD("azure", "westus3")
	if !ok {
		t.Fatal("test precondition: azure LB base must be known")
	}
	if fs[0].DollarImpactMonthly != want {
		t.Errorf("dollar impact = %v, want azure LB base %v", fs[0].DollarImpactMonthly, want)
	}
	if fs[0].DollarImpactMonthly <= 0 {
		t.Errorf("AKS idle LB must have positive dollar impact, got %v", fs[0].DollarImpactMonthly)
	}
	// This is a PUBLIC Azure LB (no internal annotation, no private ingress IP),
	// so it is priced — but the wording must not overclaim a lower-bound saving.
	assertNoOverclaim(t, strings.Join(fs[0].Evidence, " "))
}

// assertNoOverclaim fails the test if the evidence resurrects the inverted
// "lower bound / at least / realizable saving is at least" framing that
// double-counted a fixed per-LB base as a floor of realizable savings.
func assertNoOverclaim(t *testing.T, ev string) {
	t.Helper()
	low := strings.ToLower(ev)
	for _, banned := range []string{"lower bound", "at least", "realizable saving is at least"} {
		if strings.Contains(low, banned) {
			t.Errorf("evidence must not overclaim with %q: %s", banned, ev)
		}
	}
}

// internalAzureLBService is a provisioned internal Azure LB: it carries the
// azure-load-balancer-internal=true annotation, so it shares the cluster's one
// internal Standard LB and must be billed marginally ($0), not at the full base.
func internalAzureLBService(ns, name string, selector map[string]string) corev1.Service {
	svc := provisionedLBService(ns, name, selector)
	svc.Annotations = map[string]string{
		"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
	}
	return svc
}

// TestIdleLoadBalancer_InternalAzureLBMarginalDollar pins the overclaim fix:
// an internal Azure LB (shared cluster Standard LB) must NOT be billed the full
// per-LB base. Deleting one idle internal Service frees at most ~1 rule
// (marginal); with no per-rule price modelled the dollar is $0, and the
// evidence must say "marginal" / "fixed per cluster", never "lower bound".
func TestIdleLoadBalancer_InternalAzureLBMarginalDollar(t *testing.T) {
	inv := &collect.Inventory{
		Nodes: []corev1.Node{cloudNode("n1", "westus3", "azure://")},
		Services: []corev1.Service{
			internalAzureLBService("app", "internal-lb", map[string]string{"app": "ghost"}),
		},
		Pods: []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("internal idle LB still flagged, got %d", len(fs))
	}
	// The full base is positive; assert we did NOT bill it.
	base, ok := pricing.LBMonthlyUSD("azure", "westus3")
	if !ok || base <= 0 {
		t.Fatal("test precondition: azure LB base must be a known positive number")
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("internal LB → marginal/0 dollar, must NOT bill full base %v, got %v", base, fs[0].DollarImpactMonthly)
	}
	ev := strings.Join(fs[0].Evidence, " ")
	low := strings.ToLower(ev)
	if !strings.Contains(low, "internal lb") {
		t.Errorf("evidence must identify the LB as internal: %v", fs[0].Evidence)
	}
	if !strings.Contains(low, "marginal") || !strings.Contains(low, "fixed per cluster") {
		t.Errorf("evidence must frame the charge as marginal / fixed-per-cluster: %v", fs[0].Evidence)
	}
	assertNoOverclaim(t, ev)
}

// TestIdleLoadBalancer_InternalByPrivateIPMarginalDollar pins that an LB with a
// private RFC1918 ingress IP (and no annotation) is also recognized as internal
// and billed marginally ($0), not at the full base.
func TestIdleLoadBalancer_InternalByPrivateIPMarginalDollar(t *testing.T) {
	svc := lbService("app", "private-ip-lb", map[string]string{"app": "ghost"})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.4.7"}}
	inv := &collect.Inventory{
		Nodes:    []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{svc},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("internal-by-IP idle LB still flagged, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("private-IP internal LB → marginal/0 dollar, got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	if !strings.Contains(ev, "rfc1918") && !strings.Contains(ev, "private") {
		t.Errorf("evidence must cite the private/RFC1918 ingress IP: %v", fs[0].Evidence)
	}
	// The address itself never: redaction tokenises names, not addresses.
	if strings.Contains(ev, "10.0.4.7") {
		t.Errorf("evidence prints the ingress address: %v", fs[0].Evidence)
	}
	assertNoOverclaim(t, ev)
}

// TestIdleLoadBalancer_PublicIngressIPStillPriced guards the inverse: an LB with
// a PUBLIC (non-RFC1918) ingress IP and no internal annotation is a real public
// LB and must still be priced at the base — the internal detection must not
// over-trigger and zero out legitimate public-LB savings.
func TestIdleLoadBalancer_PublicIngressIPStillPriced(t *testing.T) {
	svc := lbService("app", "public-ip-lb", map[string]string{"app": "ghost"})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "52.10.20.30"}}
	inv := &collect.Inventory{
		Nodes:    []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{svc},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("public idle LB flagged, got %d", len(fs))
	}
	want, ok := pricing.LBMonthlyUSD("aws", "eu-central-1")
	if !ok {
		t.Fatal("test precondition: aws eu-central-1 LB base must be known")
	}
	if fs[0].DollarImpactMonthly != want {
		t.Errorf("public LB must be priced at base %v, got %v", want, fs[0].DollarImpactMonthly)
	}
	assertNoOverclaim(t, strings.Join(fs[0].Evidence, " "))
}

func TestIdleLoadBalancer_SystemNamespaceSkipped(t *testing.T) {
	inv := &collect.Inventory{
		Nodes: []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{
			provisionedLBService("kube-system", "sys-lb", map[string]string{"app": "ghost"}),
		},
	}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("system namespace LB skipped by default, got %d findings", got)
	}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Fatalf("with IncludeSystem want 1 finding, got %d", got)
	}
}

// TestIdleLoadBalancer_NoCloudProviderIDWithheldDollar pins the
// dangerous-recommendation fix: on a cluster with no authoritative cloud
// providerID (bare-metal / MetalLB / kube-vip), the idle finding still ships
// but the dollar is WITHHELD — never a fabricated AWS NLB price — with a
// "cloud LB not confirmed" note. node_headroom's providerFromNodes would have
// defaulted this to "aws".
func TestIdleLoadBalancer_NoCloudProviderIDWithheldDollar(t *testing.T) {
	inv := &collect.Inventory{
		// region label present, but NO providerID → cloud unconfirmed.
		Nodes: []corev1.Node{regionNode("n1", "eu-central-1")},
		Services: []corev1.Service{
			provisionedLBService("app", "metallb-vip", map[string]string{"app": "ghost"}),
		},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("idle LB still flagged when cloud unconfirmed, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("unconfirmed cloud → dollar must be withheld (0), got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	if !strings.Contains(ev, "cloud lb not confirmed") {
		t.Errorf("evidence must note the cloud LB was not confirmed: %v", fs[0].Evidence)
	}
}

// TestIdleLoadBalancer_CustomLoadBalancerClassWithheldDollar pins that a
// Service pinning a non-cloud spec.loadBalancerClass (e.g. MetalLB) gets the
// dollar withheld even on a cluster that otherwise has a cloud providerID.
func TestIdleLoadBalancer_CustomLoadBalancerClassWithheldDollar(t *testing.T) {
	metallb := "metallb.universe.tf/metallb"
	svc := provisionedLBService("app", "custom-class-lb", map[string]string{"app": "ghost"})
	svc.Spec.LoadBalancerClass = &metallb
	inv := &collect.Inventory{
		Nodes:    []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{svc},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("non-cloud loadBalancerClass → dollar withheld (0), got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	if !strings.Contains(ev, "non-cloud") {
		t.Errorf("evidence must note the non-cloud loadBalancerClass: %v", fs[0].Evidence)
	}
}

// TestIdleLoadBalancer_UnprovisionedLBZeroDollar pins the false-positive fix:
// a Service whose status.loadBalancer.ingress is empty (LB never provisioned —
// pending/failed) is not yet billed, so the dollar must be 0 with a
// not-provisioned note even on a confirmed cloud + known region.
func TestIdleLoadBalancer_UnprovisionedLBZeroDollar(t *testing.T) {
	inv := &collect.Inventory{
		Nodes: []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{
			// lbService leaves Status.LoadBalancer.Ingress empty → unprovisioned.
			lbService("app", "pending-lb", map[string]string{"app": "ghost"}),
		},
	}
	fs := IdleLoadBalancer{}.Evaluate(inv, Options{})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].DollarImpactMonthly != 0 {
		t.Errorf("unprovisioned LB → no charge yet, dollar must be 0, got %v", fs[0].DollarImpactMonthly)
	}
	ev := strings.ToLower(strings.Join(fs[0].Evidence, " "))
	if !strings.Contains(ev, "not been provisioned") {
		t.Errorf("evidence must note the LB is not provisioned: %v", fs[0].Evidence)
	}
}

// TestIdleLoadBalancer_FreshlyCreatedSkipped pins the missing-caveat fix: a
// Service created within the grace window of the snapshot races its rollout and
// must be skipped rather than flagged as an orphan.
func TestIdleLoadBalancer_FreshlyCreatedSkipped(t *testing.T) {
	now := time.Now()
	svc := provisionedLBService("app", "fresh-lb", map[string]string{"app": "ghost"})
	svc.CreationTimestamp = metav1.NewTime(now.Add(-2 * time.Minute)) // 2m old
	inv := &collect.Inventory{
		Nodes:    []corev1.Node{cloudNode("n1", "eu-central-1", "aws://")},
		Services: []corev1.Service{svc},
	}
	inv.Meta.StartedAt = now
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 0 {
		t.Fatalf("freshly-created LB (within grace window) must be skipped, got %d findings", got)
	}

	// An older Service (well past the grace window) is still flagged.
	svc.CreationTimestamp = metav1.NewTime(now.Add(-2 * time.Hour))
	inv.Services = []corev1.Service{svc}
	if got := len(IdleLoadBalancer{}.Evaluate(inv, Options{})); got != 1 {
		t.Fatalf("old idle LB past grace window must still be flagged, got %d findings", got)
	}
}

// TestIdleLoadBalancer_VetoedByPublishedEndpoints — EndpointSlices are used here only to REMOVE a
// finding, never to add one.
//
// A Service whose selector matches nothing but whose slices publish entries has working routing:
// the entries may be written by a mesh, by a manual process, or by anything else that is not the
// selector model. Before slices were collected this rule had no way to see that and billed the
// operator an unqualified "$X wasted, nothing behind it". The finding carries the only real dollar
// figure in the reliability/cost set, so a false positive here is expensive in credibility.
func TestIdleLoadBalancer_VetoedByPublishedEndpoints(t *testing.T) {
	inv := idleLBInventoryWithSlices(true)
	if got := len((IdleLoadBalancer{}).Evaluate(inv, Options{IncludeSystem: true})); got != 0 {
		t.Errorf("got %d findings; a Service with published endpoint entries is not idle", got)
	}
}

// TestIdleLoadBalancer_StillFiresWhenSlicesArePublishedEmpty — the reconciler writes a PLACEHOLDER
// slice with no entries for a selector Service with no eligible pods, so the EXISTENCE of a slice
// proves nothing. Only non-empty entries may veto.
func TestIdleLoadBalancer_StillFiresWhenSlicesArePublishedEmpty(t *testing.T) {
	inv := idleLBInventoryWithSlices(false)
	if got := len((IdleLoadBalancer{}).Evaluate(inv, Options{IncludeSystem: true})); got != 1 {
		t.Errorf("got %d findings, want 1 — an empty placeholder slice is not a backend", got)
	}
}

// TestIdleLoadBalancer_UnchangedWhenSlicesWereNotCollected — on a cluster where the endpointslices
// list was denied, the rule must behave exactly as it did before slices existed, and must not assert
// anything about endpoints.
func TestIdleLoadBalancer_UnchangedWhenSlicesWereNotCollected(t *testing.T) {
	inv := idleLBInventoryWithSlices(true) // slices present in the struct...
	inv.Meta.Collected = []string{"services", "pods"}
	inv.Meta.Denied = []string{"endpointslices: forbidden"} // ...but not readable

	findings := (IdleLoadBalancer{}).Evaluate(inv, Options{IncludeSystem: true})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 — the rule reverts to its pre-slice behaviour", len(findings))
	}
	blob := strings.Join(findings[0].Evidence, " ") + findings[0].Description
	if strings.Contains(strings.ToLower(blob), "endpoint entr") {
		t.Errorf("the rule asserted something about endpoints it could not read:\n%s", blob)
	}
}

func idleLBInventoryWithSlices(withEntries bool) *collect.Inventory {
	old := metav1.NewTime(time.Now().Add(-48 * time.Hour))
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", CreationTimestamp: old},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: map[string]string{"app": "web"},
			Ports:    []corev1.ServicePort{{Port: 80}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "10.0.0.1"}}},
		},
	}
	slice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc", Namespace: "shop",
			Labels: map[string]string{discoveryv1.LabelServiceName: "web"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	if withEntries {
		ready := true
		slice.Endpoints = []discoveryv1.Endpoint{{
			Addresses:  []string{"10.1.2.3"},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "mesh-managed", UID: "uid-1"},
		}}
	}
	return &collect.Inventory{
		Namespaces:     []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}},
		Services:       []corev1.Service{svc},
		EndpointSlices: []discoveryv1.EndpointSlice{slice},
		Meta: collect.Meta{
			Collected:     []string{"services", "pods", "endpointslices"},
			ServerVersion: "v1.30.2",
		},
	}
}

// A ZERO THIS RULE CHOSE MUST NOT READ AS A ZERO IT COULD NOT FIND.
//
// FOUND ON A LIVE AKS CLUSTER, on nine findings of a 1,612-finding reading. All nine were idle INTERNAL
// load balancers, all nine carried $0 — correctly, and for a reason the evidence spells out at length:
// internal Services share one cluster-wide Standard LB whose base charge is fixed per cluster, so billing
// each idle one the full base would double-count. And every surface reported them as **unpriced**.
//
// `unpriced` has a definition, in internal/types/price_basis.go: "this finding has a cost dimension and we
// COULD NOT PRICE IT — no rate for the region, no rate for the instance type, or no usage reading to size
// it from." None of that happened. `pricing.LBMonthlyUSD("azure", "westus3")` returns 18.25; the rule asked
// nothing and chose zero.
//
// The cause is that this rule never declared its basis, so `pipeline.classifyPriceBasis` derived one — and
// its own comment names this exact case as the one derivation cannot see: "A rule that sets the field
// explicitly wins. That matters for the case this derivation cannot see — a cost rule that priced something
// at a true zero, which is neither unpriced nor non-cost." Two other cost rules already do this
// (gp2_to_gp3.go, unattached_volumes.go, whose comment reads "the two withheld cases are DIFFERENT, which
// is what PriceBasis is for"). This one had the precedent and not the line.
//
// FOUR BRANCHES, THREE ANSWERS. The table is the point: a reader who is told "could not price" learns
// something false about a deliberate zero, and a reader told "priced" about a withheld one learns something
// false in the other direction.
func TestIdleLoadBalancer_EveryZeroSaysWhichKindOfZeroItIs(t *testing.T) {
	base, ok := pricing.LBMonthlyUSD("azure", "westus3")
	if !ok || base <= 0 {
		t.Fatal("test precondition: azure LB base must be a known positive number, or this table proves nothing")
	}

	cases := []struct {
		name      string
		inv       *collect.Inventory
		wantZero  bool
		wantBasis types.PriceBasis
		why       string
	}{
		{
			name: "an internal LB: priced, at a true zero, on purpose",
			inv: &collect.Inventory{
				Nodes:    []corev1.Node{cloudNode("n1", "westus3", "azure://")},
				Services: []corev1.Service{internalAzureLBService("app", "internal-lb", map[string]string{"app": "ghost"})},
				Pods:     []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
			},
			wantZero:  true,
			wantBasis: types.PricePriced,
			why:       "the region IS in the table and the rule chose zero because the marginal cost of one idle internal Service is not a full LB base",
		},
		{
			name: "an external LB in a priced region: priced, with a figure",
			inv: &collect.Inventory{
				Nodes:    []corev1.Node{cloudNode("n1", "westus3", "azure://")},
				Services: []corev1.Service{provisionedLBService("app", "public-lb", map[string]string{"app": "ghost"})},
				Pods:     []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
			},
			wantZero:  false,
			wantBasis: types.PricePriced,
			why:       "a rate was found and applied",
		},
		{
			name: "no cloud providerID on any node: unpriced, withheld",
			inv: &collect.Inventory{
				Nodes:    []corev1.Node{regionNode("n1", "westus3")},
				Services: []corev1.Service{provisionedLBService("app", "public-lb", map[string]string{"app": "ghost"})},
				Pods:     []corev1.Pod{runningPod("app", "other-0", map[string]string{"app": "live"})},
			},
			wantZero:  true,
			wantBasis: types.PriceUnpriced,
			why:       "the rule could not confirm a cloud LB exists, so it withheld a figure it does not have",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := IdleLoadBalancer{}.Evaluate(tc.inv, Options{})
			if len(fs) != 1 {
				t.Fatalf("expected exactly one finding, got %d", len(fs))
			}
			f := fs[0]
			if got := f.DollarImpactMonthly == 0; got != tc.wantZero {
				t.Errorf("dollar is %v, wantZero=%v", f.DollarImpactMonthly, tc.wantZero)
			}
			if f.PriceBasis != tc.wantBasis {
				t.Errorf("price basis is %q, want %q — %s.\nA zero with the wrong basis tells a reader "+
					"either \"we could not price this\" about a deliberate figure, or \"priced\" about a "+
					"withheld one. Declare it on the finding; pipeline.classifyPriceBasis cannot see which "+
					"kind of zero this is.", f.PriceBasis, tc.wantBasis, tc.why)
			}
		})
	}
}
