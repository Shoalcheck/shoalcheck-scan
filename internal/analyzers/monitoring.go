package analyzers

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// monitoring.go — THE ONE COMPONENT THAT CANNOT AUDIT ITSELF.
//
// Census: `docs/qa/2026-08-29-sweep0-field-diff.md` §10 (Addendum B). Every other analyzer in this registry
// covers a component whose own health surface still works when it is misconfigured. A monitoring stack is
// the exception: the thing that would report its failure IS the thing that failed. Nothing pages you when
// your pager is wrong.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE THREE REFUSALS, from §10.3, and they are the reason this file is short
//
//	NEVER "YOUR ALERTS DO NOT WORK". A route naming a missing receiver is a STRUCTURAL fact. Whether
//	anything ever fired is not visible, and the gap between the two is the same gap as between *published
//	in an EndpointSlice* and *served a request*.
//
//	NEVER "YOU ARE NOT MONITORING X". We see what is CONFIGURED, not what is SCRAPED. The target list
//	lives in the Prometheus process, not in a CRD, and a ServiceMonitor is an invitation rather than a
//	subscription.
//
//	NO MONITORING CRDs MEANS SILENCE, never "you have no monitoring". Each analyzer gates on PresentGVRs
//	exactly like every other one here, so an absent operator produces nothing — reporting the absence as a
//	fact is the defect B-130 was.
//
// AND A FOURTH, ADDED HERE: this is not the usage resolver. internal/prom answers *"can WE get numbers"*;
// this answers *"is THEIR monitoring sound"*. Two different questions over the same objects, and mixing
// them would make both wordings vague.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHY FOUR ANALYZERS AND NOT ONE
//
// hasAllGVRs requires EVERY declared GVR to be present, so one analyzer declaring servicemonitors,
// podmonitors, alertmanagerconfigs and prometheuses would fall silent on any cluster missing one of them.
// The prometheus-operator CRD bundle does ship them together, and "in practice they arrive together" is
// exactly the class of assumption that has cost this project a defect each time it was made. One analyzer
// per CRD, each gated on what it actually reads.
//
// DELIBERATELY NOT BUILT: whether a ServiceMonitor is SELECTED BY any Prometheus (spec.serviceMonitorSelector
// plus serviceMonitorNamespaceSelector, and the operator's own defaulting when both are nil, which differs
// by chart version). A ServiceMonitor that selects Services correctly and is picked up by no Prometheus is a
// real failure and a common one — it needs the Prometheus CR, a second selector layer and knowledge of the
// installed chart's defaults to state soundly, and stating it unsoundly would produce the loudest possible
// false positive on the commonest install.

func monitoringGVR(version, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: version, Resource: resource}
}

// selectorFrom converts an unstructured selector map into a labels.Selector.
//
// The empty-selector case is the one that matters and it is inverted from intuition: a metav1.LabelSelector
// with no matchLabels and no matchExpressions selects EVERYTHING, which is what Kubernetes means by it and
// what the prometheus-operator acts on. Treating it as "matches nothing" would make this file report every
// catch-all ServiceMonitor in existence.
func selectorFrom(obj map[string]interface{}, fields ...string) (labels.Selector, bool) {
	raw, found, err := unstructured.NestedMap(obj, fields...)
	if err != nil {
		return nil, false
	}
	if !found {
		// An ABSENT selector is not an empty one. spec.selector is required on a ServiceMonitor, so its
		// absence means an object we do not understand rather than a catch-all, and judging it would be
		// judging our own parse.
		return nil, false
	}
	var ls metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &ls); err != nil {
		return nil, false
	}
	sel, err := metav1.LabelSelectorAsSelector(&ls)
	if err != nil {
		return nil, false
	}
	return sel, true
}

// namespaceScope reports which namespaces a monitor's namespaceSelector covers: (nil, true) for every
// namespace, or an explicit set. The default — neither `any` nor `matchNames` — is the monitor's OWN
// namespace, which is the prometheus-operator's rule and not a guess.
func namespaceScope(obj map[string]interface{}, ownNamespace string) (set map[string]bool, all bool) {
	any, _, _ := unstructured.NestedBool(obj, "spec", "namespaceSelector", "any")
	if any {
		return nil, true
	}
	names, found, _ := unstructured.NestedStringSlice(obj, "spec", "namespaceSelector", "matchNames")
	if found && len(names) > 0 {
		set = map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return set, false
	}
	return map[string]bool{ownNamespace: true}, false
}

func inScope(set map[string]bool, all bool, ns string) bool {
	return all || set[ns]
}

// ── ServiceMonitor: a selector that selects no Service ───────────────────────────────────────────

// ServiceMonitorTargets reports ServiceMonitors whose selector matches no Service this reading saw.
type ServiceMonitorTargets struct{}

func (ServiceMonitorTargets) ID() string { return "stack.monitoring.servicemonitor" }
func (ServiceMonitorTargets) FindingIDs() []string {
	return []string{"stack.monitoring.servicemonitor-selects-nothing"}
}
func (ServiceMonitorTargets) Version() string { return "1.0.0" }
func (ServiceMonitorTargets) RequiredGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{monitoringGVR("v1", "servicemonitors")}
}

// RequiredCoreKinds — the claim is about Services, so a reading that could not list Services cannot make it.
func (ServiceMonitorTargets) RequiredCoreKinds() []string { return []string{"services"} }

func (a ServiceMonitorTargets) Analyze(inv *collect.Inventory) []types.Finding {
	if !listSucceeded(inv, "monitoring.coreos.com", "servicemonitors") {
		return nil
	}
	// THE DENIAL GUARD, AND IT IS WHOLE-RULE. The claim is "this selector matches no Service", so a reading
	// that was refused the Services list has no basis for it at all — not a weaker version of it. An
	// unmatched selector and an unread namespace look identical from here.
	if !collect.Observed(inv, "services") {
		return nil
	}
	var out []types.Finding
	for _, sm := range stackObjects(inv, "monitoring.coreos.com", "servicemonitors") {
		ns, _, _ := unstructured.NestedString(sm.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(sm.Object, "metadata", "name")
		sel, ok := selectorFrom(sm.Object, "spec", "selector")
		if !ok {
			continue
		}
		scope, all := namespaceScope(sm.Object, ns)
		matched, candidates := 0, 0
		for i := range inv.Services {
			svc := &inv.Services[i]
			if !inScope(scope, all, svc.Namespace) {
				continue
			}
			candidates++
			if sel.Matches(labels.Set(svc.Labels)) {
				matched++
			}
		}
		if matched > 0 {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID("stack.monitoring.servicemonitor-selects-nothing", "ServiceMonitor", ns, name),
			IDBasis:     &types.ResourceRef{Kind: "ServiceMonitor", Namespace: ns, Name: name},
			RuleID:      "stack.monitoring.servicemonitor-selects-nothing",
			RuleVersion: a.Version(),
			Title:       fmt.Sprintf("ServiceMonitor %s/%s selects no Service", ns, name),
			Description: fmt.Sprintf("ServiceMonitor %s/%s declares a label selector that matches none of "+
				"the %s in the namespaces it covers. A ServiceMonitor is how a workload asks to "+
				"be scraped; a selector matching nothing is a request with no subject.",
				ns, name, nWord(candidates, "Service", "Services")),
			WhyItMatters: "A monitoring stack is the one component that cannot report its own gaps — the " +
				"thing that would tell you a scrape is missing is the thing that is missing it. A " +
				"ServiceMonitor with no match is silent in exactly the same way as one that works.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: spec.selector is %q", ns, name, sel.String()),
				fmt.Sprintf("namespaces covered: %s", scopeText(scope, all)),
				fmt.Sprintf("%s in scope in this reading, %d matched", nWord(candidates, "Service", "Services"), matched),
				"this states what is CONFIGURED, not what is scraped: the target list lives in the " +
					"Prometheus process and is not readable from any object here",
				"whether a Prometheus selects this ServiceMonitor at all is a second question this " +
					"reading does not answer",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "ServiceMonitor", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func scopeText(set map[string]bool, all bool) string {
	if all {
		return "every namespace (spec.namespaceSelector.any=true)"
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ── PodMonitor: a selector that selects no Pod ───────────────────────────────────────────────────

// PodMonitorTargets reports PodMonitors whose selector matches no Pod this reading saw.
type PodMonitorTargets struct{}

func (PodMonitorTargets) ID() string { return "stack.monitoring.podmonitor" }
func (PodMonitorTargets) FindingIDs() []string {
	return []string{"stack.monitoring.podmonitor-selects-nothing"}
}
func (PodMonitorTargets) Version() string { return "1.0.0" }
func (PodMonitorTargets) RequiredGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{monitoringGVR("v1", "podmonitors")}
}
func (PodMonitorTargets) RequiredCoreKinds() []string { return []string{"pods"} }

func (a PodMonitorTargets) Analyze(inv *collect.Inventory) []types.Finding {
	if !listSucceeded(inv, "monitoring.coreos.com", "podmonitors") || !collect.Observed(inv, "pods") {
		return nil
	}
	var out []types.Finding
	for _, pm := range stackObjects(inv, "monitoring.coreos.com", "podmonitors") {
		ns, _, _ := unstructured.NestedString(pm.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(pm.Object, "metadata", "name")
		sel, ok := selectorFrom(pm.Object, "spec", "selector")
		if !ok {
			continue
		}
		scope, all := namespaceScope(pm.Object, ns)
		matched, candidates := 0, 0
		for i := range inv.Pods {
			p := &inv.Pods[i]
			if !inScope(scope, all, p.Namespace) {
				continue
			}
			candidates++
			if sel.Matches(labels.Set(p.Labels)) {
				matched++
			}
		}
		if matched > 0 {
			continue
		}
		out = append(out, types.Finding{
			ID:          findingID("stack.monitoring.podmonitor-selects-nothing", "PodMonitor", ns, name),
			IDBasis:     &types.ResourceRef{Kind: "PodMonitor", Namespace: ns, Name: name},
			RuleID:      "stack.monitoring.podmonitor-selects-nothing",
			RuleVersion: a.Version(),
			Title:       fmt.Sprintf("PodMonitor %s/%s selects no Pod", ns, name),
			Description: fmt.Sprintf("PodMonitor %s/%s declares a label selector that matches none of the "+
				"%s running in the namespaces it covers.", ns, name, nWord(candidates, "Pod", "Pods")),
			WhyItMatters: "A PodMonitor that matches nothing produces no scrape and no error. It reads as " +
				"configured monitoring in every review of the manifests.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: spec.selector is %q", ns, name, sel.String()),
				fmt.Sprintf("namespaces covered: %s", scopeText(scope, all)),
				fmt.Sprintf("%s in scope in this reading, %d matched", nWord(candidates, "Pod", "Pods"), matched),
				"a pod list is a moment: a selector matching nothing NOW may match a workload that is " +
					"scaled to zero or between rollouts, and this reading cannot tell those apart",
				"this states what is CONFIGURED, not what is scraped",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryConfig,
			AffectedResources: []types.ResourceRef{{Kind: "PodMonitor", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        0.8,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ── AlertmanagerConfig: a route to a receiver that is not declared ───────────────────────────────

// AlertRouting reports AlertmanagerConfig objects whose routes name receivers the same object does not
// declare, and objects that declare no receiver at all.
//
// SCOPE, AND IT IS NARROWER THAN THE KIND'S NAME SUGGESTS. Alertmanager's MAIN configuration lives in a
// Secret (`alertmanager-<name>`), which this product refuses to read by name. So a cluster configured
// entirely through that Secret has routing this reading cannot see, and every sentence here is about ONE
// AlertmanagerConfig object rather than about the Alertmanager. "This cluster has no alert receiver" is not
// a claim any reading without the Secret can make, and it is not made.
type AlertRouting struct{}

func (AlertRouting) ID() string { return "stack.monitoring.alertrouting" }
func (AlertRouting) FindingIDs() []string {
	return []string{"stack.monitoring.alert-route-receiver-missing"}
}
func (AlertRouting) Version() string { return "1.0.0" }
func (AlertRouting) RequiredGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{monitoringGVR("v1alpha1", "alertmanagerconfigs")}
}

func (a AlertRouting) Analyze(inv *collect.Inventory) []types.Finding {
	if !listSucceeded(inv, "monitoring.coreos.com", "alertmanagerconfigs") {
		return nil
	}
	var out []types.Finding
	for _, ac := range stackObjects(inv, "monitoring.coreos.com", "alertmanagerconfigs") {
		ns, _, _ := unstructured.NestedString(ac.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(ac.Object, "metadata", "name")

		declared := map[string]bool{}
		recvs, _, _ := unstructured.NestedSlice(ac.Object, "spec", "receivers")
		for _, r := range recvs {
			m, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if n, _, _ := unstructured.NestedString(m, "name"); n != "" {
				declared[n] = true
			}
		}
		route, hasRoute, _ := unstructured.NestedMap(ac.Object, "spec", "route")
		if !hasRoute {
			// No route means nothing in this object claims a receiver, so there is no contradiction to
			// report. An object holding only receivers is a legitimate building block.
			continue
		}
		var missing []string
		collectMissingReceivers(route, declared, &missing, "spec.route")
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)
		names := make([]string, 0, len(declared))
		for n := range declared {
			names = append(names, n)
		}
		sort.Strings(names)
		declaredText := strings.Join(names, ", ")
		if declaredText == "" {
			declaredText = "none"
		}
		out = append(out, types.Finding{
			ID:          findingID("stack.monitoring.alert-route-receiver-missing", "AlertmanagerConfig", ns, name),
			IDBasis:     &types.ResourceRef{Kind: "AlertmanagerConfig", Namespace: ns, Name: name},
			RuleID:      "stack.monitoring.alert-route-receiver-missing",
			RuleVersion: a.Version(),
			Title: fmt.Sprintf("AlertmanagerConfig %s/%s routes to %d %s it does not declare",
				ns, name, len(missing), map[bool]string{true: "receiver", false: "receivers"}[len(missing) == 1]),
			Description: fmt.Sprintf("AlertmanagerConfig %s/%s contains %s naming a receiver that "+
				"is not in this object's spec.receivers. The object declares: %s.",
				ns, name, nWord(len(missing), "route", "routes"), declaredText),
			WhyItMatters: "A route and its receiver are two halves of one statement, and only one half is " +
				"in this object. Nothing in the cluster reports the mismatch, because the component that " +
				"would report it is the one holding the broken configuration.",
			Evidence: append(append([]string{
				fmt.Sprintf("%s/%s declares %s: %s", ns, name, pickWord(len(names), "a receiver", "receivers"), declaredText)},
				missing...),
				"THIS IS A STRUCTURAL FACT AND NOT A STATEMENT ABOUT ALERTING. Whether any alert ever "+
					"reached this route, and whether anything fired at all, is not visible from any object "+
					"in this reading.",
				"Alertmanager's main configuration lives in a Secret this product does not read, so a "+
					"receiver defined there is invisible here and the mismatch above is scoped to this "+
					"object alone."),
			Severity:          types.SeverityHigh,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "AlertmanagerConfig", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortLow,
			Confidence:        1.0,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// collectMissingReceivers walks a route tree, recording each path whose receiver is not declared.
//
// A CHILD ROUTE MAY LEGITIMATELY NAME NO RECEIVER — it inherits its parent's. Only a NAMED receiver that is
// undeclared is a mismatch; an unnamed one is inheritance and reporting it would fire on ordinary routing.
func collectMissingReceivers(route map[string]interface{}, declared map[string]bool, out *[]string, path string) {
	if r, _, _ := unstructured.NestedString(route, "receiver"); r != "" && !declared[r] {
		*out = append(*out, fmt.Sprintf("%s.receiver = %q, which is not declared in spec.receivers", path, r))
	}
	children, _, _ := unstructured.NestedSlice(route, "routes")
	for i, c := range children {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		collectMissingReceivers(m, declared, out, fmt.Sprintf("%s.routes[%d]", path, i))
	}
}

// ── Prometheus: retention with nowhere to retain it ──────────────────────────────────────────────

// PrometheusDurability reports Prometheus objects the operator will back with an emptyDir.
type PrometheusDurability struct{}

func (PrometheusDurability) ID() string { return "stack.monitoring.prometheus" }
func (PrometheusDurability) FindingIDs() []string {
	return []string{"stack.monitoring.prometheus-storage-ephemeral"}
}
func (PrometheusDurability) Version() string { return "1.0.0" }
func (PrometheusDurability) RequiredGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{monitoringGVR("v1", "prometheuses")}
}

func (a PrometheusDurability) Analyze(inv *collect.Inventory) []types.Finding {
	if !listSucceeded(inv, "monitoring.coreos.com", "prometheuses") {
		return nil
	}
	var out []types.Finding
	for _, p := range stackObjects(inv, "monitoring.coreos.com", "prometheuses") {
		ns, _, _ := unstructured.NestedString(p.Object, "metadata", "namespace")
		name, _, _ := unstructured.NestedString(p.Object, "metadata", "name")

		// BOTH DOORS MUST BE SHUT before the operator's emptyDir default is what actually applies.
		// spec.storage is the declared one; spec.volumes plus a matching volumeMount is the escape hatch
		// several charts use, and a reading that ignored it would report a durable Prometheus as ephemeral.
		if _, hasStorage, _ := unstructured.NestedMap(p.Object, "spec", "storage"); hasStorage {
			continue
		}
		if vols, found, _ := unstructured.NestedSlice(p.Object, "spec", "volumes"); found && len(vols) > 0 {
			continue
		}
		retention, _, _ := unstructured.NestedString(p.Object, "spec", "retention")
		retentionText := "spec.retention is unset, so the operator's default of 24h applies"
		if retention != "" {
			retentionText = fmt.Sprintf("spec.retention is %q", retention)
		}
		out = append(out, types.Finding{
			ID:          findingID("stack.monitoring.prometheus-storage-ephemeral", "Prometheus", ns, name),
			IDBasis:     &types.ResourceRef{Kind: "Prometheus", Namespace: ns, Name: name},
			RuleID:      "stack.monitoring.prometheus-storage-ephemeral",
			RuleVersion: a.Version(),
			Title:       fmt.Sprintf("Prometheus %s/%s declares no storage", ns, name),
			Description: fmt.Sprintf("Prometheus %s/%s sets neither spec.storage nor spec.volumes, so the "+
				"prometheus-operator backs its data directory with an emptyDir — a volume whose lifetime is "+
				"the pod's. %s.", ns, name, retentionText),
			WhyItMatters: "Retention is a promise about history, and an emptyDir keeps it only until the " +
				"pod is replaced — which a node upgrade, an eviction or a chart change all do routinely. " +
				"The configuration reads as retaining data for as long as it says.",
			Evidence: []string{
				fmt.Sprintf("%s/%s: spec.storage is absent and spec.volumes is empty", ns, name),
				retentionText,
				"this is a SPEC fact: whether this Prometheus has actually lost history is not readable " +
					"from any object here, and no such loss is claimed",
				"an emptyDir may be deliberate — a short-lived or federated Prometheus that ships its " +
					"series elsewhere needs no local durability",
			},
			Severity:          types.SeverityMedium,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Prometheus", Namespace: ns, Name: name}},
			EstimatedEffort:   types.EffortMedium,
			Confidence:        0.9,
			Provenance:        provenance(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
