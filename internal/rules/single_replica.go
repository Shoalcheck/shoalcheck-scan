package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type SingleReplicaNoPDB struct{}

func (SingleReplicaNoPDB) ID() string      { return "k8s.workload.single-replica-no-pdb" }
func (SingleReplicaNoPDB) Version() string { return "1.0.0" }

// srOptOutAnnotations let an operator declare an intentional singleton (e.g. a
// leader-elected controller whose second replica is only a hot standby, or a
// one-shot maintenance Deployment) so the audit does not flag it. Presence of
// any of these set to "true"/"single"/"intentional" suppresses the finding.
var srOptOutAnnotations = []string{
	"shoalcheck.dev/single-replica",
	"shoalcheck.io/single-replica",
}

func (r SingleReplicaNoPDB) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding

	// Denial guard: we are about to assert "no PDB covers this workload". That
	// is only honest if the PDB list actually succeeded. If the
	// poddisruptionbudgets step was denied/timed-out (present in Meta.Denied),
	// a workload with NO observed PDB is indistinguishable from one we simply
	// never got to read — so we must not emit "no PodDisruptionBudget matches"
	// as an observed fact. Skip entirely.
	if !observed(inv, "poddisruptionbudgets") {
		return out
	}
	// Whether we can speak to the Service edge at all. If services weren't
	// collected we still emit the finding, but we must not claim the workload is
	// un-exposed (absence of a Service we never listed is not evidence).
	servicesObserved := observed(inv, "services")

	for _, w := range workloads(inv, opts) {
		if w.Kind == "DaemonSet" || w.Replicas != 1 {
			continue
		}
		if pdbCovers(inv.PDBs, w.Namespace, w.PodLabels) {
			continue
		}
		if srOptedOut(w.PodLabels) {
			continue
		}

		// Is the workload behind a Service? A pod nobody routes to has a very
		// different disruption profile (its loss is invisible to users) than a
		// front-door API. We only trust a "not exposed" determination when the
		// services list was actually collected.
		exposed := servicesObserved && workloadHasService(inv.Services, w.Namespace, w.PodLabels)

		// Non-prod tempering: the namespace NAME is only one signal. A workload
		// can sit in a generic namespace yet be labelled environment=dev /
		// tier=staging — those are equally strong "not production" evidence and
		// must temper severity the same way. We read both the pod-template labels
		// and the workload's own object metadata labels.
		nonProd := isDevNamespace(w.Namespace) || hasNonProdLabel(w.PodLabels) || hasNonProdLabel(workloadObjectLabels(inv, w))

		// Leader-elected / controller heuristic. A single replica of a
		// reconciler/operator (leader election picks one active instance anyway)
		// or a workload whose Service only exposes metrics/webhook/health ports is
		// NOT a user-serving single point of failure: a drain causes a brief
		// reconcile/admission gap, not a user-visible outage. Treat it as such even
		// when a (non-serving) Service selects it.
		controllerLike := looksLikeController(w.Name) || (exposed && serviceOnlyNonServing(inv.Services, w.Namespace, w.PodLabels))

		stateful := w.Kind == "StatefulSet"
		// A controller is only user-serving if its Service exposes a real serving
		// port. If the heuristic fired, treat it as not-serving for severity/wording
		// even though some Service may select it for metrics/webhooks.
		serving := exposed && !controllerLike

		severity := srSeverity(serving, nonProd, servicesObserved, controllerLike)

		out = append(out, types.Finding{
			ID:                findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:           &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:            r.ID(),
			RuleVersion:       r.Version(),
			Title:             fmt.Sprintf("Single replica without PDB: %s/%s", w.Namespace, w.Name),
			Description:       srDescription(w, serving, servicesObserved, stateful, controllerLike),
			WhyItMatters:      srWhyItMatters(serving, servicesObserved, stateful, controllerLike),
			Evidence:          srEvidence(w, serving, exposed, servicesObserved, nonProd, controllerLike),
			Severity:          severity,
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}},
			EstimatedEffort:   types.EffortMedium,
			// Primary remediation is to add a second replica. We deliberately do
			// NOT emit a PodDisruptionBudget manifest here: at replicas==1 a PDB
			// is meaningless (there is nothing to protect) and the obvious
			// minAvailable:1 form is the exact zero-disruption deadlock the
			// PDBBlocksDrains rule flags — it would hang every node drain. The
			// PDB only becomes meaningful AFTER the scale-up, so we recommend the
			// scale-up and describe the follow-on PDB in prose (see WhyItMatters)
			// rather than handing over an applyable manifest that strands the
			// operator at a worse failure than the one we reported.
			RemediationCommand: scaleCommand(w),
			// FACT (replicas==1, no matching PDB) is read verbatim from the spec
			// and is certain. IMPACT (a node event causes downtime) is INFERRED,
			// not measured: it depends on whether anything routes to the pod,
			// whether the app is a passive/leader-elected singleton, and the
			// namespace's role. Neighbors calibrate the same fact/impact split
			// (anti_affinity 0.6, netpol 0.8, node_headroom 0.3); 0.9 keeps the
			// certain fact prominent while acknowledging the impact is not proven.
			Confidence: 0.9,
			Provenance: provenance(),
		})
	}
	return out
}

// srSeverity modulates severity by how confidently we can call this an
// availability risk, instead of a flat High:
//   - High: the workload is on a real serving path (Service with a serving port)
//     in a production namespace — a single node event drops user-reachable
//     capacity.
//   - Medium: serving but non-prod (environment/tier dev|staging|… by namespace
//     name OR label), OR we couldn't read Services so exposure is unknown, OR a
//     leader-elected/controller workload whose loss is a brief reconcile/
//     admission gap rather than a user-visible outage.
//   - Low: confirmed no serving Service edge (background reconciler / one-shot
//     task) — pod loss is invisible to users; this is hygiene, not an outage.
//
// controllerLike never UPGRADES severity; it only caps a would-be High at Medium
// (a leader-elected singleton is by design, but a drain still opens a brief gap,
// so Medium — not Low — keeps "add a PDB if you need the gap bounded" honest).
func srSeverity(serving, nonProd, servicesObserved, controllerLike bool) types.Severity {
	if controllerLike {
		// Single replica by design for a leader-elected/controller; a drain is a
		// brief gap, not a user-visible outage. Cap at Medium regardless of the
		// serving determination (its Service, if any, is a metrics/webhook port).
		return types.SeverityMedium
	}
	if !servicesObserved {
		// Can't confirm exposure either way — don't overstate as High, don't
		// understate as Low. Medium is the honest middle.
		return types.SeverityMedium
	}
	if !serving {
		return types.SeverityLow
	}
	if nonProd {
		return types.SeverityMedium
	}
	return types.SeverityHigh
}

func srDescription(w workload, serving, servicesObserved, stateful, controllerLike bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s/%s runs exactly one replica and no PodDisruptionBudget matches its pods. ", w.Kind, w.Namespace, w.Name)
	switch {
	case controllerLike:
		b.WriteString("This looks like a leader-elected/controller workload (its name or backing Service points at a reconciler/operator, not a serving path), so single-replica is typically by design — leader election runs one active instance regardless. A node drain causes a brief reconcile/admission gap until the pod reschedules, not a user-visible outage. Add a PodDisruptionBudget only if you need that gap bounded.")
	case serving:
		b.WriteString("A Service routes to it on a serving port, so a node drain, autoscaler consolidation, or spot interruption drops user-reachable capacity until the pod reschedules.")
	case servicesObserved:
		b.WriteString("No Service in the namespace selects its pods on a serving port, so loss of the pod is not directly user-facing — but any node drain or interruption still takes the single replica down until it reschedules.")
	default:
		b.WriteString("A node drain, autoscaler consolidation, or spot interruption takes the single replica down until it reschedules; whether that is user-visible depends on whether a Service fronts it (the services list was not collected, so we cannot confirm).")
	}
	if stateful {
		b.WriteString(" This is a StatefulSet: do NOT simply scale to 2 — verify the application supports >1 replica (replication / quorum) first, or a second replica can corrupt data.")
	}
	return b.String()
}

func srWhyItMatters(serving, servicesObserved, stateful, controllerLike bool) string {
	// Default is conditional: the outage only happens IF the replica is on a
	// serving path. We never assert a "guaranteed" outage for a workload we have
	// not confirmed serves traffic.
	lead := "An unprotected single replica is a single point of failure: if it sits on a live serving path, a node event can cause a user-visible gap until the pod reschedules. "
	switch {
	case controllerLike:
		lead = "This is a leader-elected/controller-style singleton — running one active instance is by design, so a node event causes a brief reconcile/admission gap, not a user-visible outage. "
	case serving:
		lead = "This replica is behind a Service on a serving port, so a node event can cause a user-visible outage window until the pod reschedules. "
	case servicesObserved:
		lead = "No Service fronts this replica on a serving port, so a node event is unlikely to be user-visible — but the workload still vanishes briefly on any drain. "
	}
	follow := "Add a second replica first; a PodDisruptionBudget is only meaningful once there are at least 2 replicas to protect (a PDB on a single replica blocks every node drain)."
	if controllerLike {
		follow = "If you need the reconcile/admission gap bounded, add a PodDisruptionBudget — but only after at least 2 replicas (a PDB on a single replica blocks every node drain), and confirm the controller tolerates a hot standby."
	}
	if stateful {
		follow = "For a StatefulSet, confirm the app supports multiple replicas before scaling; only then is a PodDisruptionBudget (on at least 2 replicas) appropriate — a PDB on a single replica blocks every node drain."
	}
	return lead + follow
}

func srEvidence(w workload, serving, exposed, servicesObserved, nonProd, controllerLike bool) []string {
	ev := []string{
		fmt.Sprintf("%s %s/%s: spec.replicas = 1", w.Kind, w.Namespace, w.Name),
		fmt.Sprintf("No PodDisruptionBudget in namespace %s selects pod labels %v", w.Namespace, w.PodLabels),
	}
	switch {
	case serving:
		ev = append(ev, fmt.Sprintf("A Service in namespace %s selects these pod labels on a serving port (workload is in the serving path)", w.Namespace))
	case exposed:
		// Selected by a Service, but the controller heuristic fired (name match or
		// metrics/webhook-only ports) — record both facts honestly.
		ev = append(ev, fmt.Sprintf("A Service in namespace %s selects these pod labels, but only on metrics/webhook/health ports (not a user-serving path)", w.Namespace))
	case servicesObserved:
		ev = append(ev, fmt.Sprintf("No Service in namespace %s selects these pod labels (workload not directly exposed)", w.Namespace))
	default:
		ev = append(ev, "Services were not collected (absent from Meta.Collected / present in Meta.Denied) — exposure not assessed")
	}
	if controllerLike {
		ev = append(ev, fmt.Sprintf("Workload %q matches a leader-elected/controller pattern (controller/operator/cert-manager/argocd/flux/webhook/…) — single-replica is typically by design", w.Name))
	}
	if nonProd {
		ev = append(ev, fmt.Sprintf("%s/%s looks like a non-production (dev/staging/test/qa) workload by namespace name or environment/tier label — single-replica may be intentional and cost-driven", w.Namespace, w.Name))
	}
	return ev
}

func pdbCovers(pdbs []policyv1.PodDisruptionBudget, ns string, podLabels map[string]string) bool {
	for _, pdb := range pdbs {
		if pdb.Namespace != ns || pdb.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil || sel.Empty() {
			continue
		}
		if sel.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}

// workloadHasService reports whether any Service in the namespace selects the
// workload's pods. A Service selector is equality-based; an empty selector
// (headless / ExternalName / manually-managed Endpoints) selects nothing, so we
// skip it. Caller must only trust a false result when services were collected.
func workloadHasService(svcs []corev1.Service, ns string, podLabels map[string]string) bool {
	for _, svc := range svcs {
		if svc.Namespace != ns || len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(labels.Set(svc.Spec.Selector)).Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}

// isDevNamespace is a best-effort heuristic: single-replica in dev/staging is
// commonly intentional and cost-driven, so the blast radius of a disruption is
// lower. It only matches on conventional name fragments; it never upgrades
// severity, only tempers it.
func isDevNamespace(ns string) bool {
	l := strings.ToLower(ns)
	for _, frag := range []string{"dev", "staging", "stage", "qa", "test", "sandbox", "preview"} {
		if l == frag || strings.HasPrefix(l, frag+"-") || strings.HasSuffix(l, "-"+frag) || strings.Contains(l, "-"+frag+"-") {
			return true
		}
	}
	return false
}

// nonProdEnvValues are the conventional environment/tier values that mark a
// workload as not-production. A single replica in any of these is commonly
// intentional and cost-driven, so we temper severity (never upgrade).
var nonProdEnvValues = map[string]bool{
	"dev": true, "development": true,
	"staging": true, "stage": true,
	"test": true, "testing": true,
	"qa": true, "sandbox": true, "preview": true,
}

// nonProdLabelKeys are the label keys we inspect for an environment/tier hint,
// including the common app.kubernetes.io/* convention.
var nonProdLabelKeys = []string{
	"environment", "env", "tier",
	"app.kubernetes.io/environment", "app.kubernetes.io/env", "app.kubernetes.io/tier",
}

// hasNonProdLabel reports whether any recognized environment/tier label carries a
// non-production value (dev/staging/test/qa/…). Pure value match on a known set;
// it never matches "prod"/"production".
func hasNonProdLabel(m map[string]string) bool {
	for _, k := range nonProdLabelKeys {
		if v, ok := m[k]; ok && nonProdEnvValues[strings.ToLower(strings.TrimSpace(v))] {
			return true
		}
	}
	return false
}

// workloadObjectLabels returns the workload's OWN object-metadata labels (as
// opposed to the pod-template labels carried on the flattened workload). The
// flattening in workloads.go only propagates PodLabels, so we look the original
// object back up by kind/namespace/name to honestly read its metadata labels.
func workloadObjectLabels(inv *collect.Inventory, w workload) map[string]string {
	switch w.Kind {
	case "Deployment":
		for i := range inv.Deployments {
			d := &inv.Deployments[i]
			if d.Namespace == w.Namespace && d.Name == w.Name {
				return d.Labels
			}
		}
	case "StatefulSet":
		for i := range inv.StatefulSets {
			s := &inv.StatefulSets[i]
			if s.Namespace == w.Namespace && s.Name == w.Name {
				return s.Labels
			}
		}
	}
	return nil
}

// controllerNameFragments are substrings (lower-cased) in a workload name that
// strongly indicate a leader-elected/background controller or operator whose
// single replica is by design.
var controllerNameFragments = []string{
	"controller", "operator",
	"cert-manager", "argocd-", "argo-cd-",
	"flux", "kube-state-metrics",
	"-webhook", "webhook-",
}

// looksLikeController reports whether the workload name matches a known
// controller/operator/leader-elected pattern. Conservative substring match: it
// does not infer "controller" from arbitrary names, only the listed fragments.
func looksLikeController(name string) bool {
	n := strings.ToLower(name)
	for _, frag := range controllerNameFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// nonServingPortNames are Service port names that indicate a control-plane
// endpoint (scrape/admission/health), not a user-serving path.
var nonServingPortNames = map[string]bool{
	"metrics": true, "webhook": true, "webhooks": true,
	"health": true, "healthz": true, "probe": true, "readyz": true, "livez": true,
}

// serviceOnlyNonServing reports whether EVERY Service that selects the workload
// exposes only non-serving (metrics/webhook/health) ports — i.e. the workload is
// scraped/administered but not on a user-serving path. It is deliberately
// conservative: it returns true ONLY when at least one selecting Service has
// named ports AND none of any selecting Service's ports are serving. An unnamed
// port (common for single-port serving Services) or any serving-named port makes
// this false, so we never downgrade a real front-door on weak evidence.
func serviceOnlyNonServing(svcs []corev1.Service, ns string, podLabels map[string]string) bool {
	sawSelectingSvc := false
	sawNamedPort := false
	for _, svc := range svcs {
		if svc.Namespace != ns || len(svc.Spec.Selector) == 0 {
			continue
		}
		if !labels.SelectorFromSet(labels.Set(svc.Spec.Selector)).Matches(labels.Set(podLabels)) {
			continue
		}
		sawSelectingSvc = true
		for _, p := range svc.Spec.Ports {
			name := strings.ToLower(strings.TrimSpace(p.Name))
			if name == "" {
				// Unnamed port — cannot prove it is non-serving. Treat as serving.
				return false
			}
			sawNamedPort = true
			if !nonServingPortNames[name] {
				// A named serving port (http/https/grpc/…) — real serving path.
				return false
			}
		}
	}
	// Only assert "non-serving" when we actually saw a selecting Service with at
	// least one named port and every named port was non-serving.
	return sawSelectingSvc && sawNamedPort
}

// srOptedOut reports whether the workload declares itself an intentional
// singleton via a recognized opt-out label.
func srOptedOut(podLabels map[string]string) bool {
	for _, k := range srOptOutAnnotations {
		switch strings.ToLower(podLabels[k]) {
		case "true", "single", "intentional", "yes":
			return true
		}
	}
	return false
}

// scaleCommand suggests scaling to two replicas — the primary remediation.
// StatefulSets get a caveat: blindly scaling a stateful workload (e.g. a
// database primary) can corrupt data without application-level replication set
// up first.
func scaleCommand(w workload) string {
	base := fmt.Sprintf("kubectl -n %s scale %s/%s --replicas=2", w.Namespace, strings.ToLower(w.Kind), w.Name)
	if w.Kind == "StatefulSet" {
		return "# verify the app supports >1 replica (replication/quorum) before scaling a StatefulSet\n" + base
	}
	return base + "\n# only AFTER >=2 replicas, add a PodDisruptionBudget (e.g. maxUnavailable: 1); a minAvailable equal to the replica count deadlocks every node drain"
}

// RequiredKinds — A denied PDB list would let this rule report every single-replica workload as unprotected.
// See deps.go for what belongs in this list.
func (r SingleReplicaNoPDB) RequiredKinds() []string {
	return withWorkloads("poddisruptionbudgets", "services")
}
