package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

type MissingProbes struct{}

func (MissingProbes) ID() string      { return "k8s.workload.no-probes" }
func (MissingProbes) Version() string { return "1.0.0" }

// caveatScope is appended to every finding: probe absence is read from the
// stored controller PodSpec, which is not necessarily what the running pod has.
const probeSpecScopeCaveat = "Read from the controller PodSpec only — probes injected by mutating admission webhooks, operators, or mesh sidecars on the running pod are not visible here, and some teams deliberately manage probes outside the workload manifest. Confirm against a live pod before treating this as a true gap."

func (r MissingProbes) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, w := range workloads(inv, opts) {
		var evidence []string
		readinessMissing := false
		livenessMissing := false
		for _, c := range w.PodSpec.Containers {
			var missing []string
			if c.ReadinessProbe == nil {
				missing = append(missing, "readiness")
				readinessMissing = true
			}
			if c.LivenessProbe == nil {
				missing = append(missing, "liveness")
				livenessMissing = true
			}
			if len(missing) == 0 {
				continue
			}
			evidence = append(evidence, fmt.Sprintf(
				"container %s in %s %s/%s: no %s probe configured",
				c.Name, w.Kind, w.Namespace, w.Name, strings.Join(missing, " or ")))
		}
		if len(evidence) == 0 {
			continue
		}

		// Does this workload actually serve traffic? The readiness/rollout
		// consequence only applies to pods behind a Service or exposing ports.
		// A queue consumer, batch sidecar, or log-shipper DaemonSet that
		// declares no ports and sits behind no Service has nothing to gate, so
		// the "traffic reaches pods before they can serve" claim is vacuous.
		servesTraffic := workloadDeclaresPorts(w.PodSpec) || workloadBehindService(inv.Services, w.Namespace, w.PodLabels)

		// Build the impact narrative from the probes ACTUALLY missing, not a
		// fixed both-probes story. Each clause is only asserted when its probe
		// is absent — and the readiness clause is only asserted when the
		// workload serves traffic.
		var descParts []string
		var whyParts []string
		assertReadinessImpact := readinessMissing && servesTraffic
		if assertReadinessImpact {
			descParts = append(descParts, "no readiness probe means traffic can reach pods before they are ready to serve, so each rollout briefly drops requests")
			whyParts = append(whyParts, "missing readiness probes turn deploys into brief, repeatable outages for traffic-serving workloads")
		}
		if livenessMissing {
			descParts = append(descParts, "no liveness probe means a hung or deadlocked process is never restarted by the kubelet")
			whyParts = append(whyParts, "missing liveness probes leave wedged processes running until something external notices")
		}
		// Readiness missing but no traffic: neutral, non-alarming wording.
		if readinessMissing && !servesTraffic {
			descParts = append(descParts, "no readiness probe is configured; readiness also gates Service traffic where applicable, but this workload exposes no ports and sits behind no Service we observed")
		}

		desc := fmt.Sprintf("%s %s/%s ships containers without health probes: %s.",
			w.Kind, w.Namespace, w.Name, strings.Join(descParts, "; "))

		why := strings.Join(whyParts, "; ")
		if why == "" {
			// Liveness-only on a non-serving workload, or readiness-only with
			// no traffic — no strong outage claim is defensible.
			why = "Health probes let Kubernetes detect and recover from unhealthy containers; without them, failures are silent until they cascade."
		} else {
			why = strings.ToUpper(why[:1]) + why[1:] + "."
		}

		// Caveat that effective probes may live outside the inspected spec.
		evidence = append(evidence, "Caveat: "+probeSpecScopeCaveat)

		// Severity ladder (resolves the prior bare TODO):
		//   - Medium when readiness is missing on a traffic-serving workload
		//     (real, repeatable rollout impact).
		//   - Low otherwise: liveness-only, or readiness-only on a workload
		//     that serves no traffic — a real hygiene gap, not an outage path.
		severity := types.SeverityLow
		if assertReadinessImpact {
			severity = types.SeverityMedium
		}

		out = append(out, types.Finding{
			ID:           findingID(r.ID(), w.Kind, w.Namespace, w.Name),
			IDBasis:      &types.ResourceRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			RuleID:       r.ID(),
			RuleVersion:  r.Version(),
			Title:        fmt.Sprintf("Add health probes to %s/%s", w.Namespace, w.Name),
			Description:  desc,
			WhyItMatters: why,
			Evidence:     evidence,
			Severity:     severity,
			Category:     types.CategoryReliability,
			AffectedResources: []types.ResourceRef{
				{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name},
			},
			EstimatedEffort: types.EffortLow,
			// Confidence 1.0: probe field presence/absence is a literal spec
			// fact. The impact wording above is the typical, not guaranteed,
			// consequence (and the spec-scope caveat in Evidence flags that the
			// running pod may differ) — detection certainty, not impact
			// certainty, is what this number reflects.
			Confidence: 1.0,
			Provenance: provenance(),
		})

		// Only attach a liveness remediation when liveness is the gap, and make
		// it safe: a naive liveness probe (no startupProbe, low failure
		// threshold, short timeout) restarts healthy-but-slow pods and can
		// cascade a whole Deployment into CrashLoopBackOff — strictly worse
		// than no liveness probe. The skeleton pairs a startupProbe with
		// conservative thresholds and is explicitly flagged as a template to
		// validate, not a verbatim patch.
		if livenessMissing {
			out[len(out)-1].RemediationYAML = livenessProbeSkeleton()
		}
	}
	return out
}

// workloadDeclaresPorts reports whether any container in the spec exposes a
// containerPort — a proxy for "this workload is intended to receive traffic".
func workloadDeclaresPorts(spec corev1.PodSpec) bool {
	for _, c := range spec.Containers {
		if len(c.Ports) > 0 {
			return true
		}
	}
	return false
}

// workloadBehindService reports whether any Service in ns selects this
// workload's pods — mirrors the selector logic used elsewhere (a Service with
// a selector that all of the workload's pod labels satisfy). Empty-selector
// Services (headless/externalName/manually-managed Endpoints) are ignored: we
// can't attribute them to a workload from labels alone.
func workloadBehindService(svcs []corev1.Service, ns string, podLabels map[string]string) bool {
	set := labels.Set(podLabels)
	for _, svc := range svcs {
		if svc.Namespace != ns || len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(labels.Set(svc.Spec.Selector)).Matches(set) {
			return true
		}
	}
	return false
}

// livenessProbeSkeleton returns a conservative, non-destructive starting point
// for a liveness probe. It is a TEMPLATE, not a measured patch: the path/port
// and the timing must be validated against the real workload before applying,
// or the probe can restart healthy-but-slow pods. The startupProbe shields
// slow-start apps (JVM, large models, migrations) during warmup.
func livenessProbeSkeleton() string {
	return strings.Join([]string{
		"# TEMPLATE — do NOT apply blind. A liveness probe configured too aggressively",
		"# (no startupProbe, low failureThreshold, short timeout) will restart healthy-but-slow",
		"# pods and can cascade the whole Deployment into CrashLoopBackOff. Set the real",
		"# health path/port and tune the timings to your workload's warmup + GC behaviour first.",
		"#",
		"# startupProbe gates liveness until the app has finished starting; give slow-start",
		"# apps (JVM, large models, migrations) a generous startup budget.",
		"startupProbe:",
		"  httpGet: { path: /healthz, port: http }   # <-- set to your real health endpoint",
		"  periodSeconds: 10",
		"  failureThreshold: 30                       # ~5 min warmup budget; raise for slow starters",
		"livenessProbe:",
		"  httpGet: { path: /healthz, port: http }   # <-- set to your real health endpoint",
		"  periodSeconds: 15",
		"  timeoutSeconds: 5",
		"  failureThreshold: 3",
	}, "\n")
}

// RequiredKinds — Whether a missing probe matters depends on the workload being behind a Service.
// See deps.go for what belongs in this list.
func (r MissingProbes) RequiredKinds() []string { return withWorkloads("services") }
