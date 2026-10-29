package rules

import (
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// RiskyRolloutStrategy flags Deployments whose update strategy guarantees a
// near-total capacity gap during a rollout: Recreate (all pods deleted before
// replacements start) or a RollingUpdate whose maxUnavailable resolves to a
// pod count that takes most/all replicas down at once.
//
// Empty strategy fields are NOT flagged — the API server defaults them to
// RollingUpdate with 25%/25%, which is safe.
//
// Calibration notes (see docs/research/2026-06-16-rule-honesty-audit.md):
//   - The STRATEGY FIELD is read verbatim from the spec, so its presence is a
//     certain fact. Whether a capacity gap is a user-facing OUTAGE depends on
//     facts the read-only scan can only partially infer (is a Service in the
//     serving path? does an upstream retry? is this a batch/queue worker?).
//     Confidence therefore reflects impact certainty, not field-read certainty,
//     and is raised only when a Service actually selects the Deployment.
//   - Recreate is the correct (only) safe strategy for a Deployment that mounts
//     a ReadWriteOnce volume or must run as a single instance; for those the
//     blanket "maxUnavailable:0, maxSurge:1" fix DEADLOCKS the rollout
//     (Multi-Attach) or runs two writers at once. We detect PVC-backed volumes
//     in the pod template and withhold the surge YAML when present.
//   - A single-replica Deployment is tautologically "all replicas down" on any
//     rollout regardless of strategy; that reliability gap is owned by
//     SingleReplicaNoPDB, so the maxUnavailable branches require replicas >= 2.
type RiskyRolloutStrategy struct{}

func (RiskyRolloutStrategy) ID() string      { return "k8s.workload.risky-rollout-strategy" }
func (RiskyRolloutStrategy) Version() string { return "1.0.0" }

func (r RiskyRolloutStrategy) Evaluate(inv *collect.Inventory, opts Options) []types.Finding {
	var out []types.Finding
	for _, d := range inv.Deployments {
		if !opts.IncludeSystem && isSystemNamespace(d.Namespace) {
			continue
		}
		replicas := int32(1)
		if d.Spec.Replicas != nil {
			replicas = *d.Spec.Replicas
		}
		assess := riskyStrategy(&d, replicas)
		if assess.evidence == "" {
			continue
		}

		// Does anything in the serving path actually route to this Deployment?
		// Only then is a capacity gap a user-facing outage; otherwise (batch,
		// queue consumer, internal singleton) the impact is unverified.
		fronted := serviceSelectsDeployment(inv.Services, &d)

		evidence := []string{assess.evidence}

		// PVC-backed pod templates are exactly the RWO / single-writer case
		// Recreate is usually chosen for: surging a 2nd pod deadlocks on a
		// Multi-Attach error or runs two writers at once. Withhold the surge
		// YAML and say so plainly.
		//
		// B-139: THIS BLOCK USED TO SAY "access modes are not collected by the
		// read-only scan", AND THAT WAS A FALSE STATEMENT ABOUT OUR OWN COVERAGE.
		// PVCs are in the inventory with spec.accessModes populated — verified on a
		// real cluster, 39 of 39 PVCs carrying it in both spec and status, and
		// internal/rules/contradiction.go reads the field to decide whether a claim
		// is single-node. The sentence is deleted because a hedge describing a
		// limitation we no longer have understates our coverage, which is why it
		// survived every gate that looks for overstatement.
		//
		// WHAT IS NOT CHANGED, AND THE DISTINCTION IS THE POINT: this rule still
		// treats "mounts any PVC" as the signal and still says "IF that PVC is
		// ReadWriteOnce" in its evidence. Resolving that conditional into a fact is
		// new rule behaviour making a new claim, and it is a separate decision that
		// has not been taken. Deleting a false sentence about coverage and starting
		// to reason from the data are two changes, and only the first is authorised.
		usesPVC := podTemplateUsesPVC(&d.Spec.Template.Spec)

		var description, why string
		var remediationYAML string
		confidence := 0.6 // no observed Service; what depends on this is unread

		if fronted {
			confidence = 0.9
			description = fmt.Sprintf(
				"Deployment %s/%s uses an update strategy that takes nearly all replicas down at once during a rollout, and a Service in the same namespace selects its pods. What that gap means for callers is not readable from a snapshot — a published endpoint is not a request — so this reports the mechanism and the Service, and stops there.",
				d.Namespace, d.Name)
			why = "The replica count this strategy passes through is arithmetic over your own spec. A Service selecting these pods is what makes it worth reading first rather than last; it is not evidence that anything was served."
			evidence = append(evidence, fmt.Sprintf(
				"a Service in namespace %s selects this Deployment's pods (selector match — NOT proof of endpoint registration or of traffic)", d.Namespace))
		} else {
			description = fmt.Sprintf(
				"Deployment %s/%s uses an update strategy that takes nearly all replicas down at once during a rollout. No Service selecting it was observed, so what the gap costs depends on a consumer the scan cannot see — a batch or queue consumer tolerates it; something called synchronously does not. Confirm which this is.",
				d.Namespace, d.Name)
			why = "The replica count this strategy passes through is arithmetic over your own spec. Whether that matters is a question about consumers, and no consumer is observable from a read-only snapshot."
			evidence = append(evidence,
				"no Service selecting this Deployment was observed — what depends on it is NOT determinable from the read-only scan")
		}

		if usesPVC {
			// Do NOT hand a Multi-Attach deadlock as a fix. Guidance, no YAML.
			remediationYAML = ""
			evidence = append(evidence,
				"pod template mounts a PersistentVolumeClaim: if that PVC is ReadWriteOnce (or this app must run as a single writer), switching to maxSurge:1 will deadlock the rollout on a Multi-Attach error or run two writers at once — keep Recreate, or move to a StatefulSet with OnDelete/partitioned updates")
		} else {
			remediationYAML = fmt.Sprintf(
				"# Safe for stateless, multi-instance workloads. Do NOT apply if this\n"+
					"# Deployment mounts a ReadWriteOnce volume or must run as a single\n"+
					"# instance: maxSurge:1 starts a 2nd pod before the old one stops,\n"+
					"# which deadlocks on a Multi-Attach error (validate before applying).\n"+
					"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  strategy:\n    type: RollingUpdate\n    rollingUpdate:\n      maxUnavailable: 0\n      maxSurge: 1\n",
				d.Name, d.Namespace)
		}

		out = append(out, types.Finding{
			ID:                findingID(r.ID(), "Deployment", d.Namespace, d.Name),
			IDBasis:           &types.ResourceRef{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name},
			RuleID:            r.ID(),
			RuleVersion:       r.Version(),
			Title:             fmt.Sprintf("Update strategy for %s/%s takes nearly all replicas down at once", d.Namespace, d.Name),
			Description:       description,
			WhyItMatters:      why,
			Evidence:          evidence,
			Severity:          types.SeverityMedium, // a mechanical gap; what it costs depends on consumers we cannot see
			Category:          types.CategoryReliability,
			AffectedResources: []types.ResourceRef{{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name}},
			EstimatedEffort:   types.EffortLow,
			RemediationYAML:   remediationYAML,
			// Confidence reflects certainty this is a PROBLEM (impact), not that
			// the strategy field was read: 0.9 when a Service fronts it, 0.6 when
			// the serving path is unconfirmed.
			Confidence: confidence,
			Provenance: provenance(),
		})
	}
	return out
}

type strategyAssessment struct {
	evidence string // citation of the risky strategy values, or "" when safe
}

// riskyStrategy classifies a Deployment's update strategy. It returns a
// non-empty evidence citation only when the strategy would take nearly all
// replicas down at once. Empty strategy fields are safe (server-defaulted to
// RollingUpdate 25%/25%). The maxUnavailable branches require replicas >= 2:
// for a single replica every rollout touches the only pod regardless of
// strategy, so that risk belongs to SingleReplicaNoPDB, not here.
func riskyStrategy(d *appsv1.Deployment, replicas int32) strategyAssessment {
	s := d.Spec.Strategy
	if s.Type == appsv1.RecreateDeploymentStrategyType {
		return strategyAssessment{evidence: fmt.Sprintf(
			"Deployment %s/%s: strategy.type=Recreate — all %s are deleted before any replacement is created, so the replica count reaches 0 during every update",
			d.Namespace, d.Name, nWord(int(replicas), "replica", "replicas"))}
	}
	if s.RollingUpdate == nil || s.RollingUpdate.MaxUnavailable == nil {
		return strategyAssessment{} // server defaults apply (RollingUpdate 25%/25%) — safe
	}
	if replicas < 2 {
		// Tautological on a single replica; owned by SingleReplicaNoPDB.
		return strategyAssessment{}
	}

	mu := s.RollingUpdate.MaxUnavailable
	// A bare-integer STRING (e.g. "3", no "%") is rejected by the scaler, so
	// normalize it to an Int form first — it means the same as an int field.
	scaleArg := mu
	if mu.Type == intstr.String && !strings.HasSuffix(mu.StrVal, "%") {
		n, perr := strconv.Atoi(mu.StrVal)
		if perr != nil {
			return strategyAssessment{} // non-numeric, non-percent: not our case
		}
		v := intstr.FromInt32(int32(n))
		scaleArg = &v
	}
	// Resolve int OR percentage to an absolute pod count using K8s
	// maxUnavailable semantics: percentages round DOWN (roundUp=false), so
	// 75% of 4 = 3 down. This mirrors pdb_blocks_drains.go's use of the same
	// helper and catches near-total values the old >=100% check missed.
	down, err := intstr.GetScaledValueFromIntOrPercent(scaleArg, int(replicas), false)
	if err != nil || down <= 0 {
		return strategyAssessment{}
	}
	remaining := int(replicas) - down

	// Flag when the rollout can leave serving capacity at or near zero. We
	// treat "<= 1 replica left serving while more than one exists" as the
	// near-total-collapse bar: all replicas gone, or only a single pod left to
	// carry the entire load mid-rollout.
	if remaining <= 1 {
		if remaining <= 0 {
			return strategyAssessment{evidence: fmt.Sprintf(
				"Deployment %s/%s: strategy.rollingUpdate.maxUnavailable=%s resolves to %d of %d pods down — a rollout may take ALL replicas down at once",
				d.Namespace, d.Name, mu.String(), down, replicas)}
		}
		return strategyAssessment{evidence: fmt.Sprintf(
			"Deployment %s/%s: strategy.rollingUpdate.maxUnavailable=%s resolves to %d of %d pods down — 1 replica remains during the rollout",
			d.Namespace, d.Name, mu.String(), down, replicas)}
	}
	return strategyAssessment{}
}

// podTemplateUsesPVC reports whether the pod template mounts any PersistentVolumeClaim.
//
// It deliberately asks only whether a claim is mounted, not what kind. The access mode is
// readable — see the B-139 note at the call site — and reasoning from it is a separate
// decision that has not been taken. This function is the "is there a volume at all"
// question and nothing more.
func podTemplateUsesPVC(spec *corev1.PodSpec) bool {
	for _, v := range spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			return true
		}
	}
	return false
}

// serviceSelectsDeployment reports whether any Service's selector matches the
// Deployment's pod-template labels — i.e. the Deployment is in a serving path.
// A Service with an empty selector matches nothing here (it targets manual
// Endpoints, not these pods).
func serviceSelectsDeployment(svcs []corev1.Service, d *appsv1.Deployment) bool {
	podLabels := labels.Set(d.Spec.Template.Labels)
	for _, svc := range svcs {
		if svc.Namespace != d.Namespace || len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(svc.Spec.Selector).Matches(podLabels) {
			return true
		}
	}
	return false
}

// RequiredKinds — A strategy matters because traffic flows to it; the Service list is what establishes that.
// See deps.go for what belongs in this list.
func (r RiskyRolloutStrategy) RequiredKinds() []string { return []string{"deployments", "services"} }
