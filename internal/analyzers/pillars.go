package analyzers

import "github.com/Shoalcheck/shoalcheck-scan/internal/types"

// pillars.go — which of the product's headline claims an ANALYZER finding belongs to.
//
// WHY A SECOND TABLE. internal/rules owns the pillar declaration for the rule registry and cannot see these
// IDs: they are minted here. A table in internal/rules naming stack.* rules would be a hand-maintained copy of
// a set it cannot enumerate, which is the defect class this project has found four times. So each package
// declares its own, and internal/pipeline merges them.
//
// ALMOST EVERYTHING HERE ABSTAINS, and that is the honest answer. An Argo application out of sync, an Istio
// mesh in permissive mode, a certificate near expiry — each is a true finding in its own section, and none of
// them is one of the three things the document leads with.
//
// THE EXCEPTION IS MONITORING, and it is the reason the third pillar exists. Every other component's own
// health surface still works when it is misconfigured; a monitoring stack is the one whose failure removes the
// thing that would report the failure. Nothing pages you when your pager is wrong. Each finding assigned below
// is a STRUCTURAL fact — a selector that matches nothing, a route naming a receiver that is not defined,
// metrics on ephemeral storage — never a claim that an alert failed to fire, which a snapshot cannot see.
var pillarByRule = map[string]types.Pillar{
	// A scrape configuration that selects nothing: the metrics a dashboard is drawn from are not being
	// collected, and the dashboard looks the same either way.
	"stack.monitoring.servicemonitor-selects-nothing": types.PillarObservability,
	"stack.monitoring.podmonitor-selects-nothing":     types.PillarObservability,
	// A route naming a receiver that is not defined: the alert has nowhere to go. Structural, and the strongest
	// case in the pillar — nothing else in the cluster reports it.
	"stack.monitoring.alert-route-receiver-missing": types.PillarObservability,
	// Metrics on ephemeral storage: the history a post-incident question is asked of does not survive the pod.
	"stack.monitoring.prometheus-storage-ephemeral": types.PillarObservability,

	// ── abstentions, each with its reason ──────────────────────────────────────────────────────
	// These are true and belong in their own sections. None is one of the three headline claims: a GitOps
	// controller, a mesh and a certificate all report their own state, which is the property the monitoring
	// pillar exists because monitoring lacks.
	"stack.argocd.degraded":        types.PillarNone,
	"stack.argocd.outofsync":       types.PillarNone,
	"stack.flux.not-ready":         types.PillarNone,
	"stack.gateway.not-programmed": types.PillarNone,
	"stack.istio.permissive-mtls":  types.PillarNone,
	"stack.keda.not-ready":         types.PillarNone,
	"stack.strimzi.not-ready":      types.PillarNone,
	"stack.certmanager.expiring":   types.PillarNone,
	"stack.certmanager.not-issued": types.PillarNone,
	// A mesh's opaque-port annotation is a configuration fact the mesh itself surfaces.
	"stack.linkerd.opaque-port": types.PillarNone,
	// The HPA pair rests on a controller's published status — currentReplicas against the ceiling — which is
	// the Ground Truth test exactly, and k8s.reliability.hpa-pinned-at-max is already assigned there for the
	// same reason. Assigned rather than abstained so two readings of one object agree about which claim they are.
	"stack.hpa.pinned-at-max": types.PillarGroundTruth,
	// no-headroom is the SPEC (min == max, or max == 1), not a status: an HPA that cannot scale is a
	// declaration the operator made, and every admission-time linter sees it. Not "what no dashboard shows".
	"stack.hpa.no-headroom": types.PillarNone,
}

// PillarByRule returns a copy of the analyzer pillar table.
func PillarByRule() map[string]types.Pillar {
	out := make(map[string]types.Pillar, len(pillarByRule))
	for k, v := range pillarByRule {
		out[k] = v
	}
	return out
}
