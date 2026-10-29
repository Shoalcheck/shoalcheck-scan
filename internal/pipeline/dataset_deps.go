package pipeline

import (
	"sort"

	"github.com/Shoalcheck/shoalcheck-scan/internal/history"
)

// dataset_deps.go — WHICH PRODUCERS REST ON WHICH REFERENCE DATASETS.
//
// Gate 3 (internal/history/refdata_gate.go) only fires for a producer whose Deps name the dataset. So a rule
// that emits a dollar figure and does not appear here gets its figure compared across a price-table refresh —
// the defect intact, for that one rule. That makes this a list with teeth, and this project's most repeated
// failure is a list you must remember to update.
//
// SO IT IS GUARDED TWO WAYS, and neither is a reminder:
//
//   - dynamically, from the golden fixture: every rule that produced a DollarImpactMonthly in the shipped
//     document must be here (TestDatasetDeps_EveryDollarBearingProducerDeclaresPricing). That is only worth
//     something because the fixture-drift gate keeps the document representative — the two hold each other up.
//   - statically, from the source: every rule defined in a file that assigns DollarImpactMonthly must be here
//     (TestDatasetDeps_EveryRuleThatCanCarryADollarIsListed). This one covers the 19 rules the persona cannot
//     make fire, which the fixture-derived test cannot see.
//
// OVER-DECLARATION IS FREE AND UNDER-DECLARATION IS THE DEFECT. Declaring pricing on a producer that never
// carries a dollar disarms a comparison that would never have fired; omitting it lets a table refresh be
// reported as the customer's change. So the static test is allowed to be coarse — it asks about the FILE, and
// a file holding several rules requires all of them — and that coarseness is in the safe direction.
//
// A dataset name here must be one refdata.Datasets() holds, or the stamp never matches it and the gate
// silently never fires. That has its own test.
var datasetDepsByProducer = map[string][]history.DatasetDep{
	// Pricing is a VALUE dataset: the finding fires either way, with or without a figure. Never Presence —
	// gates_test.go already proves pricing coverage does not change which findings appear, and Presence:true
	// would move every cost finding to NotEvaluated on the first refresh, withholding the whole comparison to
	// protect one number.
	"k8s.cost.idle-loadbalancer":            {{Name: "pricing"}},
	"k8s.cost.node-headroom":                {{Name: "pricing"}},
	"k8s.cost.overprovisioned-resources":    {{Name: "pricing"}},
	"k8s.cost.unattached-volume":            {{Name: "pricing"}},
	"k8s.cost.ebs-gp2-where-gp3-is-cheaper": {{Name: "pricing"}},
	// Two datasets, and they move it differently. The surcharge comes from pricing — a VALUE dataset, the
	// finding fires with or without the figure. The window it is measured against comes from kubeversions, and
	// that table decides WHETHER the finding exists: a provider that extends a version's support, or a refreshed
	// table that corrects a date, makes this finding vanish with the cluster untouched, and "no longer in the
	// set" would attribute that to the customer. So kubeversions is PRESENCE here (deadline-calendar spec §2.1):
	// across a kubeversions refresh the finding goes to NotEvaluated, where the reason names both versions.
	"k8s.cost.kubernetes-version-past-standard-support": {{Name: "pricing"}, {Name: "kubeversions", Presence: true}},
	"k8s.cost.instance-generation-lag":                  {{Name: "pricing"}},
	"k8s.cost.commitment-candidate":                     {{Name: "pricing"}},
	// The drain family shares node_drain.go with node-headroom's pricing helpers and can attach a figure to
	// a placement or volume finding. Listed because the file can, not because the fixture showed it.
	"k8s.reliability.node-drain-budget":            {{Name: "pricing"}},
	"k8s.reliability.node-drain-unmanaged-pod":     {{Name: "pricing"}},
	"k8s.reliability.node-placement-concentration": {{Name: "pricing"}},
	"k8s.reliability.node-pinned-volume":           {{Name: "pricing"}},
	// PRESENCE, NOT VALUE — the one case the Presence flag was designed for, and the reason it is a flag
	// rather than an exclusive bucket. The API-removal schedule decides WHETHER this finding exists at all:
	// a refreshed table that adds a newly announced removal makes the finding appear, and reporting that
	// appearance as "this cluster changed" would be exactly backwards. So the finding moves to Gate 1's
	// NotEvaluated bucket across a version change instead of being compared.
	"k8s.upgrade.deprecated-api-served": {{Name: "api-removals", Presence: true}},
}

// datasetDepsFor returns the datasets a producer rests on, sorted so two readings of the same table list them
// identically.
func datasetDepsFor(id string) []history.DatasetDep {
	deps := datasetDepsByProducer[id]
	if len(deps) == 0 {
		return nil
	}
	out := append([]history.DatasetDep(nil), deps...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
