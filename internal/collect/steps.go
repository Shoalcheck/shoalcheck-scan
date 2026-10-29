package collect

import "strings"

// THE ONE MAP FROM A COLLECTOR STEP NAME TO THE ACCESS IT EXERCISED.
//
// The report has two vocabularies for the same reading and no translation between them. A rule declares what it
// rests on as a collector STEP NAME — "pods", "server-resources" — because that is what Meta.Collected records
// and what a comparison checks membership against. The session trace groups requests at the RBAC unit, an
// apiGroup/RESOURCE tuple: "core/pods". Both are correct for their own job, and until this existed a reader
// could be told a finding rests on "pods" and shown a ledger row for "core/pods" with nothing joining them.
//
// IT LIVES HERE, NEXT TO THE STEP NAMES IT MAPS. The steps are minted in this package, in the `step("pods", …)`
// calls a few hundred lines below; a table in the pipeline or the report would be a second list to keep in sync
// with this one, which is the defect that hid 21 print-floor failures earlier in this project. A renamed step
// and its tuple now move in the same file, and stepTupleTest asserts the two sides still agree.
//
// The map is deliberately NOT derived from the typed clientset calls. Those calls are spread across twenty
// closures and several of them list more than one thing; deriving would mean parsing Go, and a derivation
// nobody can read is not more trustworthy than twenty lines anybody can check against `kubectl api-resources`.
var stepTuples = map[string]string{
	// Core group: the tuple has no group segment of its own, so the trace writes "core/".
	"nodes":                  "core/nodes",
	"namespaces":             "core/namespaces",
	"pods":                   "core/pods",
	"services":               "core/services",
	"serviceaccounts":        "core/serviceaccounts",
	"resourcequotas":         "core/resourcequotas",
	"limitranges":            "core/limitranges",
	"persistentvolumes":      "core/persistentvolumes",
	"persistentvolumeclaims": "core/persistentvolumeclaims",

	"deployments":  "apps/deployments",
	"statefulsets": "apps/statefulsets",
	"daemonsets":   "apps/daemonsets",

	"endpointslices":            "discovery.k8s.io/endpointslices",
	"poddisruptionbudgets":      "policy/poddisruptionbudgets",
	"networkpolicies":           "networking.k8s.io/networkpolicies",
	"ingresses":                 "networking.k8s.io/ingresses",
	"horizontalpodautoscalers":  "autoscaling/horizontalpodautoscalers",
	"cronjobs":                  "batch/cronjobs",
	"jobs":                      "batch/jobs",
	"storageclasses":            "storage.k8s.io/storageclasses",
	"customresourcedefinitions": "apiextensions.k8s.io/customresourcedefinitions",
	"ingressclasses":            "networking.k8s.io/ingressclasses",
	"priorityclasses":           "scheduling.k8s.io/priorityclasses",

	"clusterrolebindings": "rbac.authorization.k8s.io/clusterrolebindings",
	"rolebindings":        "rbac.authorization.k8s.io/rolebindings",
	"clusterroles":        "rbac.authorization.k8s.io/clusterroles",
	"roles":               "rbac.authorization.k8s.io/roles",

	// Discovery is not a resource request at all: it is GETs against /api, /apis and /apis/<g>/<v>, which the
	// trace classifies as non-resource URLs. Naming it "core/server-resources" would invent an API that does
	// not exist, and leaving it unmapped would make every rule that reads PresentGVRs uncitable.
	"server-resources": "nonResourceURL",
}

// StepTuple returns the apiGroup/resource tuple a collector step's requests are recorded under, and whether the
// step is one this build knows.
//
// A custom-resource step needs no table entry: the collector names it "cr:<resource>.<group>", built from the
// analyzer's own RequiredGVRs, so the tuple is already inside the name and is recovered rather than looked up.
// That is the whole reason analyzer dependencies were derived from GVRs in the first place — a new analyzer
// becomes citable without anybody editing this file.
func StepTuple(step string) (string, bool) {
	if t, ok := stepTuples[step]; ok {
		return t, true
	}
	if gr, ok := strings.CutPrefix(step, CRStepPrefix); ok {
		// GroupResource().String() is "resource.group", or bare "resource" in the core group. The trace's
		// tuple is the same two parts the other way round.
		if res, group, found := strings.Cut(gr, "."); found && res != "" && group != "" {
			return group + "/" + res, true
		}
		if gr != "" {
			return "core/" + gr, true
		}
	}
	return "", false
}

// CRStepPrefix is how a custom-resource list step is labelled, and this is its ONE definition.
//
// It was a bare "cr:" literal at the site that mints it (dynamic.go), at two sites that parse it back
// (permissions.go), at a third in internal/analyzers, and as a second exported constant in that package's
// deps.go. Five spellings of one string, in the two packages whose agreement is the only thing making a
// custom-resource finding citable — and internal/analyzers already imports this one, so there was never a
// cycle to justify the copy.
const CRStepPrefix = "cr:"
