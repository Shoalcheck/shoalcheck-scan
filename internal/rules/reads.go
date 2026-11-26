package rules

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// THE KINDS THE RULES READ BEYOND THE CORE COLLECTOR (Batch 5, decision D1, docs/engine/read-set.md). Each is read
// through the operator-object path: only when served, one bounded step each, a denial recorded as "not read", and
// pruned to the fields below's readers declare (internal/collect/prune.go).
var (
	gvrValidatingWebhooks = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}
	gvrMutatingWebhooks   = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}
	gvrAPIServices        = schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}
	gvrVPA                = schema.GroupVersionResource{Group: "autoscaling.k8s.io", Version: "v1", Resource: "verticalpodautoscalers"}
	gvrPodMetrics         = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}
	gvrRollouts           = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "rollouts"}
	gvrNodePools          = schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodepools"}
	gvrCSINodes           = schema.GroupVersionResource{Group: "storage.k8s.io", Version: "v1", Resource: "csinodes"}
	// The built-in policy engine (ENG-14). Policies are kept as identity only; a binding keeps the policy it binds
	// and its validationActions, which is all that says whether it can refuse a request.
	gvrVAPs        = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}
	gvrVAPBindings = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}
)

// EngineGVRs are the kinds above, which the pipeline asks the collector for beside the analyzers' own.
func EngineGVRs() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{gvrValidatingWebhooks, gvrMutatingWebhooks, gvrAPIServices, gvrVPA, gvrPodMetrics,
		gvrRollouts, gvrNodePools, gvrCSINodes, gvrVAPs, gvrVAPBindings}
}

// crKind is how a kind read through the operator-object path is named among the reading's collected kinds.
func crKind(gvr schema.GroupVersionResource) string {
	return collect.CRStepPrefix + gvr.GroupResource().String()
}

// crObjects is what was read of a kind; ok is false when it was not read (not served, denied, failed).
func crObjects(inv *collect.Inventory, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, bool) {
	if !observed(inv, crKind(gvr)) {
		return nil, false
	}
	return inv.StackObjects[gvr], true
}
