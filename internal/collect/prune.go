package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// THE OPERATOR OBJECTS ARE KEPT TO THE FIELDS SOMETHING READS.
//
// The never-read guard (internal/trace/guard.go) refuses Secrets, but a Secret is not the only place a
// password lives. An Argo CD Application carries Helm values inline in spec.source.helm.values, a Flux
// HelmRelease in spec.values, and both repeat them in kubectl's last-applied annotation and in status
// (comparedTo). Whole operator objects would go into the
// capture file a CI gate reads, which ends up in CI artifacts. No analyzer reads any of those fields.
//
// So every operator object is pruned when it is read, before it reaches the Inventory, a clone, a capture
// or a replay, to an allowlist of the fields some code reads, mapped from the analyzers and rules on
// 2026-10-29 (roadmap 0.2.0, A2). Its identity stays (name, namespace, uid, generation, resourceVersion,
// creationTimestamp, ownerReferences: the gate's overlay needs them), and so does a SHA-256 digest of the
// full spec. The spec itself does not, so the gate tells a changed spec from an unchanged one by the
// digest. A kind with no rule here keeps only its identity: an analyzer added without declaring its fields
// fails its own tests, and no spec reaches a capture unpruned.

// SpecDigestAnnotation carries the SHA-256 of an operator object's full spec as read, so a change can be
// compared with what was live after the spec itself was dropped.
const SpecDigestAnnotation = "shoalcheck.dev/spec-sha256"

// keep is a field tree. A nil subtree keeps the field whole. A non-nil one keeps only its keys, applied to
// every element when the field is a list.
type keep map[string]keep

var conditions = keep{"conditions": keep{"type": nil, "status": nil}}

var pruneRules = map[schema.GroupResource]keep{
	{Group: "cert-manager.io", Resource: "certificates"}: {
		"spec":   keep{"issuerRef": keep{"kind": nil}},
		"status": keep{"notAfter": nil, "conditions": conditions["conditions"]},
	},
	{Group: "security.istio.io", Resource: "peerauthentications"}:      {"spec": keep{"mtls": keep{"mode": nil}}},
	{Group: "security.istio.io", Resource: "authorizationpolicies"}:    {},
	{Group: "networking.istio.io", Resource: "destinationrules"}:       {},
	{Group: "policy.linkerd.io", Resource: "servers"}:                  {"spec": keep{"proxyProtocol": nil}},
	{Group: "argoproj.io", Resource: "applications"}:                   {"status": keep{"health": keep{"status": nil}, "sync": keep{"status": nil}}},
	{Group: "kustomize.toolkit.fluxcd.io", Resource: "kustomizations"}: {"status": conditions},
	{Group: "helm.toolkit.fluxcd.io", Resource: "helmreleases"}:        {"status": conditions},
	{Group: "keda.sh", Resource: "scaledobjects"}:                      {"status": conditions},
	{Group: "kafka.strimzi.io", Resource: "kafkas"}:                    {"status": conditions},
	{Group: "gateway.networking.k8s.io", Resource: "gateways"}: {"status": keep{
		"conditions": conditions["conditions"], "listeners": conditions, "parents": conditions}},
	{Group: "gateway.networking.k8s.io", Resource: "httproutes"}: {"status": keep{
		"conditions": conditions["conditions"], "listeners": conditions, "parents": conditions}},
	{Group: "monitoring.coreos.com", Resource: "servicemonitors"}: {"spec": keep{"selector": nil, "namespaceSelector": nil}},
	{Group: "monitoring.coreos.com", Resource: "podmonitors"}:     {"spec": keep{"selector": nil, "namespaceSelector": nil}},
	// receivers carry webhook URLs and secret references; only their names are read. The route tree is
	// matchers and receiver names, read recursively.
	{Group: "monitoring.coreos.com", Resource: "alertmanagerconfigs"}:  {"spec": keep{"receivers": keep{"name": nil}, "route": nil}},
	{Group: "monitoring.coreos.com", Resource: "prometheuses"}:         {"spec": keep{"storage": nil, "volumes": nil, "retention": nil}},
	{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}:            {},
	{Group: "cilium.io", Resource: "ciliumclusterwidenetworkpolicies"}: {},
	{Group: "projectcalico.org", Resource: "networkpolicies"}:          {},
	{Group: "projectcalico.org", Resource: "globalnetworkpolicies"}:    {},

	// THE RULES' OWN KINDS (Batch 5, docs/engine/read-set.md). Never a webhook's caBundle or URL: a webhook with no
	// service is "by URL", which is all a rule says of it.
	{Group: "admissionregistration.k8s.io", Resource: "validatingwebhookconfigurations"}: {"webhooks": webhookKeep},
	{Group: "admissionregistration.k8s.io", Resource: "mutatingwebhookconfigurations"}:   {"webhooks": webhookKeep},
	{Group: "apiregistration.k8s.io", Resource: "apiservices"}: {
		"spec":   keep{"service": keep{"namespace": nil, "name": nil}},
		"status": keep{"conditions": keep{"type": nil, "status": nil, "reason": nil}},
	},
	{Group: "autoscaling.k8s.io", Resource: "verticalpodautoscalers"}: {
		"spec": keep{"targetRef": keep{"kind": nil, "name": nil}, "updatePolicy": keep{"updateMode": nil}},
		"status": keep{"recommendation": keep{"containerRecommendations": keep{"containerName": nil, "target": nil,
			"lowerBound": nil, "upperBound": nil}}},
	},
	{Group: "metrics.k8s.io", Resource: "pods"}: {"window": nil, "timestamp": nil,
		"containers": keep{"name": nil, "usage": keep{"cpu": nil, "memory": nil}}},
	{Group: "argoproj.io", Resource: "rollouts"}: {
		"spec": keep{"replicas": nil, "selector": nil, "workloadRef": keep{"kind": nil, "name": nil}, "template": podTemplateKeep,
			"strategy": keep{"canary": keep{"maxSurge": nil, "maxUnavailable": nil}, "blueGreen": keep{"activeService": nil, "previewService": nil}}},
		"status": keep{"replicas": nil, "readyReplicas": nil, "availableReplicas": nil, "updatedReplicas": nil,
			"conditions": keep{"type": nil, "status": nil, "reason": nil}},
	},
	{Group: "karpenter.sh", Resource: "nodepools"}: {
		"spec": keep{"disruption": nil, "limits": nil, "template": keep{"spec": keep{"expireAfter": nil}}},
	},
	{Group: "storage.k8s.io", Resource: "csinodes"}: {"spec": keep{"drivers": keep{"name": nil, "allocatable": keep{"count": nil}}}},
	// A policy's CEL expressions and messages are customer-authored text no rule reads; only its identity stays. A
	// binding keeps which policy it binds and whether it denies, warns or audits (ENG-14).
	{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}:       {},
	{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicybindings"}: {"spec": keep{"policyName": nil, "validationActions": nil}},
}

// podTemplateKeep is a pod template as the rules read it (ENG-11): its labels and the spec fields rules inspect. An env
// variable keeps its name only; its value and valueFrom never reach the reading, as dropEnvValues does for the kinds
// read typed.
var containerKeep = keep{"name": nil, "image": nil, "resources": nil, "ports": nil, "readinessProbe": nil, "livenessProbe": nil,
	"startupProbe": nil, "securityContext": nil, "volumeMounts": nil, "lifecycle": nil, "env": keep{"name": nil}}

var podTemplateKeep = keep{
	"metadata": keep{"labels": nil},
	"spec": keep{"containers": containerKeep, "initContainers": containerKeep, "volumes": keep{"name": nil, "persistentVolumeClaim": nil,
		"emptyDir": nil, "hostPath": nil}, "affinity": nil, "nodeSelector": nil, "tolerations": nil, "topologySpreadConstraints": nil,
		"priorityClassName": nil, "securityContext": nil, "serviceAccountName": nil, "automountServiceAccountToken": nil,
		"terminationGracePeriodSeconds": nil, "hostNetwork": nil, "hostPID": nil, "hostIPC": nil},
}

// webhookKeep is a webhook as the rules read it: what it is called, what it does on failure, which Service backs it,
// which requests it intercepts, and how long it may take.
var webhookKeep = keep{"name": nil, "failurePolicy": nil, "timeoutSeconds": nil, "rules": nil,
	"clientConfig": keep{"service": keep{"namespace": nil, "name": nil, "port": nil}}}

// HasPruneRule reports whether gr has declared the fields its readers use. A test in internal/analyzers
// holds every GVR an analyzer requests to having one.
func HasPruneRule(gr schema.GroupResource) bool {
	_, ok := pruneRules[gr]
	return ok
}

// SpecDigest is the SHA-256 of spec as canonical JSON (encoding/json sorts map keys), or "" for no spec.
func SpecDigest(spec any) string {
	if spec == nil {
		return ""
	}
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PruneCR returns u reduced to its identity, the spec digest and the fields gr's readers declare.
func PruneCR(gr schema.GroupResource, u *unstructured.Unstructured) unstructured.Unstructured {
	out := map[string]any{}
	for _, k := range []string{"apiVersion", "kind"} {
		if v, ok := u.Object[k]; ok {
			out[k] = v
		}
	}
	meta := map[string]any{}
	if m, ok := u.Object["metadata"].(map[string]any); ok {
		for _, k := range []string{"name", "namespace", "uid", "generation", "resourceVersion", "creationTimestamp", "ownerReferences"} {
			if v, ok := m[k]; ok {
				meta[k] = v
			}
		}
	}
	if d := SpecDigest(u.Object["spec"]); d != "" {
		meta["annotations"] = map[string]any{SpecDigestAnnotation: d}
	}
	out["metadata"] = meta
	for field, sub := range pruneRules[gr] {
		if v, ok := u.Object[field]; ok {
			out[field] = filter(v, sub)
		}
	}
	return unstructured.Unstructured{Object: out}
}

func filter(v any, k keep) any {
	if k == nil {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(k))
		for key, sub := range k {
			if x, ok := t[key]; ok {
				m[key] = filter(x, sub)
			}
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = filter(x, k)
		}
		return l
	default:
		// A scalar where the rule expects an object: the rule does not describe this shape, so nothing of it
		// is kept rather than a value nobody declared.
		return nil
	}
}
