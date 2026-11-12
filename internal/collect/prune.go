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
// (comparedTo). The collector used to keep every operator object whole, and whole objects go into the
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
}

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
