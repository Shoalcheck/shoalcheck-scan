package collect

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// crd.go — the four fields of a CustomResourceDefinition this product reads, and nothing else.
//
// NARROWED ON THE WAY IN. A CRD carries its whole OpenAPI schema, validation rules, printer columns and
// subresource wiring; none of it is read by any rule, and carrying it would put a large amount of
// customer-authored structure into the Inventory, into --redact's blast radius and into every future
// serialisation. What the upgrade family needs is the conversion strategy and the Service behind it.

// CRDInfo is a CustomResourceDefinition reduced to what a rule may claim about.
type CRDInfo struct {
	Name  string
	Group string
	// ConversionStrategy is "None" or "Webhook". Empty when the field was absent, which the API server
	// defaults to "None" — but the DEFAULT IS NOT ASSERTED HERE: an absent field and an explicit "None"
	// are the same to a rule that only acts on "Webhook", and conflating them in the collector would hide
	// a schema change from whatever reads this next.
	ConversionStrategy string
	// WebhookServiceNamespace/Name are the Service backing a Webhook strategy. Both empty when the
	// webhook is reached by URL instead — a strategy this product cannot resolve, and says so.
	WebhookServiceNamespace string
	WebhookServiceName      string
	// WebhookURL is set when the conversion webhook is addressed by URL rather than by Service. It is
	// carried so the rule can say WHY it is not judging, rather than being silently absent.
	WebhookURL string
}

// crdInfoFrom narrows one unstructured CRD. Every read goes through unstructured.Nested*, because a bare
// type assertion panics on JSON-decoded objects where numbers decode to float64 or int64 by path.
// CRDInfoFrom narrows a CustomResourceDefinition the way a read does, for one that came from a manifest rather
// than from the API server (internal/overlay). One narrowing, so the two cannot disagree about a field.
func CRDInfoFrom(u *unstructured.Unstructured) CRDInfo { return crdInfoFrom(u) }

func crdInfoFrom(u *unstructured.Unstructured) CRDInfo {
	out := CRDInfo{Name: u.GetName()}
	out.Group, _, _ = unstructured.NestedString(u.Object, "spec", "group")
	out.ConversionStrategy, _, _ = unstructured.NestedString(u.Object, "spec", "conversion", "strategy")
	out.WebhookURL, _, _ = unstructured.NestedString(u.Object,
		"spec", "conversion", "webhook", "clientConfig", "url")
	out.WebhookServiceNamespace, _, _ = unstructured.NestedString(u.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "namespace")
	out.WebhookServiceName, _, _ = unstructured.NestedString(u.Object,
		"spec", "conversion", "webhook", "clientConfig", "service", "name")
	return out
}
