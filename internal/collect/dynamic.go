package collect

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GVRSet is the server's preferred served-resource set from
// ServerPreferredResources, keyed by GVR. Membership is the analyzer gate: a
// GVR present here is List-safe (the API server actually serves that exact
// version), so a no-Istio / no-cert-manager cluster silently skips instead of
// 404-Listing an absent CRD.
type GVRSet map[schema.GroupVersionResource]struct{}

// Has reports whether gvr is served by the cluster.
func (s GVRSet) Has(gvr schema.GroupVersionResource) bool { _, ok := s[gvr]; return ok }

// gvrSetFromLists flattens APIResourceLists into a GVR set, recording the
// SERVER-PREFERRED version per group/resource (ServerPreferredResources already
// returns one preferred version per group, so Istio resolves to v1beta1-vs-v1,
// cert-manager to v1alpha2-vs-v1, Cilium to v2 — whatever THIS server prefers).
// Subresources (Name contains "/", e.g. certificates/status) are skipped: they
// are not listable kinds. A nil/empty lists slice yields an empty set, never
// nil-map-panics on Has.
func gvrSetFromLists(lists []*metav1.APIResourceList) GVRSet {
	set := GVRSet{}
	for _, rl := range lists {
		if rl == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range rl.APIResources {
			if strings.Contains(r.Name, "/") {
				continue // subresource, not a listable kind
			}
			set[gv.WithResource(r.Name)] = struct{}{}
		}
	}
	return set
}

// ListCR lists a single GVR namespace-wide (or cluster-scoped when ns==""),
// reusing the paginate Limit/Continue loop. The caller passes the per-step ctx
// (already 30s-bounded by the step wrapper). A NotFound/Forbidden bubbles up so
// the step records it in Meta.Denied; this returns the partial slice it managed
// to read. Field reads on the returned objects MUST go through
// unstructured.NestedString / NestedInt64 / NestedSlice / NestedMap — a bare
// .(int64) panics on JSON-decoded CRs (numbers decode to float64 OR int64
// depending on the path).
func (c *Collector) ListCR(ctx context.Context, gvr schema.GroupVersionResource, ns string) ([]unstructured.Unstructured, error) {
	if c.dyn == nil {
		return nil, fmt.Errorf("dynamic client unavailable")
	}
	var out []unstructured.Unstructured
	err := paginate(ctx, func() { out = nil }, func(ctx context.Context, opts metav1.ListOptions) (string, error) {
		l, err := c.dyn.Resource(gvr).Namespace(ns).List(ctx, opts)
		if err != nil {
			return "", err // NotFound/Forbidden bubble to the step → Meta.Denied
		}
		out = append(out, l.Items...)
		return l.GetContinue(), nil
	})
	return out, err
}

// collectStack reads the CRs the registered analyzers need: the intersection of
// wantGVRs and the served set (PresentGVRs). Each GVR gets its own step (30s
// timeout, degrade into Meta.Denied) so one broken CRD never fails the run.
// Results land in inv.StackObjects keyed by GVR. In Phase 0 wantGVRs is nil, so
// this returns immediately and StackObjects stays nil — byte-identical to the
// pre-Phase-0 collector. The step closure is passed in (not re-created) so CR
// reads reuse Collect's exact timeout-and-degrade wrapper.
func (c *Collector) collectStack(ctx context.Context, inv *Inventory, step func(kind string, fn func(ctx context.Context) error), wantGVRs []schema.GroupVersionResource) {
	if len(wantGVRs) == 0 || c.dyn == nil {
		return
	}
	for _, gvr := range wantGVRs {
		if !inv.PresentGVRs.Has(gvr) {
			continue // not served — absent GVR is a real "not installed" observation
		}
		gvr := gvr
		step(CRStepPrefix+gvr.GroupResource().String(), func(ctx context.Context) error {
			items, err := c.ListCR(ctx, gvr, metav1.NamespaceAll)
			if err != nil {
				return err
			}
			if inv.StackObjects == nil {
				inv.StackObjects = map[schema.GroupVersionResource][]unstructured.Unstructured{}
			}
			inv.StackObjects[gvr] = append(inv.StackObjects[gvr], items...)
			return nil
		})
	}
}
