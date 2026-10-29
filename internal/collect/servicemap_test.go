package collect

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func TestResolveWorkloadID(t *testing.T) {
	inv := &Inventory{
		Deployments: []appsv1.Deployment{
			{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"}},
		},
		StatefulSets: []appsv1.StatefulSet{
			{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "shop"}},
		},
	}
	resolve := ResolveWorkloadID(inv)
	if got := resolve("shop", "api"); got != "Deployment/api" {
		t.Errorf("resolve(shop,api) = %q, want Deployment/api", got)
	}
	if got := resolve("shop", "db"); got != "StatefulSet/db" {
		t.Errorf("resolve(shop,db) = %q, want StatefulSet/db", got)
	}
	if got := resolve("shop", "ghost"); got != "" {
		t.Errorf("resolve(shop,ghost) = %q, want \"\" (unmapped)", got)
	}
	if got := resolve("other", "api"); got != "" {
		t.Errorf("resolve across namespace must miss, got %q", got)
	}
}

// fakeGraph is a concrete ObservedGraphInput for the applier test.
type fakeGraph struct {
	src, win, note string
	edges          []types.ObservedEdge
}

func (f fakeGraph) GraphSource() string              { return f.src }
func (f fakeGraph) GraphWindow() string              { return f.win }
func (f fakeGraph) GraphAsOf() time.Time             { return time.Time{} }
func (f fakeGraph) GraphNote() string                { return f.note }
func (f fakeGraph) GraphEdges() []types.ObservedEdge { return f.edges }

func TestApplyObservedGraph(t *testing.T) {
	arch := &types.Architecture{Tier: types.TierDeclared}
	g := fakeGraph{
		src: "istio", win: "5m",
		edges: []types.ObservedEdge{{From: "Deployment/web", To: "Deployment/api", RequestsPerSec: 10}},
	}
	ApplyObservedGraph(arch, g)
	if arch.Tier != types.TierObserved {
		t.Errorf("Tier = %q, want observed", arch.Tier)
	}
	if len(arch.ObservedEdges) != 1 {
		t.Errorf("want 1 observed edge, got %d", len(arch.ObservedEdges))
	}
	if arch.ObservedSource != "istio" || arch.ObservedWindow != "5m" {
		t.Errorf("source/window not stamped: %+v", arch)
	}
}
