package pipeline

import (
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

func clusterWith(name, provider string, link *types.FleetLinkage) *types.AuditReport {
	return &types.AuditReport{
		Cluster:      types.ClusterInfo{Name: name, Provider: provider, NodeCount: 3, PodCount: 9},
		FleetLinkage: link,
	}
}

// TestDeriveFleetTopology_SharedRegistry: clusters pulling from the SAME private
// registry get an image-promotion link and become peers.
func TestDeriveFleetTopology_SharedRegistry(t *testing.T) {
	a := clusterWith("dev-aks", "aks", &types.FleetLinkage{PrivateRegistries: []string{"shop.azurecr.io"}})
	b := clusterWith("prod-aks", "aks", &types.FleetLinkage{PrivateRegistries: []string{"shop.azurecr.io"}})
	clusters := []*types.AuditReport{a, b}

	deriveFleetTopology(clusters)

	for _, c := range clusters {
		if len(c.Peers) != 2 {
			t.Errorf("%s: want 2 peers, got %d", c.Cluster.Name, len(c.Peers))
		}
		if len(c.Relationships) != 1 || c.Relationships[0].Kind != "image-promotion" {
			t.Errorf("%s: want 1 image-promotion relationship, got %+v", c.Cluster.Name, c.Relationships)
		}
	}
}

// TestDeriveFleetTopology_SharedDigest: a shared private image DIGEST is the
// strongest signal (same artifact) — still image-promotion, note differs.
func TestDeriveFleetTopology_SharedDigest(t *testing.T) {
	d := "shop.azurecr.io/api@sha256:abc123"
	a := clusterWith("dev", "aks", &types.FleetLinkage{PrivateImageDigests: []string{d}, PrivateRegistries: []string{"shop.azurecr.io"}})
	b := clusterWith("prod", "aks", &types.FleetLinkage{PrivateImageDigests: []string{d}, PrivateRegistries: []string{"shop.azurecr.io"}})
	deriveFleetTopology([]*types.AuditReport{a, b})
	if len(a.Relationships) != 1 || a.Relationships[0].Kind != "image-promotion" {
		t.Fatalf("want image-promotion from shared digest, got %+v", a.Relationships)
	}
}

// TestDeriveFleetTopology_CrossClusterCall: A's ExternalName target is a host B
// serves → directional cross-cluster-call.
func TestDeriveFleetTopology_CrossClusterCall(t *testing.T) {
	a := clusterWith("frontend", "eks", &types.FleetLinkage{OutboundHosts: []string{"api.internal.acme.com"}})
	b := clusterWith("backend", "eks", &types.FleetLinkage{ServedHosts: []string{"api.internal.acme.com"}})
	deriveFleetTopology([]*types.AuditReport{a, b})
	if len(a.Relationships) != 1 || a.Relationships[0].Kind != "cross-cluster-call" || a.Relationships[0].Direction != "one-way" {
		t.Fatalf("want one-way cross-cluster-call, got %+v", a.Relationships)
	}
	if a.Relationships[0].From != "frontend" || a.Relationships[0].To != "backend" {
		t.Errorf("direction should be frontend→backend, got %s→%s", a.Relationships[0].From, a.Relationships[0].To)
	}
}

// TestDeriveFleetTopology_NoFalsePositive: two UNRELATED clusters — different
// private registries, different served hosts, only public images in common —
// get NO peers and NO relationships (the founder's bug: a fake "replication"
// edge from shared workload names like argocd/cert-manager).
func TestDeriveFleetTopology_NoFalsePositive(t *testing.T) {
	a := clusterWith("acme-ads-dev", "eks", &types.FleetLinkage{
		PrivateRegistries: []string{"444455556666.dkr.ecr.eu-north-1.amazonaws.com"},
		ServedHosts:       []string{"api-dev.ads.example.com"},
	})
	b := clusterWith("shop-dev", "aks", &types.FleetLinkage{
		PrivateRegistries: []string{"shop.azurecr.io"},
		ServedHosts:       []string{"api.dev.shop.example"},
	})
	clusters := []*types.AuditReport{a, b}

	deriveFleetTopology(clusters)

	for _, c := range clusters {
		if len(c.Peers) != 0 || len(c.Relationships) != 0 {
			t.Errorf("%s: unrelated clusters must have NO peers/relationships, got peers=%d rels=%d",
				c.Cluster.Name, len(c.Peers), len(c.Relationships))
		}
	}
}

// TestDeriveFleetTopology_SingleCluster: a one-cluster fleet has no peers.
func TestDeriveFleetTopology_SingleCluster(t *testing.T) {
	a := clusterWith("solo", "eks", &types.FleetLinkage{PrivateRegistries: []string{"x.azurecr.io"}})
	deriveFleetTopology([]*types.AuditReport{a})
	if len(a.Peers) != 0 || len(a.Relationships) != 0 {
		t.Errorf("single-cluster fleet should have no peers/relationships")
	}
}
