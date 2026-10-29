package pipeline

import (
	"fmt"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// fleetLink is one detected cross-cluster relationship between two fleet members.
type fleetLink struct {
	from, to  int
	kind      string
	direction string // "one-way" | "bidirectional"
	note      string
}

// deriveFleetTopology fills in each cluster's Peers + Relationships ONLY when
// there is a GENUINE, org-scoped link between fleet members — never on a weak
// coincidence. Two unrelated companies' clusters (different private registries,
// different domains) produce NO link, so the multi-cluster panel correctly
// stays hidden. Signals, all read-only and collision-resistant:
//
//   - image-promotion: the SAME private-registry image DIGEST runs on both — the
//     identical built artifact, from a registry only one org can push to.
//   - image-promotion (registry): both pull from the same PRIVATE registry host
//     (an ACR instance or ECR account is org-scoped) even without a shared digest.
//   - cross-cluster-call: one cluster's ExternalName target is a hostname the
//     OTHER cluster actually serves via Ingress (a configured A→B reference).
//
// Shared workload NAMES (argocd, cert-manager, external-dns) are deliberately
// NOT a signal — every cluster runs that common infra, so a name match proves
// nothing (the earlier false positive this replaces). Cross-cluster traffic,
// VPC peering and shared public SaaS endpoints are not read-only-inferable and
// are never drawn.
func deriveFleetTopology(clusters []*types.AuditReport) {
	if len(clusters) < 2 {
		return // a single-cluster audit has no peers
	}

	var links []fleetLink
	for i := 0; i < len(clusters); i++ {
		for j := i + 1; j < len(clusters); j++ {
			a, b := clusters[i].FleetLinkage, clusters[j].FleetLinkage
			if a == nil || b == nil {
				continue
			}
			// S1: shared PRIVATE image digest → same artifact promoted to both.
			if n := intersectCount(a.PrivateImageDigests, b.PrivateImageDigests); n > 0 {
				links = append(links, fleetLink{i, j, "image-promotion", "bidirectional",
					fmt.Sprintf("%d shared private image digest%s — the same built artifact runs on both (image-promotion pipeline)", n, plural(n))})
			} else if reg := intersect(a.PrivateRegistries, b.PrivateRegistries); len(reg) > 0 {
				// S1b: shared PRIVATE registry host (org-scoped) → same org.
				links = append(links, fleetLink{i, j, "image-promotion", "bidirectional",
					fmt.Sprintf("both pull from private registry %s — same organisation / shared delivery", reg[0])})
			}
			// S2: cross-cluster call — one cluster references a host the other serves.
			if hosts := intersect(a.OutboundHosts, b.ServedHosts); len(hosts) > 0 {
				links = append(links, fleetLink{i, j, "cross-cluster-call", "one-way",
					fmt.Sprintf("references %s — a hostname the other cluster serves", hosts[0])})
			}
			if hosts := intersect(b.OutboundHosts, a.ServedHosts); len(hosts) > 0 {
				links = append(links, fleetLink{j, i, "cross-cluster-call", "one-way",
					fmt.Sprintf("references %s — a hostname the other cluster serves", hosts[0])})
			}
		}
	}

	if len(links) == 0 {
		return // no genuine link — leave Peers/Relationships empty (panel hides)
	}

	// Only clusters that participate in a link become peers (the linked sub-fleet).
	involved := map[int]bool{}
	for _, l := range links {
		involved[l.from], involved[l.to] = true, true
	}
	var idxs []int
	for i := range clusters {
		if involved[i] {
			idxs = append(idxs, i)
		}
	}
	for _, i := range idxs {
		c := clusters[i]
		peers := make([]types.ClusterPeer, 0, len(idxs))
		for _, j := range idxs {
			p := clusters[j]
			peers = append(peers, types.ClusterPeer{
				Name:        p.Cluster.Name,
				Provider:    strings.ToUpper(p.Cluster.Provider),
				Region:      p.Cluster.Region,
				Role:        fleetRoleFromName(p.Cluster.Name),
				Status:      "active",
				NodeCount:   p.Cluster.NodeCount,
				PodCount:    p.Cluster.PodCount,
				Audited:     true,
				Description: fmt.Sprintf("%d nodes · %d pods · audited in this fleet run", p.Cluster.NodeCount, p.Cluster.PodCount),
			})
		}
		c.Peers = peers

		var rels []types.ClusterRelationship
		for _, l := range links {
			if l.from != i && l.to != i {
				continue
			}
			rels = append(rels, types.ClusterRelationship{
				From:      clusters[l.from].Cluster.Name,
				To:        clusters[l.to].Cluster.Name,
				Kind:      l.kind,
				Direction: l.direction,
				Note:      l.note,
			})
		}
		c.Relationships = rels
	}
}

// fleetRoleFromName infers a cluster's role from its name (the only environment
// signal a read-only fleet audit has).
func fleetRoleFromName(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "prod"):
		return "production"
	case strings.Contains(n, "stag"):
		return "staging"
	case strings.Contains(n, "dr") || strings.Contains(n, "failover"):
		return "disaster-recovery"
	case strings.Contains(n, "dev"):
		return "development"
	case strings.Contains(n, "test") || strings.Contains(n, "qa"):
		return "testing"
	default:
		return "peer"
	}
}

func intersect(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, y := range b {
		if set[y] {
			out = append(out, y)
		}
	}
	return out
}

func intersectCount(a, b []string) int { return len(intersect(a, b)) }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
