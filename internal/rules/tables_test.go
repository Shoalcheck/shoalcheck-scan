package rules

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// AN IMAGE REFERENCE SPLITS AS THE CONTAINER RUNTIME RESOLVES IT: no host is Docker Hub, a port is a host, a
// digest is kept as the reference and marked.
func TestTables_SplitImage(t *testing.T) {
	for _, c := range []struct {
		in, reg, repo, ref string
		digest             bool
	}{
		{"nginx", "docker.io", "nginx", "", false},
		{"nginx:1.27", "docker.io", "nginx", "1.27", false},
		{"bitnami/redis:7", "docker.io", "bitnami/redis", "7", false},
		{"registry.local:5000/team/api:v2", "registry.local:5000", "team/api", "v2", false},
		{"ghcr.io/org/app@sha256:abc", "ghcr.io", "org/app", "sha256:abc", true},
		{"ghcr.io/org/app:v1@sha256:abc", "ghcr.io", "org/app", "sha256:abc", true},
	} {
		reg, repo, ref, digest := splitImage(c.in)
		if reg != c.reg || repo != c.repo || ref != c.ref || digest != c.digest {
			t.Errorf("%s: got %s %s %s %v", c.in, reg, repo, ref, digest)
		}
	}
}

// THE PERSONA'S TABLES ARE PRESENT, SORTED AND NEVER CLAIM A NODE DRAINS. Read from the committed golden, which the
// drift gate holds equal to what the pipeline writes today.
func TestTables_PersonaVerdictsNeverSayDrains(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/golden/sample-audit.json")
	if err != nil {
		t.Fatal(err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(raw, &ar); err != nil {
		t.Fatal(err)
	}
	pl, im, nv, rg, cp := ar.Placement, ar.Images, ar.NodeVerdicts, ar.RBACGraph, ar.Capacity
	if pl == nil || im == nil || nv == nil || rg == nil || cp == nil {
		t.Fatalf("a table is missing over a fully read inventory: %v %v %v %v %v", pl != nil, im != nil, nv != nil, rg != nil, cp != nil)
	}
	blocked := 0
	for i, r := range nv.Rows {
		switch r.Verdict {
		case "blocked", "serialized":
			blocked++
		case "no blocker found":
		default:
			t.Errorf("node %s has verdict %q", r.Node, r.Verdict)
		}
		if i > 0 && nv.Rows[i-1].Node >= r.Node {
			t.Errorf("verdict rows are not sorted at %s", r.Node)
		}
	}
	if blocked == 0 {
		t.Errorf("the persona has drain findings and no node is blocked in the verdict table")
	}
	for _, r := range pl.Rows {
		sum := 0
		for _, z := range r.Zones {
			sum += z.Pods
		}
		if sum > r.Replicas {
			t.Errorf("%s/%s: %d pods in zones of %d", r.Namespace, r.Name, sum, r.Replicas)
		}
	}
}

// THE THIRD LAYER (ENG-51): a pool's used capacity is its containers' p95s summed, said as an upper bound; with no
// usage source the layer is absent, never zero.
func TestTables_CapacityHasAUsedLayerOnlyWithUsage(t *testing.T) {
	inv, usage := overProvisioned()
	inv.Meta.Collected = []string{"nodes", "pods"}
	cp := capacityTable(inv, Options{})
	if len(cp.Rows) != 1 || cp.Rows[0].UsedCPU != 0 || cp.Rows[0].UsedBasis != "" {
		t.Fatalf("without usage the used layer must be absent: %+v", cp.Rows)
	}
	cp = capacityTable(inv, Options{Usage: usage, UsageWindow: "7d", UsageBasis: week})
	r := cp.Rows[0]
	if r.UsedCPU != 1500 || r.UsedMem != 3*400<<20 || !strings.Contains(r.UsedBasis, "7d p95: an upper bound") {
		t.Fatalf("used layer: %+v", r)
	}
	if r.RequestedCPU != 3000 || r.AllocatableCPU != 4000 {
		t.Fatalf("the other layers moved: %+v", r)
	}
}
