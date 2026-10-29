package collect

import (
	"os"
	"path/filepath"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pricing"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A CLUSTER LABELLED ONLY WITH THE BETA KEY READ AS "unzoned", WITH NOTHING SAYING SO.
//
// That is an absence rendered as a fact — this project's cardinal defect — and it is a bug on its own merits
// before anything is built on top of it. `topology.kubernetes.io/zone` became the GA key in Kubernetes 1.17;
// `failure-domain.beta.kubernetes.io/zone` is what older clusters, and plenty of on-prem and
// cloud-controller-manager setups, still carry. The kubelet stopped setting it, which is not the same as
// nobody having it.
//
// Read as one zone containing everything, a zone-loss engine would conclude that losing that zone leaves the
// entire cluster with nowhere to go. So the fallback goes in BEFORE the reasoning that stands on it, not
// beside it.
func TestZoneOf_FallsBackToTheBetaLabel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   string
		why    string
	}{
		{"the GA key", map[string]string{gaZoneLabel: "eu-central-1a"}, "eu-central-1a", "the modern label"},
		{"the beta key alone", map[string]string{betaZoneLabel: "eu-central-1b"}, "eu-central-1b",
			"an older or on-prem cluster; reading this as unzoned is the defect"},
		{"both, disagreeing", map[string]string{gaZoneLabel: "ga-zone", betaZoneLabel: "beta-zone"}, "ga-zone",
			"the GA key wins: a cluster carrying both was migrated, and the beta value can be stale"},
		{"neither", map[string]string{"kubernetes.io/hostname": "n1"}, "",
			"genuinely unzoned — and an empty string is what lets a caller say so rather than guess"},
		{"the GA key present but empty", map[string]string{gaZoneLabel: "", betaZoneLabel: "eu-central-1c"},
			"eu-central-1c", "an empty label is not a value; a present-but-empty GA key must not shadow a real beta one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: tc.labels}}
			if got := ZoneOf(n); got != tc.want {
				t.Errorf("ZoneOf = %q, want %q — %s", got, tc.want, tc.why)
			}
		})
	}
}

// The region key has the same GA/beta split and the same consequence one level up: a report that cannot name
// the region prices against nothing.
func TestRegionOf_FallsBackToTheBetaLabel(t *testing.T) {
	for _, tc := range []struct {
		labels map[string]string
		want   string
	}{
		{map[string]string{gaRegionLabel: "eu-central-1"}, "eu-central-1"},
		{map[string]string{betaRegionLabel: "eu-west-1"}, "eu-west-1"},
		{map[string]string{gaRegionLabel: "ga", betaRegionLabel: "beta"}, "ga"},
		{map[string]string{}, ""},
	} {
		n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels}}
		if got := RegionOf(n); got != tc.want {
			t.Errorf("RegionOf(%v) = %q, want %q", tc.labels, got, tc.want)
		}
	}
}

// ZoneLabelSource NAMES WHICH KEY THE ANSWER CAME FROM, so a surface that cares can disclose that a cluster is
// zoned only by a deprecated label rather than presenting the derived zone as though it came from the current
// one.
func TestZoneLabelSource_NamesTheKeyItUsed(t *testing.T) {
	node := func(labels map[string]string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: labels}}
	}
	for _, tc := range []struct {
		name  string
		nodes []corev1.Node
		want  string
	}{
		{"all GA", []corev1.Node{node(map[string]string{gaZoneLabel: "a"})}, gaZoneLabel},
		{"all beta", []corev1.Node{node(map[string]string{betaZoneLabel: "a"})}, betaZoneLabel},
		{"mixed prefers the GA key, because at least one node is on the modern label",
			[]corev1.Node{node(map[string]string{betaZoneLabel: "a"}), node(map[string]string{gaZoneLabel: "b"})}, gaZoneLabel},
		{"none", []corev1.Node{node(nil)}, ""},
		{"no nodes at all", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ZoneLabelSource(tc.nodes); got != tc.want {
				t.Errorf("ZoneLabelSource = %q, want %q", got, tc.want)
			}
		})
	}
}

// ONE READER, AND A GATE THAT SAYS SO.
//
// The raw label was read in four places — assemble.go twice, anti_affinity.go, node_headroom.go and
// rightsizing.go. A fallback added to some of them is worse than one added to none: the same cluster would
// then be zoned for one rule and unzoned for another, and no single output would look wrong.
//
// This project's most repeated defect is a list you must remember to update, so the property is asserted
// instead: exactly one file names these label strings, and it is the one that owns the fallback.
func TestTopologyLabels_HaveExactlyOneReader(t *testing.T) {
	roots := []string{".", filepath.Join("..", "rules"), filepath.Join("..", "report"), filepath.Join("..", "pipeline"), filepath.Join("..", "analyzers")}
	raw := []string{
		`"topology.kubernetes.io/zone"`,
		`"topology.kubernetes.io/region"`,
		`"failure-domain.beta.kubernetes.io/zone"`,
		`"failure-domain.beta.kubernetes.io/region"`,
	}

	var offenders []string
	scanned := 0
	for _, root := range roots {
		files, err := filepath.Glob(filepath.Join(root, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", root, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") || filepath.Base(f) == "zonelabels.go" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			scanned++
			for _, lit := range raw {
				if strings.Contains(string(b), lit) {
					offenders = append(offenders, f+" names "+lit)
				}
			}
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%d file(s) read a topology label directly:\n  %s\n\nUse collect.ZoneOf / collect.RegionOf. A "+
			"fallback present in some readers and absent in others makes the same cluster zoned for one rule "+
			"and unzoned for another, and no single output looks wrong.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
	// NON-VACUITY: the scan must have covered real files, and topology.go must actually name the literals —
	// otherwise "exactly one reader" is true because there are none.
	if scanned < 20 {
		t.Fatalf("only %d file(s) scanned", scanned)
	}
	own, err := os.ReadFile("zonelabels.go")
	if err != nil {
		t.Fatalf("read topology.go: %v", err)
	}
	for _, lit := range raw {
		if !strings.Contains(string(own), lit) {
			t.Errorf("zonelabels.go does not name %s, so the one reader is not the one this test exempts", lit)
		}
	}
}

// THE FALLBACK MUST CHANGE WHAT A REPORT SAYS, not only what a helper returns.
//
// A helper tested in isolation proves the arithmetic and nothing about the product. This asserts the property
// at the surface the defect was visible on: a beta-labelled cluster used to render as one AZ called "unzoned",
// which a zone-loss engine would read as one zone containing every node.
func TestBuildArchitecture_ABetaLabelledClusterIsNotOneUnzonedAZ(t *testing.T) {
	betaNodes := []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{betaZoneLabel: "eu-central-1a"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n2", Labels: map[string]string{betaZoneLabel: "eu-central-1b"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n3", Labels: map[string]string{betaZoneLabel: "eu-central-1b"}}},
	}
	inv := &Inventory{Nodes: betaNodes}
	inv.Meta.Collected = []string{"nodes"}

	arch := buildArchitecture(inv, nil, "", "onprem", pricing.Embedded())
	if arch == nil {
		t.Fatal("no architecture was built")
	}
	byName := map[string]int{}
	for _, az := range arch.AZs {
		byName[az.Name] = len(az.Nodes)
	}
	if _, unzoned := byName["unzoned"]; unzoned {
		t.Errorf("a beta-labelled cluster still renders an \"unzoned\" AZ: %v", byName)
	}
	if len(arch.AZs) != 2 {
		t.Errorf("%d AZ(s) %v, want 2 — a beta-labelled cluster read as ONE zone containing everything is the "+
			"input that would make a zone-loss engine report the whole cluster as homeless", len(arch.AZs), byName)
	}
	if byName["eu-central-1a"] != 1 || byName["eu-central-1b"] != 2 {
		t.Errorf("nodes landed in the wrong zones: %v", byName)
	}

	// NON-VACUITY: a genuinely unlabelled cluster must STILL read as one "unzoned" AZ. The fallback widens
	// what counts as a zone label; it does not invent zones for a cluster that has none.
	plain := &Inventory{Nodes: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"kubernetes.io/hostname": "n1"}}},
	}}
	plain.Meta.Collected = []string{"nodes"}
	arch2 := buildArchitecture(plain, nil, "", "onprem", pricing.Embedded())
	if len(arch2.AZs) != 1 || arch2.AZs[0].Name != "unzoned" {
		t.Errorf("an unlabelled cluster produced %d AZ(s) — the fallback is inventing zones", len(arch2.AZs))
	}
	// And the source is nameable, so a surface can say the zones came from a deprecated key.
	if got := ZoneLabelSource(betaNodes); got != betaZoneLabel {
		t.Errorf("ZoneLabelSource = %q for a beta-only cluster, want %q", got, betaZoneLabel)
	}
}
