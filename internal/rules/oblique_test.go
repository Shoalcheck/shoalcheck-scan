package rules

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// oblique_test.go — §3 of the exhaustive-coverage spec: when something looks unreachable, find what the
// cluster PUBLISHES about it.
//
// Both rules under test here answer a question this product refuses to answer directly. Neither claims to
// have answered the original question, and the phrase list is what holds that line.

// bannedObliquePhrases — the two direct questions are "is this image vulnerable" and "is this node's
// kubelet configured safely", and neither is answerable from a read-only snapshot. Every phrase here would
// claim one of them.
var bannedObliquePhrases = []string{
	"vulnerable", "vulnerability", "cve", "exploit", "unpatched", "security patch",
	"insecure", "compromised", "malicious",
	"end of life", "unsupported version", "no longer supported",
	"will break", "will fail", "guaranteed", "certainly",
}

func TestOblique_NeverClaimsTheQuestionItCouldNotAnswer(t *testing.T) {
	out := allObliqueFindings(obliqueFixture())
	if len(out) == 0 {
		t.Fatal("the fixture produced no findings, so this test scanned nothing")
	}
	for _, f := range out {
		blob := strings.ToLower(strings.Join(append([]string{
			f.Title, f.Description, f.WhyItMatters, f.RemediationYAML, f.RemediationCommand,
		}, f.Evidence...), "\n"))
		for _, p := range bannedObliquePhrases {
			if strings.Contains(blob, p) {
				t.Errorf("finding %s says %q — the oblique route answers a WEAKER question, and saying "+
					"otherwise is the whole failure this family was written to avoid:\n%s", f.ID, p, blob)
			}
		}
	}
}

func TestOblique_NeverCarriesDollars(t *testing.T) {
	for _, f := range allObliqueFindings(obliqueFixture()) {
		if f.DollarImpactMonthly != 0 {
			t.Errorf("finding %s carries $%.2f", f.ID, f.DollarImpactMonthly)
		}
	}
}

func TestOblique_NeverSpeaksAboutADeniedKind(t *testing.T) {
	objectKind := map[string]string{"nodes": "Node", "pods": "Pod", "deployments": "Deployment",
		"statefulsets": "StatefulSet", "daemonsets": "DaemonSet"}
	rules := []struct {
		name string
		eval func(*collect.Inventory) []types.Finding
		deps []string
	}{
		{"NodeVersionSkew", func(i *collect.Inventory) []types.Finding {
			return (NodeVersionSkew{}).Evaluate(i, Options{IncludeSystem: true})
		}, (NodeVersionSkew{}).RequiredKinds()},
		{"ImageDigestDrift", func(i *collect.Inventory) []types.Finding {
			return (ImageDigestDrift{}).Evaluate(i, Options{IncludeSystem: true})
		}, (ImageDigestDrift{}).RequiredKinds()},
	}
	for _, r := range rules {
		if got := r.eval(obliqueFixture()); len(got) == 0 {
			t.Fatalf("%s is silent on its own fixture", r.name)
		}
		for _, kind := range r.deps {
			want, known := objectKind[kind]
			if !known {
				t.Fatalf("%s declares %q with no object-kind mapping in this test", r.name, kind)
			}
			inv := obliqueFixture()
			inv.Meta.Collected = withoutKind(inv.Meta.Collected, kind)
			inv.Meta.Denied = append(inv.Meta.Denied, kind+": forbidden")
			for _, f := range r.eval(inv) {
				for _, ref := range f.AffectedResources {
					if ref.Kind == want {
						t.Errorf("%s named %s %s/%s with %s denied", r.name, ref.Kind, ref.Namespace,
							ref.Name, kind)
					}
				}
			}
		}
	}
}

func TestNodeVersionSkew_TheWaysItWouldBeWrong(t *testing.T) {
	t.Run("one version across every node is not skew", func(t *testing.T) {
		inv := healthyObliqueFixture()
		assertSilent(t, (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a patch difference is not a minor-version skew", func(t *testing.T) {
		// v1.31.2 and v1.31.7 side by side is an ordinary rolling node replacement. A rule comparing the
		// whole version string would fire on every cluster that has ever replaced a node.
		inv := healthyObliqueFixture()
		inv.Nodes = append(inv.Nodes, nodeAt("node-patch", "v1.31.7"))
		assertSilent(t, (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a distribution suffix is not a different version", func(t *testing.T) {
		// v1.31.2+k3s1, v1.31.2-eks-abc123 and v1.31.2 are the same minor version wearing three vendors'
		// labels, and every managed provider ships one.
		inv := healthyObliqueFixture()
		inv.Nodes = append(inv.Nodes, nodeAt("node-eks", "v1.31.2-eks-1a2b3c"),
			nodeAt("node-k3s", "v1.31.2+k3s1"))
		assertSilent(t, (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a version string this rule cannot parse is counted, not judged", func(t *testing.T) {
		inv := healthyObliqueFixture()
		inv.Nodes = append(inv.Nodes, nodeAt("node-weird", "somebody-elses-build"))
		assertSilent(t, (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("an unstamped build reports major 0 and is not a version", func(t *testing.T) {
		// "0.0.0-master+$Format:%H$" is what a binary built without version stamping reports — the fake
		// clientset returns exactly this, and so does anything behind a proxy that rewrites discovery.
		// Read as major 0 it would make every real kubelet "newer than the API server".
		if _, _, ok := minorVersion("0.0.0-master+$Format:%H$"); ok {
			t.Error("parsed an unstamped build as a version")
		}
		inv := healthyObliqueFixture()
		inv.Meta.ServerVersion = "0.0.0-master+$Format:%H$"
		inv.Nodes = append(inv.Nodes, nodeAt("node-old", "v1.28.9"))
		got := (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("expected the spread finding, got %d", len(got))
		}
		for _, e := range got[0].Evidence {
			if strings.Contains(e, "newer than the API server:") {
				t.Errorf("claimed a kubelet is newer than the API server off a placeholder version: %s", e)
			}
		}
	})

	t.Run("an unreadable server version withholds the skew-window claim, not the spread", func(t *testing.T) {
		inv := healthyObliqueFixture()
		inv.Meta.ServerVersion = ""
		inv.Nodes = append(inv.Nodes, nodeAt("node-old", "v1.28.9"))
		got := (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true})
		if len(got) != 1 {
			t.Fatalf("the spread across two minor versions is readable without the server version; got %d", len(got))
		}
		blob := strings.Join(got[0].Evidence, "\n")
		if !strings.Contains(blob, "server version") {
			t.Errorf("the finding does not say why the window comparison was withheld:\n%s", blob)
		}
	})
}

func TestImageDigestDrift_TheWaysItWouldBeWrong(t *testing.T) {
	t.Run("every replica on the same digest is not drift", func(t *testing.T) {
		inv := healthyObliqueFixture()
		inv.Pods = append(inv.Pods,
			podRunning("api-1", "api", "acme/api:v3", "sha256:aaaa"),
			podRunning("api-2", "api", "acme/api:v3", "sha256:aaaa"))
		assertSilent(t, (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a container that has not started yet reports no imageID", func(t *testing.T) {
		// An empty imageID is UNKNOWN, not a different digest. A rule that treated "" as a value would
		// report drift on every workload with a pod still pulling.
		inv := healthyObliqueFixture()
		inv.Pods = append(inv.Pods,
			podRunning("api-1", "api", "acme/api:v3", "sha256:aaaa"),
			podRunning("api-2", "api", "acme/api:v3", ""))
		assertSilent(t, (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("two runtimes spell the same digest differently", func(t *testing.T) {
		// containerd reports "acme/api@sha256:aaaa" and dockershim reported
		// "docker-pullable://acme/api@sha256:aaaa". A rule comparing the raw strings would report drift on
		// any cluster mid-runtime-migration, which is the opposite of what it is for.
		inv := healthyObliqueFixture()
		inv.Pods = append(inv.Pods,
			podRunning("api-1", "api", "acme/api:v3", "acme/api@sha256:aaaa"),
			podRunning("api-2", "api", "acme/api:v3", "docker-pullable://acme/api@sha256:aaaa"))
		assertSilent(t, (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("two workloads sharing a tag are not one workload drifting", func(t *testing.T) {
		// A tag that moved between two INDEPENDENT deployments is a real observation and a different
		// claim; this rule is scoped to one workload so that its statement stays exact.
		inv := healthyObliqueFixture()
		a := podRunning("api-1", "api", "acme/shared:v1", "sha256:aaaa")
		b := podRunning("web-1", "web", "acme/shared:v1", "sha256:bbbb")
		inv.Pods = append(inv.Pods, a, b)
		assertSilent(t, (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true}))
	})

	t.Run("a pod with no controller is its own workload", func(t *testing.T) {
		inv := healthyObliqueFixture()
		p1 := podRunning("bare-1", "", "acme/api:v3", "sha256:aaaa")
		p2 := podRunning("bare-2", "", "acme/api:v3", "sha256:bbbb")
		inv.Pods = append(inv.Pods, p1, p2)
		assertSilent(t, (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true}))
	})
}

func TestOblique_EachRuleFiresOnItsPlantedPositive(t *testing.T) {
	inv := obliqueFixture()
	for _, c := range []struct {
		name string
		got  []types.Finding
	}{
		{"NodeVersionSkew", (NodeVersionSkew{}).Evaluate(inv, Options{IncludeSystem: true})},
		{"ImageDigestDrift", (ImageDigestDrift{}).Evaluate(inv, Options{IncludeSystem: true})},
	} {
		if len(c.got) == 0 {
			t.Errorf("%s found nothing on a fixture built to make it fire", c.name)
		}
	}
}

func TestOblique_AUniformClusterProducesNothing(t *testing.T) {
	for _, f := range allObliqueFindings(healthyObliqueFixture()) {
		t.Errorf("a uniform cluster produced %s: %s", f.RuleID, f.Title)
	}
}

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

func nodeAt(name, kubelet string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{
			KubeletVersion:          kubelet,
			ContainerRuntimeVersion: "containerd://1.7.20",
			OSImage:                 "Ubuntu 22.04.4 LTS",
			KernelVersion:           "5.15.0-113-generic",
		}},
	}
}

// podRunning builds a pod owned by ReplicaSet "<owner>-abc" (or unowned when owner is empty), running one
// container of the given spec image and reporting the given imageID.
func podRunning(name, owner, image, imageID string) corev1.Pod {
	yes := true
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "c", Image: image, ImageID: imageID}}},
	}
	if owner != "" {
		p.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: owner + "-abc", Controller: &yes}}
	}
	return p
}

func obliqueKinds() []string {
	return []string{"nodes", "pods", "deployments", "statefulsets", "daemonsets"}
}

func healthyObliqueFixture() *collect.Inventory {
	return &collect.Inventory{
		Meta: collect.Meta{Collected: obliqueKinds(), StartedAt: fixedReading, ServerVersion: "v1.31.2"},
		Nodes: []corev1.Node{
			nodeAt("node-a", "v1.31.2"),
			nodeAt("node-b", "v1.31.2"),
		},
	}
}

func obliqueFixture() *collect.Inventory {
	inv := healthyObliqueFixture()
	// NodeVersionSkew: one node two minor versions behind the rest.
	inv.Nodes = append(inv.Nodes, nodeAt("node-stale", "v1.29.6"))
	// ImageDigestDrift: two replicas of one workload on two digests of one tag.
	inv.Pods = append(inv.Pods,
		podRunning("api-1", "api", "acme/api:v3", "acme/api@sha256:1111"),
		podRunning("api-2", "api", "acme/api:v3", "acme/api@sha256:2222"))
	return inv
}

func allObliqueFindings(inv *collect.Inventory) []types.Finding {
	opts := Options{IncludeSystem: true}
	var out []types.Finding
	out = append(out, (NodeVersionSkew{}).Evaluate(inv, opts)...)
	out = append(out, (ImageDigestDrift{}).Evaluate(inv, opts)...)
	return out
}

var _ = fmt.Sprintf
